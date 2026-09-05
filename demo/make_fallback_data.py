"""Generate the recorded data the demo falls back to when hardware fails.

A live demo with no fallback is a demo that can fail in front of an audience.
These recordings drive the identical detection and alerting code, so the
dashboard still fills with real alerts if the SDR will not enumerate or a
Feather will not flash.

Everything here is clearly synthetic and the runbook says so. This is
insurance, not a substitute for the real measurement.
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sim.rf_synth import Emitter, write_csv
from collectors import pcap
from tests.test_pcap import (build_tcp_segment, build_ipv4_packet,
                             write_capture, ethernet_frame)


OUTPUT_DIRECTORY = "demo/fallback"

NOMINAL_HZ = 433_920_000.0
SPAN_HZ = 150_000.0
BIN_HZ = 250.0

# An RFM69 emitting a bare carrier is narrow -- a few hundred hertz, not the
# kilohertz a modulated signal would occupy.
CARRIER_WIDTH_HZ = 400.0

# Plausible crystal errors for two boards off the same reel.
BOARD_A_PPM = -11.4
BOARD_B_PPM = 6.8

# Addresses matching demo/asn_map.example.json.
DEVICE_IP = "192.168.1.42"
CLOUD_IP = "192.168.1.50"
ROGUE_IP = "192.168.1.60"


def make_rf_recordings() -> None:
    """Four sweeps covering every beat of the RF act."""
    board_a = Emitter(ppm=BOARD_A_PPM, power_db=-30, width_hz=CARRIER_WIDTH_HZ)
    board_b = Emitter(ppm=BOARD_B_PPM, power_db=-33, width_hz=CARRIER_WIDTH_HZ)

    recordings = [
        ("rf_baseline.csv", [board_a], 12, "board A alone -- for the baseline step"),
        ("rf_authorised.csv", [board_a], 8, "board A alone again -- must stay silent"),
        ("rf_two_radios.csv", [board_a, board_b], 8, "both boards -- rogue detected"),
        ("rf_rogue_only.csv", [board_b], 8, "board A off -- the case counting misses"),
    ]

    for filename, emitters, sweeps, description in recordings:
        path = os.path.join(OUTPUT_DIRECTORY, filename)
        write_csv(path, NOMINAL_HZ, emitters, span_hz=SPAN_HZ, bin_hz=BIN_HZ,
                  sweeps=sweeps, seed=len(filename))
        print(f"  {filename:<22} {description}")


def _session_frames(destination_ip: str, payload_bytes: int, source_port: int):
    """Three packets standing in for one TLS session: open, data, close."""
    frames = []
    stages = (
        (pcap.TCP_FLAG_SYN, b""),
        (0x18, b"x" * payload_bytes),          # PSH+ACK carrying the data
        (pcap.TCP_FLAG_FIN | 0x10, b""),
    )
    for flags, payload in stages:
        segment = build_tcp_segment(source_port, 8443, flags, payload)
        packet = build_ipv4_packet(DEVICE_IP, destination_ip, segment)
        frames.append(ethernet_frame(packet))
    return frames


def make_network_recordings() -> None:
    """Two captures: authorised traffic, and the same plus a rogue call."""
    normal_frames = []
    for index in range(8):
        if index % 4 == 3:
            payload = 3400          # periodic telemetry
        else:
            payload = 300           # heartbeat
        normal_frames.extend(_session_frames(CLOUD_IP, payload, 50000 + index))

    write_capture(os.path.join(OUTPUT_DIRECTORY, "tls_normal.pcap"),
                  pcap.LINK_TYPE_ETHERNET, normal_frames)
    print(f"  {'tls_normal.pcap':<22} 8 authorised sessions -- no findings")

    rogue_frames = list(normal_frames)
    rogue_frames.extend(_session_frames(ROGUE_IP, 4096, 51000))
    write_capture(os.path.join(OUTPUT_DIRECTORY, "tls_rogue.pcap"),
                  pcap.LINK_TYPE_ETHERNET, rogue_frames)
    print(f"  {'tls_rogue.pcap':<22} same, plus one call to an unknown network")


def main() -> int:
    """Write every fallback recording."""
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    print(f"Writing fallback recordings to {OUTPUT_DIRECTORY}/\n")
    make_rf_recordings()
    make_network_recordings()
    print("\nUse with --replay. See docs/DEMO.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

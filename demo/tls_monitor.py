"""Live network egress monitoring for the demo.

Captures real packets on the Pi, groups them into TLS sessions, checks each
session against the allowlist, and posts an alert for anything unexpected.

This is Layer 2. It never sees inside the encrypted sessions -- only who the
device talked to, how much moved, and when. That is enough to notice a call to
a network the device has no business contacting.

Runs in windows: capture for a while, analyse, alert, repeat. Ctrl-C to stop.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import tls_egress
from core import rules
from sinks.webhook import AlertSink
from sim.asn_fixture import load_asn_map, ALLOWED_ASNS, ALLOWED_COUNTRIES


DEFAULT_CAPTURE_SECONDS = 15.0
DEFAULT_PORT = 443


def _require_tcpdump() -> None:
    if shutil.which("tcpdump") is None:
        raise RuntimeError(
            "tcpdump not found. Install it:\n"
            "  Raspberry Pi / Debian:  sudo apt install tcpdump"
        )


def capture_window(interface: str, seconds: float, port: int, output_path: str) -> bool:
    """Capture traffic for a fixed period. Returns False if nothing was written.

    tcpdump needs root to open the interface, so this normally runs under sudo.
    -w writes classic pcap, which is what collectors/pcap.py reads; pcapng
    would be rejected.
    """
    command = [
        "tcpdump",
        "-i", interface,
        "-w", output_path,
        "-s", "0",                 # capture whole packets, so SNI survives
        "-q",
        f"tcp port {port}",
    ]

    process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True)
    time.sleep(seconds)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

    stderr_output = ""
    if process.stderr is not None:
        stderr_output = process.stderr.read()

    if "Operation not permitted" in stderr_output or "permission denied" in stderr_output.lower():
        raise RuntimeError(
            "tcpdump could not open the interface. Run this script with sudo:\n"
            "  sudo python3 demo/tls_monitor.py ..."
        )

    return os.path.exists(output_path) and os.path.getsize(output_path) > 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="eth0",
                        help="wlan0 for Wi-Fi, eth0 for wired, lo for local-only tests")
    parser.add_argument("--asn-map", default="demo/asn_map.json")
    parser.add_argument("--alert-url", default=None)
    parser.add_argument("--window", type=float, default=DEFAULT_CAPTURE_SECONDS)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--schedule", default=None,
                        help="JSON file of operator-known maintenance windows")
    args = parser.parse_args()

    try:
        _require_tcpdump()
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    if not os.path.exists(args.asn_map):
        print(f"No address map at {args.asn_map}.\n"
              f"Copy demo/config.example.json and fill in the real addresses "
              f"of your cloud and rogue machines.", file=sys.stderr)
        return 1

    asn_lookup = load_asn_map(args.asn_map)

    maintenance_windows = None
    if args.schedule and os.path.exists(args.schedule):
        with open(args.schedule) as handle:
            maintenance_windows = []
            for window in json.load(handle)["maintenance_windows"]:
                maintenance_windows.append(tuple(window))

    sink = AlertSink(args.alert_url, source_name="pi-tls-monitor")
    print(f"Capturing on {args.interface}, tcp port {args.port}, "
          f"{args.window:.0f}s windows")
    if args.alert_url:
        print(f"Alerts -> {args.alert_url}")
    else:
        print("Alerts -> console only (pass --alert-url to post them)")
    print("Ctrl-C to stop.\n")

    window_number = 0
    try:
        while True:
            window_number += 1
            handle, capture_path = tempfile.mkstemp(suffix=".pcap")
            os.close(handle)

            try:
                got_packets = capture_window(args.interface, args.window,
                                             args.port, capture_path)
                if not got_packets:
                    print(f"window {window_number:>3}  no traffic captured")
                    continue

                observations = tls_egress.from_pcap(capture_path, asn_lookup,
                                                    port=args.port)
                findings = rules.evaluate(
                    observations, ALLOWED_ASNS, ALLOWED_COUNTRIES,
                    maintenance_windows=maintenance_windows,
                )

                print(f"window {window_number:>3}  sessions={len(observations)}  "
                      f"findings={len(findings)}")
                for observation in observations:
                    fields = observation.fields
                    print(f"      -> {fields['dst']:<16} AS{fields['asn']:<6} "
                          f"{fields['cc']:<3} {fields['bytes']:>8} bytes  "
                          f"{fields['asn_name']}")

                sink.send_all(findings)

            finally:
                if os.path.exists(capture_path):
                    os.unlink(capture_path)

    except KeyboardInterrupt:
        print(f"\nstopped after {window_number} windows; "
              f"{sink.sent_count} alert(s) delivered, {sink.failed_count} failed")
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

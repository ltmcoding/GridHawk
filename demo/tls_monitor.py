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
from core.schedule import load_windows_for_live_capture, ScheduleTimeBaseError
from correlate.inventory import Inventory, enrich, rank
from sinks.webhook import AlertSink
from sim.asn_fixture import load_asn_map, ALLOWED_ASNS, ALLOWED_COUNTRIES


DEFAULT_CAPTURE_SECONDS = 15.0
DEFAULT_PORT = 443

# A device that keeps calling an unauthorised endpoint would otherwise raise the
# same alert every window. Report it once, then hold off for this long.
ALERT_REPEAT_SUPPRESSION_S = 60.0


def _alert_identity(finding):
    """What makes two alerts "the same alert" for suppression purposes."""
    return (finding.kind, finding.subject, finding.detail.get("dst"))


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
                        help="operator-known maintenance windows; must use "
                             "absolute times for live capture")
    parser.add_argument("--replay", default=None,
                        help="analyse a recorded pcap instead of capturing")
    parser.add_argument("--inventory", default="demo/inventory.json",
                        help="Layer 1 join: weights alerts by capacity at risk")
    args = parser.parse_args()

    if not args.replay:
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
    if args.schedule:
        if not os.path.exists(args.schedule):
            print(f"No schedule at {args.schedule}", file=sys.stderr)
            return 1
        try:
            # Live capture stamps packets in epoch seconds, so a schedule
            # written in scenario time would suppress nothing at all. This
            # refuses that combination rather than failing silently.
            maintenance_windows = load_windows_for_live_capture(args.schedule)
        except ScheduleTimeBaseError as error:
            print(error, file=sys.stderr)
            return 1
        print(f"Maintenance windows: {len(maintenance_windows)} loaded")

    inventory = None
    if args.inventory and os.path.exists(args.inventory):
        inventory = Inventory.load(args.inventory)
        print(f"Inventory: {len(inventory.records)} device(s), "
              f"{inventory.total_mw():.3f} MW total")

    sink = AlertSink(args.alert_url, source_name="pi-tls-monitor")
    print(f"Capturing on {args.interface}, tcp port {args.port}, "
          f"{args.window:.0f}s windows")
    if args.alert_url:
        print(f"Alerts -> {args.alert_url}")
    else:
        print("Alerts -> console only (pass --alert-url to post them)")
    print("Ctrl-C to stop.\n")

    window_number = 0
    last_alert_time: dict[tuple, float] = {}

    try:
        while True:
            window_number += 1
            if args.replay:
                # Fallback: analyse a recorded capture on the same cadence a
                # live window would arrive, through identical detection code.
                capture_path = args.replay
                remove_capture = False
                time.sleep(args.window)
            else:
                handle, capture_path = tempfile.mkstemp(suffix=".pcap")
                os.close(handle)
                remove_capture = True

            try:
                if not args.replay:
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

                if inventory is not None and findings:
                    findings = rank(enrich(findings, inventory))

                print(f"window {window_number:>3}  sessions={len(observations)}  "
                      f"findings={len(findings)}")
                for observation in observations:
                    fields = observation.fields
                    print(f"      -> {fields['dst']:<16} AS{fields['asn']:<6} "
                          f"{fields['cc']:<3} {fields['bytes']:>8} bytes  "
                          f"{fields['asn_name']}")

                now = time.time()
                for finding in findings:
                    identity = _alert_identity(finding)
                    previously_sent = last_alert_time.get(identity)
                    if previously_sent is not None:
                        if now - previously_sent < ALERT_REPEAT_SUPPRESSION_S:
                            continue
                    sink.send(finding)
                    last_alert_time[identity] = now

            finally:
                if remove_capture and os.path.exists(capture_path):
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

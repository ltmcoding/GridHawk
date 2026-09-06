"""Live network egress monitoring for the demo.

Captures real packets on the Pi, groups them into TLS sessions, checks each
session against the allowlist, and posts an alert for anything unexpected.

This is Layer 2. It never sees inside the encrypted sessions -- only who the
device talked to, how much moved, and when. That is enough to notice a call to
a network the device has no business contacting.

Runs in windows: capture for a while, analyse, alert, repeat. Ctrl-C to stop.
With --replay it analyses a recorded capture instead, through identical code,
so the demo survives a hardware or network failure.
"""

from __future__ import annotations

import argparse
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
from sinks.webhook import AlertSink, destination_identity
from sim.asn_fixture import load_asn_map, ALLOWED_ASNS, ALLOWED_COUNTRIES


DEFAULT_CAPTURE_SECONDS = 15.0
DEFAULT_PORT = 443

# A device that keeps calling an unauthorised endpoint would otherwise raise the
# same alert every window. Report it once, then hold off for this long.
ALERT_REPEAT_SUPPRESSION_S = 60.0

# The dashboard shows the sessions from the most recent window. A single
# unauthorised call appears in exactly one window and then vanishes from view
# about eight seconds later -- long before anyone has finished looking at it.
# Recent sessions are kept so a flagged one stays on screen, and flagged ones
# are kept longer than the rest.
RECENT_SESSIONS_KEPT = 8
FLAGGED_SESSION_KEPT_S = 90.0

# Capture whole packets so the server name in the TLS handshake survives.
FULL_PACKET_SNAPLEN = "0"


class CaptureFailed(RuntimeError):
    """Raised when packets could not be captured at all."""


# --------------------------------------------------------------------------
# Getting packets: from the wire, or from a recording
# --------------------------------------------------------------------------

def require_tcpdump() -> None:
    """Fail early and clearly if the capture tool is missing."""
    if shutil.which("tcpdump") is None:
        raise CaptureFailed(
            "tcpdump not found. Install it:\n"
            "  Raspberry Pi / Debian:  sudo apt install tcpdump"
        )


def capture_window(interface: str, seconds: float, port: int, output_path: str) -> bool:
    """Capture traffic for a fixed period. Returns False if nothing was written.

    tcpdump needs root to open an interface, so this normally runs under sudo.
    -w writes classic pcap, which is what collectors/pcap.py reads; pcapng
    would be rejected.
    """
    command = [
        "tcpdump",
        "-i", interface,
        "-w", output_path,
        "-s", FULL_PACKET_SNAPLEN,
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

    if "not permitted" in stderr_output or "permission denied" in stderr_output.lower():
        raise CaptureFailed(
            "tcpdump could not open the interface. Run this script with sudo:\n"
            "  sudo python3 demo/tls_monitor.py ..."
        )

    return os.path.exists(output_path) and os.path.getsize(output_path) > 0


class CaptureSource:
    """Supplies one capture file per window, live or replayed.

    Keeping both cases behind one object means the analysis loop never asks
    which mode it is in -- the earlier version tested that three separate times
    and still managed to print the wrong thing.
    """

    def __init__(self, replay_path: str | None, interface: str,
                 port: int, window_seconds: float):
        """A replay_path of None means capture from the live interface."""
        self.replay_path = replay_path
        self.interface = interface
        self.port = port
        self.window_seconds = window_seconds

    @property
    def is_replay(self) -> bool:
        """True when reading a recording rather than the wire."""
        return self.replay_path is not None

    def describe(self) -> str:
        """A banner that states what is actually happening.

        The earlier version announced "Capturing on eth0" while replaying a
        file, which is exactly the sort of thing that misleads an audience.
        """
        if self.is_replay:
            return (f"REPLAY MODE -- reading {self.replay_path} "
                    f"(no capture, no radio, no root needed)")
        return (f"Capturing on {self.interface}, tcp port {self.port}, "
                f"{self.window_seconds:.0f}s windows")

    def next_window(self) -> str | None:
        """Path to a capture for this window, or None when nothing was seen.

        The caller must pass the result to release() when finished.
        """
        if self.is_replay:
            # Pace the replay so windows arrive as they would live.
            time.sleep(self.window_seconds)
            return self.replay_path

        handle, path = tempfile.mkstemp(suffix=".pcap")
        os.close(handle)
        if capture_window(self.interface, self.window_seconds, self.port, path):
            return path
        self.release(path)
        return None

    def release(self, path: str | None) -> None:
        """Delete a temporary capture. Recorded files are left alone."""
        if path is None or self.is_replay:
            return
        if os.path.exists(path):
            os.unlink(path)


# --------------------------------------------------------------------------
# Set-up, each step failing with its own explanation
# --------------------------------------------------------------------------

def load_address_map(path: str):
    """Load the IP-to-network map the allowlist is checked against."""
    if not os.path.exists(path):
        raise CaptureFailed(
            f"No address map at {path}.\n"
            f"Copy demo/asn_map.example.json to demo/asn_map.json and fill in "
            f"the real addresses of your cloud and rogue machines."
        )
    return load_asn_map(path)


def load_schedule(path: str | None):
    """Load maintenance windows, insisting on absolute times.

    Live capture stamps packets in epoch seconds, so a schedule written in
    scenario time would place every window decades in the past and suppress
    nothing at all -- silently, which is the worst failure mode.
    """
    if not path:
        return None
    if not os.path.exists(path):
        raise CaptureFailed(f"No schedule at {path}")
    return load_windows_for_live_capture(path)


def load_inventory(path: str | None) -> Inventory | None:
    """Load the Layer 1 join, if one is configured. Optional by design."""
    if not path or not os.path.exists(path):
        return None
    return Inventory.load(path)


# --------------------------------------------------------------------------
# One window's work
# --------------------------------------------------------------------------

def analyse_window(capture_path: str, asn_lookup, port: int,
                   maintenance_windows, inventory: Inventory | None):
    """Turn one capture into ranked findings."""
    observations = tls_egress.from_pcap(capture_path, asn_lookup, port=port)
    findings = rules.evaluate(observations, ALLOWED_ASNS, ALLOWED_COUNTRIES,
                              maintenance_windows=maintenance_windows)

    if inventory is not None and findings:
        findings = rank(enrich(findings, inventory))

    return observations, findings


def print_window(window_number: int, observations, findings) -> None:
    """Show what this window saw, so the audience can follow along."""
    print(f"window {window_number:>3}  sessions={len(observations)}  "
          f"findings={len(findings)}")
    for observation in observations:
        fields = observation.fields
        print(f"      -> {fields['dst']:<16} AS{fields['asn']:<6} "
              f"{fields['cc']:<3} {fields['bytes']:>8} bytes  {fields['asn_name']}")


def _recent_sessions(history: list[dict], observations, flagged: set) -> list[dict]:
    """Sessions to show on the dashboard: this window, plus flagged history.

    A flagged session is the whole point of the display, so it outlives the
    window it appeared in. Ordinary sessions are replaced each window.
    """
    now = time.time()

    for observation in observations:
        fields = observation.fields
        history.append({
            "dst": fields["dst"],
            "asn_name": fields["asn_name"],
            "cc": fields["cc"],
            "bytes": fields["bytes"],
            "allowed": fields["dst"] not in flagged,
            "seen_at": now,
        })

    kept_flagged = []
    kept_allowed = []
    for entry in history:
        if entry["allowed"]:
            kept_allowed.append(entry)
        elif now - entry["seen_at"] <= FLAGGED_SESSION_KEPT_S:
            kept_flagged.append(entry)

    kept_allowed = kept_allowed[-RECENT_SESSIONS_KEPT:]
    history[:] = kept_flagged + kept_allowed

    # Flagged first: it is the thing worth seeing.
    return kept_flagged + kept_allowed


def monitor(source: CaptureSource, asn_lookup, port: int,
            maintenance_windows, inventory: Inventory | None,
            sink: AlertSink, max_windows: int | None = None) -> int:
    """Capture, analyse and alert until interrupted, or for a set number of windows."""
    window_number = 0
    session_history: list[dict] = []

    try:
        while True:
            if max_windows is not None and window_number >= max_windows:
                break
            window_number += 1
            capture_path = source.next_window()

            if capture_path is None:
                print(f"window {window_number:>3}  no traffic captured")
                continue

            try:
                observations, findings = analyse_window(
                    capture_path, asn_lookup, port, maintenance_windows, inventory)
                print_window(window_number, observations, findings)

                flagged = set()
                for finding in findings:
                    destination = finding.detail.get("dst")
                    if destination:
                        flagged.add(destination)

                sessions = _recent_sessions(session_history, observations, flagged)
                any_flagged = any(not s["allowed"] for s in sessions)

                sink.send_status(
                    "alert" if any_flagged else "ok",
                    {"sessions": sessions, "windows": window_number},
                )
                sink.send_all(findings)
            finally:
                source.release(capture_path)

    except KeyboardInterrupt:
        print(f"\nstopped after {window_number} windows; "
              f"{sink.sent_count} alert(s) delivered, "
              f"{sink.failed_count} failed, {sink.suppressed_count} suppressed as repeats")

    return 0


def main() -> int:
    """Parse arguments, set everything up, then monitor."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="eth0",
                        help="wlan0 for Wi-Fi, eth0 for wired, lo for local tests")
    parser.add_argument("--asn-map", default="demo/asn_map.json")
    parser.add_argument("--alert-url", default=None)
    parser.add_argument("--window", type=float, default=DEFAULT_CAPTURE_SECONDS)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--schedule", default=None,
                        help="maintenance windows; live capture needs absolute times")
    parser.add_argument("--replay", default=None,
                        help="analyse a recorded pcap instead of capturing")
    parser.add_argument("--inventory", default="demo/inventory.json",
                        help="Layer 1 join: weights alerts by capacity at risk")
    parser.add_argument("--max-windows", type=int, default=None,
                        help="stop after this many capture windows instead of "
                             "running until interrupted; lets a script drive the demo")
    args = parser.parse_args()

    source = CaptureSource(args.replay, args.interface, args.port, args.window)

    try:
        if not source.is_replay:
            require_tcpdump()
        asn_lookup = load_address_map(args.asn_map)
        maintenance_windows = load_schedule(args.schedule)
        inventory = load_inventory(args.inventory)
    except (CaptureFailed, ScheduleTimeBaseError) as error:
        print(error, file=sys.stderr)
        return 1

    if maintenance_windows:
        print(f"Maintenance windows: {len(maintenance_windows)} loaded")
    if inventory is not None:
        print(f"Inventory: {len(inventory.records)} device(s), "
              f"{inventory.total_mw():.3f} MW total")

    sink = AlertSink(args.alert_url, source_name="pi-tls-monitor", layer="tls_egress",
                     suppress_repeats_for=ALERT_REPEAT_SUPPRESSION_S,
                     identity_of=destination_identity)

    print(source.describe())
    if args.alert_url:
        print(f"Alerts -> {args.alert_url}")
    else:
        print("Alerts -> console only (pass --alert-url to post them)")
    print("Ctrl-C to stop.\n")

    try:
        return monitor(source, asn_lookup, args.port, maintenance_windows,
                       inventory, sink, max_windows=args.max_windows)
    except CaptureFailed as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

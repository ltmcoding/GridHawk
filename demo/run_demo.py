#!/usr/bin/env python3
"""Run the whole GridHawk demo, one step at a time.

Runs on the Pi. Your Mac should already have the dashboard and the vendor cloud
running -- this checks both before starting rather than failing halfway through
in front of people.

Between steps it stops and tells you exactly which radio to switch, and waits
for Return. Nothing happens until you are ready.

    python3 demo/run_demo.py --mac Landons-MacBook-Pro-4.local

Every step reports what it expected and what it got, so a step that goes wrong
is obvious rather than something you notice later from the dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DASHBOARD_PORT = 8080
CLOUD_PORT = 8443

BASELINE_SWEEPS = 12
QUIET_SWEEPS = 10          # long enough to be convincing, short enough to hold a room
ALARM_SWEEPS = 6
CAPTURE_WINDOW_S = 8.0
QUIET_WINDOWS = 2

# ANSI, because a demo is easier to follow when the instruction is not the same
# colour as the output scrolling past it.
BOLD, DIM, GREEN, RED, AMBER, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[0m")

background_processes: list[subprocess.Popen] = []


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

def rule() -> None:
    print(f"{DIM}{'-' * 72}{RESET}")


def step(number: int, title: str) -> None:
    print()
    rule()
    print(f"{BOLD}Step {number}. {title}{RESET}")
    rule()


def say(line: str) -> None:
    """A line worth saying out loud while the step runs."""
    print(f'{CYAN}  "{line}"{RESET}')


def instruct(action: str) -> None:
    """Stop and wait. The demo does not move until the hardware is ready."""
    print()
    print(f"{AMBER}{BOLD}  ACTION: {action}{RESET}")
    try:
        input(f"{AMBER}  Press Return when done. {RESET}")
    except (EOFError, KeyboardInterrupt):
        print("\n  stopped")
        cleanup()
        sys.exit(1)


def verdict(passed: bool, message: str) -> bool:
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}UNEXPECTED{RESET}"
    print(f"  [{mark}] {message}")
    return passed


# --------------------------------------------------------------------------
# Talking to the dashboard
# --------------------------------------------------------------------------

def dashboard_url(mac_host: str) -> str:
    return f"http://{mac_host}:{DASHBOARD_PORT}"


def alert_count(mac_host: str) -> int:
    """How many alerts the dashboard is holding.

    Counting the dashboard's own total is more reliable than parsing a
    monitor's console output, and it proves delivery end to end rather than
    just that a finding was raised locally.
    """
    try:
        with urllib.request.urlopen(f"{dashboard_url(mac_host)}/alerts.json", timeout=5) as r:
            return len(json.load(r))
    except (urllib.error.URLError, OSError, ValueError):
        return -1


def reachable(url: str, timeout: float = 5.0) -> bool:
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True             # answered, which is all we need
    except (urllib.error.URLError, OSError):
        return False


# --------------------------------------------------------------------------
# Running the pieces
# --------------------------------------------------------------------------

def run(command: list[str], label: str) -> str:
    """Run a step in the foreground and show its output as it happens."""
    print(f"{DIM}  $ {' '.join(command)}{RESET}")
    collected = []
    process = subprocess.Popen(command, cwd=REPO, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in process.stdout:
            collected.append(line)
            print(f"    {line.rstrip()}")
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        raise
    return "".join(collected)


def start_background(command: list[str], label: str) -> subprocess.Popen:
    print(f"{DIM}  starting {label} in the background{RESET}")
    process = subprocess.Popen(command, cwd=REPO, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    background_processes.append(process)
    return process


def cleanup() -> None:
    for process in background_processes:
        if process.poll() is None:
            process.terminate()
    for process in background_processes:
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------

def preflight(args) -> bool:
    step(0, "Preflight")
    ok = True

    ok &= verdict(reachable(dashboard_url(args.mac) + "/alerts.json"),
                  f"dashboard reachable at {dashboard_url(args.mac)}")
    if not ok:
        print(f"{DIM}    On your Mac: python3 -m sinks.alert_receiver "
              f"--bind 0.0.0.0 --port {DASHBOARD_PORT}{RESET}")

    cloud_open = False
    try:
        import socket
        with socket.create_connection((args.mac, CLOUD_PORT), timeout=5):
            cloud_open = True
    except OSError:
        pass
    ok &= verdict(cloud_open, f"vendor cloud reachable at {args.mac}:{CLOUD_PORT}")
    if not cloud_open:
        print(f"{DIM}    On your Mac: python3 -m sim.cloud.server "
              f"--bind 0.0.0.0 --port {CLOUD_PORT}{RESET}")

    rogue_open = False
    try:
        import socket
        with socket.create_connection((args.rogue, CLOUD_PORT), timeout=5):
            rogue_open = True
    except OSError:
        pass
    ok &= verdict(rogue_open, f"rogue endpoint reachable at {args.rogue}:{CLOUD_PORT}")
    if not rogue_open:
        print(f"{DIM}    On your Mac: sudo ifconfig en0 alias {args.rogue} "
              f"255.255.252.0{RESET}")

    ok &= verdict(os.path.exists(os.path.join(REPO, args.asn_map)),
                  f"address map present at {args.asn_map}")

    if not args.replay:
        from collectors import rf_live
        ok &= verdict(rf_live.is_available(), "rtl_power installed")

    return bool(ok)


# --------------------------------------------------------------------------
# The demo
# --------------------------------------------------------------------------

def act_one_rf(args) -> None:
    alert_url = f"{dashboard_url(args.mac)}/alert"
    common = [sys.executable, "demo/rf_monitor.py", "monitor",
              "--baseline-file", args.baseline, "--alert-url", alert_url,
              "--nominal", str(args.nominal), "--span", str(args.span),
              "--bin-hz", str(args.bin_hz)]
    if args.replay:
        common += ["--replay", args.replay_two, "--integration", "0.4"]

    step(1, "Baseline the authorised radio")
    instruct("Power ON radio A.  Power OFF radio B.")
    say("First we record where the authorised radio actually transmits.")
    baseline_command = [sys.executable, "demo/rf_monitor.py", "baseline",
                        "--baseline-file", args.baseline, "--sweeps", str(BASELINE_SWEEPS),
                        "--tolerance-hz", str(args.tolerance),
                        "--nominal", str(args.nominal), "--span", str(args.span),
                        "--bin-hz", str(args.bin_hz)]
    if args.replay:
        baseline_command += ["--replay", args.replay_one]
    output = run(baseline_command, "baseline")
    verdict("Baselined 1 emitter" in output,
            "exactly one emitter baselined (two would mean radio B was still on)")

    step(2, "Watch with only the authorised radio")
    say("Same radio, still running. The detector should stay silent.")
    before = alert_count(args.mac)
    if args.replay:
        common_quiet = list(common)
        common_quiet[common_quiet.index(args.replay_two)] = args.replay_one
    else:
        common_quiet = common
    run(common_quiet + ["--max-sweeps", str(QUIET_SWEEPS)], "quiet watch")
    raised = alert_count(args.mac) - before
    verdict(raised == 0,
            f"{QUIET_SWEEPS} sweeps of the authorised radio raised {raised} alerts "
            f"(expected 0)")

    step(3, "Switch on the second radio")
    instruct("Power ON radio B.  Leave radio A on.")
    say("Identical firmware, identical commanded frequency. Their crystals differ.")
    before = alert_count(args.mac)
    run(common + ["--max-sweeps", str(ALARM_SWEEPS)], "both radios")
    raised = alert_count(args.mac) - before
    verdict(raised > 0, f"second radio raised {raised} alert(s) (expected at least 1)")

    step(4, "Switch the authorised radio off")
    instruct("Power OFF radio A.  Leave radio B on.")
    say("One carrier again -- the expected count. But it is the wrong one, "
        "and counting radios would say nothing.")
    before = alert_count(args.mac)
    if args.replay:
        common_rogue = list(common)
        common_rogue[common_rogue.index(args.replay_two)] = args.replay_rogue
    else:
        common_rogue = common
    run(common_rogue + ["--max-sweeps", str(ALARM_SWEEPS)], "rogue alone")
    raised = alert_count(args.mac) - before
    verdict(raised > 0,
            f"rogue alone raised {raised} alert(s) (expected at least 1 -- this is "
            f"the case carrier counting cannot see)")


def act_two_network(args) -> None:
    alert_url = f"{dashboard_url(args.mac)}/alert"

    step(5, "Normal inverter traffic")
    say("The inverter calls its vendor cloud. Encrypted -- we never decrypt it. "
        "We read the envelopes.")

    monitor_command = [sys.executable, "demo/tls_monitor.py",
                       "--interface", args.interface, "--port", str(CLOUD_PORT),
                       "--asn-map", args.asn_map, "--alert-url", alert_url,
                       "--window", str(CAPTURE_WINDOW_S)]
    if args.replay:
        monitor_command += ["--replay", "demo/fallback/tls_normal.pcap"]
    elif os.geteuid() != 0:
        monitor_command = ["sudo"] + monitor_command

    if not args.replay:
        start_background([sys.executable, "demo/inverter_traffic.py",
                          "--host", args.mac, "--port", str(CLOUD_PORT),
                          "--interval", "2"], "inverter traffic")
        time.sleep(3)

    before = alert_count(args.mac)
    run(monitor_command + ["--max-windows", str(QUIET_WINDOWS)], "quiet capture")
    raised = alert_count(args.mac) - before
    verdict(raised == 0, f"normal traffic raised {raised} alerts (expected 0)")

    step(6, "The inverter calls somewhere it should not")
    instruct("Ready to make the unauthorised call.")
    say("Same device, one connection to a network it has no business contacting.")

    if not args.replay:
        run([sys.executable, "demo/rogue_call.py",
             "--host", args.rogue, "--port", str(CLOUD_PORT)], "rogue call")
        rogue_monitor = monitor_command
    else:
        rogue_monitor = list(monitor_command)
        rogue_monitor[rogue_monitor.index("demo/fallback/tls_normal.pcap")] = \
            "demo/fallback/tls_rogue.pcap"

    before = alert_count(args.mac)
    run(rogue_monitor + ["--max-windows", str(QUIET_WINDOWS)], "rogue capture")
    raised = alert_count(args.mac) - before
    verdict(raised > 0, f"the unauthorised call raised {raised} alert(s) (expected 1)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mac", required=True,
                        help="your Mac's hostname or address -- prefer the .local name, "
                             "since DHCP moves addresses")
    parser.add_argument("--rogue", default="192.168.8.250",
                        help="the unauthorised endpoint (the alias on your Mac)")
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--asn-map", default="demo/asn_map.json")
    parser.add_argument("--baseline", default="demo/baseline.json")
    parser.add_argument("--tolerance", type=float, default=400.0,
                        help="match tolerance in Hz; must be well under half the gap "
                             "between your two radios")
    parser.add_argument("--nominal", type=float, default=433_920_000.0)
    parser.add_argument("--span", type=float, default=150_000.0)
    parser.add_argument("--bin-hz", type=float, default=250.0)
    parser.add_argument("--replay", action="store_true",
                        help="rehearse with recorded data: no radios, no capture, no root")
    parser.add_argument("--skip-preflight", action="store_true")
    args = parser.parse_args()

    args.replay_one = "demo/fallback/rf_baseline.csv"
    args.replay_two = "demo/fallback/rf_two_radios.csv"
    args.replay_rogue = "demo/fallback/rf_rogue_only.csv"

    print()
    print(f"{BOLD}GridHawk demo{RESET}")
    print(f"{DIM}  dashboard  {dashboard_url(args.mac)}{RESET}")
    if args.replay:
        print(f"{AMBER}  REPLAY MODE -- recorded data, no hardware. Say so if you "
              f"present this.{RESET}")

    try:
        if not args.skip_preflight and not preflight(args):
            print(f"\n{RED}  Preflight failed. Fix the above, or pass "
                  f"--skip-preflight to continue anyway.{RESET}")
            return 1

        act_one_rf(args)
        act_two_network(args)

        print()
        rule()
        print(f"{BOLD}Done.{RESET} {alert_count(args.mac)} alerts on the dashboard.")
        rule()
        print()
    except KeyboardInterrupt:
        print(f"\n{AMBER}  interrupted{RESET}")
        return 1
    finally:
        cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

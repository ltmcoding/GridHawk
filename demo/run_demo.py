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

# How long to let each phase run. Long enough to be convincing and for the
# dashboard to settle; short enough to hold a room.
QUIET_DWELL_S = 20.0
ALARM_DWELL_S = 16.0
CAPTURE_WINDOW_S = 8.0

# Addresses baked into the recorded captures by demo/make_fallback_data.py.
# A rehearsal has to resolve those, not whatever this machine is called today.
REPLAY_CLOUD_IP = "192.168.1.50"
REPLAY_ROGUE_IP = "192.168.1.60"

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


def check_step(exit_code: int, before: int, after: int,
               expect_alerts: bool, description: str) -> bool:
    """Judge one step on both whether it ran and whether it alerted.

    Three distinct outcomes get three distinct messages, because "no alerts"
    means something completely different depending on why.
    """
    if exit_code != 0:
        return verdict(False, f"{description}: the command failed (exit {exit_code}) "
                              f"-- see the output above")
    if before < 0 or after < 0:
        return verdict(False, f"{description}: could not reach the dashboard, so "
                              f"delivery cannot be confirmed. Check --mac.")
    raised = after - before
    if expect_alerts:
        return verdict(raised > 0, f"{description}: {raised} alert(s) delivered "
                                   f"(expected at least 1)")
    return verdict(raised == 0, f"{description}: {raised} alert(s) delivered "
                                f"(expected 0)")


# --------------------------------------------------------------------------
# Talking to the dashboard
# --------------------------------------------------------------------------

def dashboard_url(mac_host: str) -> str:
    return f"http://{mac_host}:{DASHBOARD_PORT}"


DASHBOARD_TIMEOUT_S = 3.0


def alert_count(mac_host: str) -> int:
    """How many alerts the dashboard is holding.

    Counting the dashboard's own total is more reliable than parsing a
    monitor's console output, and it proves delivery end to end rather than
    just that a finding was raised locally.
    """
    try:
        with urllib.request.urlopen(f"{dashboard_url(mac_host)}/alerts.json",
                                    timeout=DASHBOARD_TIMEOUT_S) as r:
            return len(json.load(r))
    except (urllib.error.URLError, OSError, ValueError):
        return -1


def reachable(url: str, timeout: float = DASHBOARD_TIMEOUT_S) -> bool:
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

def run(command: list[str], label: str) -> tuple[str, int]:
    """Run a step in the foreground, showing output as it happens.

    Returns the output and the exit code. The exit code matters: a monitor that
    crashed produced no alerts, and counting that as "0 alerts, as expected"
    would report a passing step over a stack trace.
    """
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
    return "".join(collected), process.returncode


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

def resolve_cloud_address(args) -> str:
    """Find the Mac's authorised address, avoiding the rogue alias.

    The rogue endpoint is an alias on the same interface as the real one, so
    Bonjour advertises BOTH under the Mac's .local name -- and the rogue can
    come back first. Anything that resolves the hostname itself may therefore
    aim the "normal" inverter traffic straight at the unauthorised address and
    hammer it forever, which looks like the demo generating endless attacks.

    So we resolve once here, discard loopback and the rogue, and hand the
    resulting address to every component rather than letting each re-resolve.
    """
    import socket
    candidates = []
    for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
            args.mac, None, socket.AF_INET):
        address = sockaddr[0]
        if address.startswith("127.") or address == args.rogue:
            continue
        if address not in candidates:
            candidates.append(address)

    if not candidates:
        raise OSError(f"{args.mac} resolves only to loopback or the rogue address")
    return candidates[0]


def write_address_map(args) -> str:
    """Regenerate the address map from the addresses actually in use.

    A map written by hand goes stale the moment DHCP moves the Mac, and the
    failure is quiet and confusing: every session resolves to UNKNOWN, so the
    detector flags all of them and normal traffic looks like an attack. The
    runner already knows both endpoints, so it writes the map itself.
    """
    if args.replay:
        cloud_ip, rogue_ip = REPLAY_CLOUD_IP, REPLAY_ROGUE_IP
    else:
        cloud_ip, rogue_ip = resolve_cloud_address(args), args.rogue

    path = os.path.join(REPO, args.asn_map)
    with open(path, "w") as handle:
        json.dump({
            "_comment": "Written by run_demo.py from the addresses in use.",
            cloud_ip: [64500, "VENDOR-CLOUD-PRIMARY", "DE"],
            rogue_ip: [64666, "UNKNOWN-TRANSIT", "CN"],
        }, handle, indent=1)

    print(f"{DIM}  address map written: {cloud_ip} authorised, "
          f"{rogue_ip} unauthorised{RESET}")
    return cloud_ip


def preflight(args) -> bool:
    """Check every dependency before anything starts.

    Failing here costs thirty seconds. Failing halfway through costs the demo.
    """
    step(0, "Preflight")
    ok = True

    dashboard_ok = reachable(dashboard_url(args.mac) + "/alerts.json")
    ok &= verdict(dashboard_ok, f"dashboard reachable at {dashboard_url(args.mac)}")
    if not dashboard_ok:
        print(f"{DIM}    Start it there: python3 -m sinks.alert_receiver "
              f"--bind 0.0.0.0 --port {DASHBOARD_PORT}{RESET}")
        print(f"{DIM}    Or, to rehearse with everything on this machine: "
              f"make demo-rehearse{RESET}")

    try:
        args.cloud_ip = write_address_map(args)
        ok &= verdict(True, f"address map matches the cloud at {args.cloud_ip}")
    except OSError as error:
        args.cloud_ip = None
        ok &= verdict(False, f"could not resolve {args.mac}: {error}")

    # Replay needs no cloud, no rogue endpoint, no radio and no capture -- it
    # reads recordings. Checking for them would fail a rehearsal that is fine.
    if args.replay:
        ok &= verdict(all(os.path.exists(os.path.join(REPO, p)) for p in
                          (args.replay_one, args.replay_two, args.replay_rogue,
                           "demo/fallback/tls_normal.pcap",
                           "demo/fallback/tls_rogue.pcap")),
                      "recorded demo data present (run 'make fallback' if missing)")
        return bool(ok)

    cloud_open = False
    cloud_target = args.cloud_ip or args.mac
    try:
        import socket
        with socket.create_connection((cloud_target, CLOUD_PORT), timeout=5):
            cloud_open = True
    except OSError:
        pass
    ok &= verdict(cloud_open, f"vendor cloud reachable at {cloud_target}:{CLOUD_PORT}")
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

    if not args.replay:
        from collectors import rf_live
        ok &= verdict(rf_live.is_available(), "rtl_power installed")

    return bool(ok)


# --------------------------------------------------------------------------
# The demo
# --------------------------------------------------------------------------

def lane_summary(mac_host: str) -> str:
    """One line describing what the dashboard is showing right now."""
    try:
        with urllib.request.urlopen(f"{dashboard_url(mac_host)}/state.json",
                                    timeout=DASHBOARD_TIMEOUT_S) as r:
            state = json.load(r)
    except (urllib.error.URLError, OSError, ValueError):
        return "dashboard unreachable"

    parts = []
    for lane in state["lanes"]:
        detail = lane.get("detail", {})
        if lane["source"] == "rf":
            carriers = detail.get("carriers", [])
            unknown = sum(1 for c in carriers if not c.get("known"))
            parts.append(f"RF {len(carriers)} carrier(s)"
                         + (f", {unknown} unaccounted" if unknown else ""))
        else:
            parts.append(f"net {len(detail.get('sessions', []))} session(s)")
    return " | ".join(parts)


def dwell(args, seconds: float, note: str) -> None:
    """Let the monitor run, showing what the dashboard sees while it does.

    The monitors stay up across the whole act rather than being started and
    stopped per step. Bounded runs made the script tidy but left the dashboard
    stale between steps -- dead at exactly the moment an audience is looking at
    it. Now the screen stays live and the script only handles the pauses.
    """
    print(f"{DIM}  {note} for {seconds:.0f}s{RESET}")
    finish = time.time() + seconds
    while time.time() < finish:
        print(f"{DIM}    {lane_summary(args.mac)}{RESET}")
        time.sleep(4)


class MonitorHandle:
    """Holds the running monitor so a phase can swap it in replay.

    Live and replay differ here in a way worth being explicit about. Live keeps
    ONE monitor up while you physically switch radios -- that is the demo. A
    recording cannot be switched, so replay restarts the monitor against a
    different file to stand in for the same change.
    """

    def __init__(self, base_command: list[str], replay: bool):
        self.base_command = base_command
        self.replay = replay
        self.process: subprocess.Popen | None = None

    def start(self, recording: str | None = None) -> None:
        command = list(self.base_command)
        if recording is not None:
            command += ["--replay", recording]
            if "rf_monitor.py" in " ".join(command):
                command += ["--integration", "0.5"]
        self.process = start_background(command, "monitor")

    def switch_to(self, recording: str | None) -> None:
        """In replay, restart against a new recording. Live monitors keep going."""
        if not self.replay:
            return
        self.stop()
        self.start(recording)
        time.sleep(3)

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None


def act_one_rf(args) -> None:
    alert_url = f"{dashboard_url(args.mac)}/alert"

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
    output, code = run(baseline_command, "baseline")

    # Real bands are not empty. Baselining whatever is already transmitting is
    # correct -- that is the point of a baseline -- so more than one emitter is
    # normal outdoors and only worth a note. What matters is that radio B was
    # not among them, which is why the pause above exists.
    baselined = 0
    for line in output.splitlines():
        if "Baselined" in line and "emitter" in line:
            baselined = int(line.split("Baselined")[1].split()[0])
    verdict(code == 0 and baselined >= 1,
            f"{baselined} emitter(s) baselined as authorised")
    if baselined > 1:
        print(f"{DIM}    More than one signal is in this band. That is fine -- they "
              f"are now the known background.{RESET}")
        print(f"{DIM}    Just confirm radio B really was off, or it has been "
              f"recorded as authorised and step 3 will not fire.{RESET}")

    # The SDR can only be held by one process, so the monitor starts only after
    # baselining has released it.
    monitor = MonitorHandle(
        [sys.executable, "demo/rf_monitor.py", "monitor",
         "--baseline-file", args.baseline, "--alert-url", alert_url,
         "--nominal", str(args.nominal), "--span", str(args.span),
         "--bin-hz", str(args.bin_hz)],
        replay=args.replay)
    monitor.start(args.replay_one if args.replay else None)
    time.sleep(3)

    step(2, "Watch with only the authorised radio")
    say("Same radio, still running. The detector should stay silent.")
    before = alert_count(args.mac)
    dwell(args, QUIET_DWELL_S, "watching")
    check_step(0 if monitor.running() else 1,
               before, alert_count(args.mac), False,
               "the authorised radio alone")

    step(3, "Switch on the second radio")
    instruct("Power ON radio B.  Leave radio A on.")
    say("Identical firmware, identical commanded frequency. Their crystals differ.")
    before = alert_count(args.mac)
    monitor.switch_to(args.replay_two)
    dwell(args, ALARM_DWELL_S, "watching")
    check_step(0 if monitor.running() else 1,
               before, alert_count(args.mac), True, "the second radio")

    step(4, "Switch the authorised radio off")
    instruct("Power OFF radio A.  Leave radio B on.")
    say("One carrier again -- the expected count. But it is the wrong one, "
        "and counting radios would say nothing.")
    before = alert_count(args.mac)
    monitor.switch_to(args.replay_rogue)
    dwell(args, ALARM_DWELL_S, "watching")
    check_step(0 if monitor.running() else 1,
               before, alert_count(args.mac), True,
               "the rogue alone (the case carrier counting cannot see)")

    monitor.stop()


def act_two_network(args) -> None:
    alert_url = f"{dashboard_url(args.mac)}/alert"

    step(5, "Normal inverter traffic")
    say("The inverter calls its vendor cloud. Encrypted -- we never decrypt it. "
        "We read the envelopes.")

    base = [sys.executable, "demo/tls_monitor.py",
            "--interface", args.interface, "--port", str(CLOUD_PORT),
            "--asn-map", args.asn_map, "--alert-url", alert_url,
            "--window", str(CAPTURE_WINDOW_S)]
    if not args.replay and os.geteuid() != 0:
        base = ["sudo"] + base

    if not args.replay:
        cloud_host = args.cloud_ip or args.mac
        print(f"{DIM}  inverter traffic aimed at {cloud_host} "
              f"(the resolved address, not the name){RESET}")
        start_background([sys.executable, "demo/inverter_traffic.py",
                          "--host", cloud_host, "--port", str(CLOUD_PORT),
                          "--interval", "2"], "inverter traffic")
        time.sleep(3)

    monitor = MonitorHandle(base, replay=args.replay)
    if args.replay:
        monitor.base_command = [a for a in base]
        monitor.process = start_background(
            base + ["--replay", "demo/fallback/tls_normal.pcap"], "network monitor")
    else:
        monitor.process = start_background(base, "network monitor")
    time.sleep(CAPTURE_WINDOW_S + 4)

    before = alert_count(args.mac)
    dwell(args, QUIET_DWELL_S, "capturing")
    check_step(0 if monitor.running() else 1,
               before, alert_count(args.mac), False, "normal traffic")

    step(6, "The inverter calls somewhere it should not")
    instruct("Ready to make the unauthorised call.")
    say("Same device, one connection to a network it has no business contacting.")

    before = alert_count(args.mac)
    if args.replay:
        monitor.stop()
        monitor.process = start_background(
            base + ["--replay", "demo/fallback/tls_rogue.pcap"], "network monitor")
        time.sleep(CAPTURE_WINDOW_S + 3)
    else:
        run([sys.executable, "demo/rogue_call.py",
             "--host", args.rogue, "--port", str(CLOUD_PORT)], "rogue call")

    dwell(args, ALARM_DWELL_S, "capturing")
    check_step(0 if monitor.running() else 1,
               before, alert_count(args.mac), True, "the unauthorised call")

    monitor.stop()


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
    parser.add_argument("--with-dashboard", action="store_true",
                        help="start a dashboard on this machine first, so a "
                             "rehearsal needs nothing else running")
    args = parser.parse_args()

    args.cloud_ip = None
    args.replay_one = "demo/fallback/rf_baseline.csv"
    args.replay_two = "demo/fallback/rf_two_radios.csv"
    args.replay_rogue = "demo/fallback/rf_rogue_only.csv"

    if args.with_dashboard:
        start_background([sys.executable, "-m", "sinks.alert_receiver",
                          "--bind", "0.0.0.0", "--port", str(DASHBOARD_PORT)],
                         "dashboard")
        time.sleep(2)

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

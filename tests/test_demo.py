"""Tests for the demo-facing code: live capture, alerting, schedules, inventory.

None of this needs a radio, a network, or root. Run: python3 -m tests.test_demo
"""

import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import ThreadingHTTPServer

from collectors import rf_live
from core.events import Finding
from core.schedule import (
    load_windows, load_windows_for_live_capture, looks_like_scenario_time,
    ScheduleTimeBaseError,
)
from correlate.inventory import Inventory, enrich, rank, summarise
from sinks.alert_receiver import AlertHandler, received_alerts
from sinks.webhook import AlertSink

RESULTS = []
SCRATCH = "runs/t"


def check(name, condition):
    RESULTS.append((name, bool(condition)))
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}")


def make_finding(subject="192.168.1.42", severity="high", kind="new_asn", dst="10.0.0.1"):
    return Finding(ts=1.0, source="tls_egress", subject=subject, kind=kind,
                   severity=severity, detail={"dst": dst})


# --------------------------------------------------------------------------

def test_sweep_grouping():
    print("\nrtl_power row grouping")

    rows = [
        "2026-09-05, 13:00:00, 433845000, 433845750, 250.00, 64, -60.1, -59.8, -25.0",
        "2026-09-05, 13:00:00, 433845750, 433846500, 250.00, 64, -60.3, -59.9, -60.2",
        "2026-09-05, 13:00:01, 433845000, 433845750, 250.00, 64, -60.0, -59.7, -24.8",
        "2026-09-05, 13:00:01, 433845750, 433846500, 250.00, 64, -60.4, -59.6, -60.1",
    ]
    sweeps = list(rf_live.group_rows_into_sweeps(rows))
    check("two timestamps produce two sweeps", len(sweeps) == 2)
    check("each sweep merges both rows", len(sweeps[0]) == 6 and len(sweeps[1]) == 6)

    frequencies = [frequency for frequency, _power in sweeps[0]]
    check("bins come out sorted by frequency", frequencies == sorted(frequencies))

    with_header = ["hz_low, hz_high, ignored"] + rows[:2]
    check("header lines are skipped",
          len(list(rf_live.group_rows_into_sweeps(with_header))) == 1)

    check("empty input yields nothing",
          list(rf_live.group_rows_into_sweeps([])) == [])
    check("malformed rows are skipped",
          list(rf_live.group_rows_into_sweeps(["garbage", "1,2"])) == [])

    trailing = list(rf_live.group_rows_into_sweeps(rows[:2]))
    check("a final sweep is emitted at end of input", len(trailing) == 1)


def test_replay():
    print("\nsweep replay from file")

    os.makedirs(SCRATCH, exist_ok=True)
    path = os.path.join(SCRATCH, "replay.csv")
    with open(path, "w") as handle:
        handle.write("2026-09-05, 13:00:00, 433845000, 433845750, 250.00, 64, -60.1, -25.0\n")
        handle.write("2026-09-05, 13:00:01, 433845000, 433845750, 250.00, 64, -60.0, -24.9\n")

    once = list(rf_live.replay_sweeps(path, loop=False))
    check("replay reads every sweep once", len(once) == 2)

    looped = []
    for sweep in rf_live.replay_sweeps(path, loop=True):
        looped.append(sweep)
        if len(looped) >= 5:
            break
    check("replay loops for a continuous demo", len(looped) == 5)


def test_alert_sink():
    print("\nalert delivery")

    server = ThreadingHTTPServer(("127.0.0.1", 8091), AlertHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    received_alerts.clear()

    sink = AlertSink("http://127.0.0.1:8091/alert", source_name="test", verbose=False)
    check("finding is accepted by the endpoint", sink.send(make_finding()) is True)
    check("endpoint stored it", len(received_alerts) == 1)
    check("reporter name travels with it", received_alerts[0]["reporter"] == "test")
    check("sent tally increments", sink.sent_count == 1)

    delivered = sink.send_all([make_finding(), make_finding(severity="critical")])
    check("send_all reports how many landed", delivered == 2)

    server.shutdown()

    # An unreachable endpoint must not raise: a monitor that dies because its
    # alert endpoint is down has made the problem worse.
    unreachable = AlertSink("http://127.0.0.1:9/alert", verbose=False)
    check("unreachable endpoint returns False rather than raising",
          unreachable.send(make_finding()) is False)
    check("failure tally increments", unreachable.failed_count == 1)

    console_only = AlertSink(None, verbose=False)
    check("no URL configured is not an error",
          console_only.send(make_finding()) is False)


def test_schedule_time_base():
    print("\nmaintenance-window time bases")

    os.makedirs(SCRATCH, exist_ok=True)

    scenario_path = os.path.join(SCRATCH, "sched_scenario.json")
    with open(scenario_path, "w") as handle:
        json.dump({"maintenance_windows": [[300.0, 600.0]]}, handle)

    epoch_path = os.path.join(SCRATCH, "sched_epoch.json")
    with open(epoch_path, "w") as handle:
        json.dump({"maintenance_windows": [[1_757_030_400.0, 1_757_034_000.0]]}, handle)

    iso_path = os.path.join(SCRATCH, "sched_iso.json")
    with open(iso_path, "w") as handle:
        json.dump({"maintenance_windows_iso":
                   [["2026-09-06T02:00:00Z", "2026-09-06T03:00:00Z"]]}, handle)

    check("scenario times are recognised as relative",
          looks_like_scenario_time(load_windows(scenario_path)) is True)
    check("epoch times are recognised as absolute",
          looks_like_scenario_time(load_windows(epoch_path)) is False)

    rejected = False
    try:
        load_windows_for_live_capture(scenario_path)
    except ScheduleTimeBaseError as error:
        rejected = "epoch" in str(error).lower()
    check("live capture rejects a scenario-time schedule", rejected)

    check("live capture accepts epoch times",
          len(load_windows_for_live_capture(epoch_path)) == 1)

    iso_windows = load_windows_for_live_capture(iso_path)
    check("ISO timestamps load as absolute times", len(iso_windows) == 1)
    check("ISO window spans one hour",
          abs((iso_windows[0][1] - iso_windows[0][0]) - 3600.0) < 1.0)


def test_inventory():
    print("\nLayer 1 inventory join")

    inventory = Inventory.load("demo/inventory.example.json")
    check("comment keys are not loaded as devices", "_comment" not in inventory.records)
    check("devices loaded", len(inventory.records) >= 4)

    big = make_finding(subject="192.168.1.42", severity="high")
    small = make_finding(subject="192.168.1.45", severity="high")
    unknown = make_finding(subject="10.99.99.99", severity="high")

    enrich([big, small, unknown], inventory)

    check("capacity attached to a known device", big.mw_at_risk == 0.501)
    check("vendor and model named", big.detail["device"] == "Sungrow SG110CX")
    check("capacity shown in kW for readability", big.detail["capacity_kw"] == 501.0)
    check("county carried through", big.detail["county"] == "Kern")
    check("unknown device still alerts, unranked",
          unknown.detail["device"] == "not in inventory")

    # The whole point: identical severity, different urgency.
    check("same severity ranks by capacity", big.priority > small.priority)

    ordered = rank([small, unknown, big])
    check("ranking puts the largest device first", ordered[0] is big)
    check("ranking puts the unknown device last", ordered[-1] is unknown)

    critical = make_finding(subject="192.168.1.42", severity="critical")
    enrich([critical], inventory)
    check("severity still dominates capacity", critical.priority > big.priority)

    totals = summarise([big, small, unknown])
    check("summary counts findings", totals["n_findings"] == 3)
    check("summary totals megawatts", abs(totals["mw_at_risk"] - 0.510) < 0.01)


def main():
    print("demo-facing code")
    test_sweep_grouping()
    test_replay()
    test_alert_sink()
    test_schedule_time_base()
    test_inventory()

    failed = [name for name, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

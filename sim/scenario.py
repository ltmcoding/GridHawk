"""Scenario generator and sealed ground-truth manifest.

Red/blue split: this module decides what happens and writes the answer key to
truth/<seed>.json.  The detector reads only the capture.  Whoever tunes the
detector must not read the manifest before scoring, or the result means
nothing -- a detector tuned against its own generator proves only that it can
recognise itself.

Some seeds inject NOTHING.  A detector never tested on a clean run has an
unmeasured false-positive rate, which is the number operators care about most.
"""

from __future__ import annotations

import argparse
import json
import os
import random
from dataclasses import dataclass, asdict

# Behaviour profile for a grid-tied inverter's cloud client.
# NOTE: these constants are ASSUMED, not measured -- we have no bench unit.
# Forescout's SUN:DOWN (27 Mar 2025) documents real Sungrow/Growatt/SMA cloud
# behaviour and is the right source to replace these with.
PROFILE = {
    "telemetry": {"interval": 300, "jitter": 15, "bytes": (1_200, 8_000)},
    "heartbeat": {"interval": 60, "jitter": 5, "bytes": (200, 400)},
    "fw_check": {"interval": 86_400, "jitter": 3_600, "bytes": (500, 1_500)},
}

AUTHORIZED = ["172.28.0.10", "172.28.0.11"]
FIRMWARE_CDN = "172.28.0.12"

ANOMALIES = ("new_asn", "geo_drift", "off_cycle_burst", "volume_spike", "tunnel_indicator")

ANOMALY_DST = {
    "new_asn": "172.28.0.20",
    "geo_drift": "172.28.0.21",
    "tunnel_indicator": "172.28.0.22",
    "off_cycle_burst": None,     # authorized dst, wrong time
    "volume_spike": None,        # authorized dst, wrong size
}


@dataclass
class Event:
    t: float
    kind: str          # 'telemetry' | 'heartbeat' | 'fw_check' | anomaly name
    dst: str
    nbytes: int
    benign: bool


def build(seed: int, duration_s: float = 7_200.0) -> tuple[list[Event], list[dict]]:
    rng = random.Random(seed)
    events: list[Event] = []

    for kind, spec in PROFILE.items():
        t = rng.uniform(0, spec["interval"])
        while t < duration_s:
            events.append(Event(
                t=t,
                kind=kind,
                dst=rng.choice(AUTHORIZED) if kind != "fw_check" else FIRMWARE_CDN,
                nbytes=rng.randint(*spec["bytes"]),
                benign=True,
            ))
            t += spec["interval"] + rng.gauss(0, spec["jitter"])

    truth: list[dict] = []
    # 0..4 anomalies.  Zero is a legitimate and important outcome.
    for _ in range(rng.randint(0, 4)):
        kind = rng.choice(ANOMALIES)
        at = rng.uniform(60, duration_s - 60)
        dst = ANOMALY_DST[kind] or rng.choice(AUTHORIZED)
        if kind == "volume_spike":
            nbytes = rng.randint(2_000_000, 16_000_000)
        elif kind == "off_cycle_burst":
            nbytes = rng.randint(1_000, 5_000)
        else:
            nbytes = rng.randint(800, 20_000)
        events.append(Event(t=at, kind=kind, dst=dst, nbytes=nbytes, benign=False))
        truth.append({"t": round(at, 3), "kind": kind, "dst": dst, "bytes": nbytes})

    events.sort(key=lambda e: e.t)
    truth.sort(key=lambda x: x["t"])
    return events, truth


def known_schedule(events: list[Event], pad: float = 120.0) -> list[tuple[float, float]]:
    """Windows the operator legitimately knows about, from their own change log.

    This is operator knowledge, not answer-key leakage: a site owner knows when
    they scheduled firmware. Only BENIGN fw_check events are included -- an
    injected anomaly never appears here.
    """
    return [(e.t - pad, e.t + pad) for e in events
            if e.benign and e.kind == "fw_check"]


def main() -> None:
    ap = argparse.ArgumentParser(description="build a scenario + sealed manifest")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--duration", type=float, default=7_200.0)
    ap.add_argument("--events-out", default=None)
    ap.add_argument("--truth-out", default=None)
    a = ap.parse_args()

    events, truth = build(a.seed, a.duration)
    ev_path = a.events_out or f"runs/{a.seed}.events.json"
    tr_path = a.truth_out or f"truth/{a.seed}.json"
    os.makedirs(os.path.dirname(ev_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(tr_path) or ".", exist_ok=True)

    with open(ev_path, "w") as fh:
        json.dump([asdict(e) for e in events], fh, indent=1)
    with open(tr_path, "w") as fh:
        json.dump({"seed": a.seed, "anomalies": truth}, fh, indent=1)

    sched_path = ev_path.replace(".events.json", ".schedule.json")
    with open(sched_path, "w") as fh:
        json.dump({"maintenance_windows": known_schedule(events)}, fh, indent=1)

    print(f"seed {a.seed}: {len(events)} events -> {ev_path}")
    print(f"  manifest SEALED -> {tr_path}  ({len(truth)} anomalies; do not read before scoring)")


if __name__ == "__main__":
    main()

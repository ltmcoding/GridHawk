"""Run the detector over a scenario replay or a pcap and write findings."""

from __future__ import annotations

import argparse
import os

from collectors import tls_egress
from core import rules
from core.events import write_findings
from sim.asn_fixture import asn_lookup, ALLOWED_ASNS, ALLOWED_COUNTRIES


def main() -> None:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--events", help="scenario replay (deterministic, for scoring)")
    src.add_argument("--pcap", help="real capture (proves the capture path)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--volume-factor", type=float, default=8.0)
    ap.add_argument("--schedule", help="operator-known maintenance windows (JSON)")
    a = ap.parse_args()

    if a.events:
        obs = tls_egress.from_events(a.events, asn_lookup)
    else:
        obs = tls_egress.from_pcap(a.pcap, asn_lookup)

    windows = None
    if a.schedule and os.path.exists(a.schedule):
        import json
        windows = [tuple(w) for w in json.load(open(a.schedule))["maintenance_windows"]]

    findings = rules.evaluate(obs, ALLOWED_ASNS, ALLOWED_COUNTRIES,
                              volume_factor=a.volume_factor,
                              maintenance_windows=windows)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    write_findings(a.out, findings)
    print(f"{len(obs)} observations -> {len(findings)} findings -> {a.out}")


if __name__ == "__main__":
    main()

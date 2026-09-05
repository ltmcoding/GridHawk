"""Network egress attestation (Grid Lockout Layer 2).

Metadata only.  We hold no inverter, therefore no client certificate, therefore
no mTLS interception and no payload visibility.  Everything here works on what
is observable from outside the TLS session: destination, ASN, country, session
byte volume, and connection cadence.

Two input paths that emit an identical Observation stream:
  from_pcap()   -- real capture; proves the capture pipeline
  from_events() -- deterministic scenario replay; used for scoring
"""

from __future__ import annotations

import json
from collections import defaultdict

from core.events import Observation
from collectors import pcap as pcapmod


def from_pcap(path: str, asn_lookup, port: int = 443) -> list[Observation]:
    """Assemble TCP flows from a capture into per-session Observations."""
    flows: dict[tuple, dict] = {}
    out: list[Observation] = []

    def emit(key, f):
        asn, name, cc = asn_lookup(f["dst"])
        out.append(Observation(
            ts=f["start"], source="tls_egress", subject=f["src"],
            fields={
                "dst": f["dst"], "dport": f["dport"],
                "asn": asn, "asn_name": name, "cc": cc,
                "bytes": f["bytes"], "duration": round(f["last"] - f["start"], 4),
                "sni": f["sni"],
            },
        ))

    for p in pcapmod.read(path):
        if p.dport != port and p.sport != port:
            continue
        outbound = p.dport == port
        key = (p.src, p.dst, p.sport, p.dport) if outbound else (p.dst, p.src, p.dport, p.sport)
        f = flows.get(key)
        if f is None:
            f = flows[key] = {
                "src": key[0], "dst": key[1], "dport": key[3],
                "start": p.ts, "last": p.ts, "bytes": 0, "sni": None,
            }
        f["last"] = p.ts
        f["bytes"] += p.wire_len
        if f["sni"] is None and p.payload:
            f["sni"] = pcapmod.parse_sni(p.payload)
        if p.fin or p.rst:
            emit(key, f)
            del flows[key]

    for key, f in flows.items():        # captures often end mid-flow
        emit(key, f)
    out.sort(key=lambda o: o.ts)
    return out


def from_events(path: str, asn_lookup) -> list[Observation]:
    """Replay a scenario's event list as Observations, in scenario time."""
    events = json.load(open(path))
    out: list[Observation] = []
    for ev in events:
        asn, name, cc = asn_lookup(ev["dst"])
        out.append(Observation(
            ts=ev["t"], source="tls_egress", subject="172.28.0.5",
            fields={
                "dst": ev["dst"], "dport": 443,
                "asn": asn, "asn_name": name, "cc": cc,
                "bytes": ev["nbytes"], "duration": 0.2,
                "sni": f"{ev['dst'].replace('.', '-')}.vendor-cloud.test",
            },
        ))
    out.sort(key=lambda o: o.ts)
    return out

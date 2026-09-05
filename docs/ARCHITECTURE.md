# Architecture

## Where GridHawk sits

Grid Lockout defines a five-layer control stack. GridHawk implements two of them.

| Layer | Control | Status |
|---|---|---|
| 1 · Fleet inventory | Entity-resolved registry from interconnection records | BUILT (Grid Lockout artifact) |
| **2 · Network egress attestation** | **Passive monitor at the site boundary** | **this repo** |
| **3 · RF egress detection** | **Spectrum monitoring at the enclosure** | **this repo** |
| 4 · Power-side behavioural attestation | Compare actual P/Q against commanded setpoint | spec only |
| 5 · SunSpec attestation register | Somewhere to put a firmware-integrity result | reference impl pending |

Layers 2 and 3 are separate for a structural reason, not an organisational one.
The threat that motivated the project — an undocumented cellular radio inside
the enclosure — **never touches the site network**. Egress monitoring cannot
observe traffic that does not traverse it. Layer 3 exists precisely to cover
what Layer 2 cannot see, so the two must fail independently.

## Data flow

```
  ┌────────────────┐
  │ sources        │
  │                │        Observation
  │  rf ───────────┼──────┐  (ts, source, subject, fields)
  │  tls_egress ───┼──────┤
  │  modbus     ▨  ├──────┤
  │  correlate  ▨  ├──────┤
  └────────────────┘      │
                          ▼
                   ┌─────────────┐   Baseline (learned, not hardcoded)
                   │ rules       │◄──────────────┐
                   │  evaluate() │               │
                   └──────┬──────┘   maintenance_windows (operator change log)
                          │
                          ▼  Finding (kind, severity, detail, mw_at_risk)
                   ┌─────────────┐
                   │ sinks       │   priority = severity_weight × MW_at_risk
                   │  jsonl      │
                   └─────────────┘
  ▨ = not yet built
```

## The invariant that makes this testable

**No collector knows where its input came from.** A source reading a live
capture, a replayed pcap, and the simulator all emit the identical
`Observation` shape. That has three consequences worth stating explicitly:

1. Scoring against the simulator exercises the *same* rule code that would run
   against hardware. There is no separate "test mode" that could drift.
2. Swapping the simulator for a bench inverter changes one call site, not the
   rules engine.
3. The ASN resolver is injected as a parameter (`asn_lookup`), so replacing the
   test fixture with Team Cymru or MaxMind touches no detection logic.

## Module map

| Path | Responsibility |
|---|---|
| `core/events.py` | `Observation`, `Finding`, the anomaly vocabulary, priority |
| `core/rules.py` | Baseline learning, all detection rules, abstain guards |
| `collectors/tls_egress.py` | Layer 2 — flow assembly from pcap or replay |
| `collectors/pcap.py` | Minimal classic-pcap reader + TLS SNI parser (stdlib) |
| `collectors/rf.py` | Layer 3 — carrier detection, ppm estimation, identification |
| `sim/scenario.py` | Scenario generator + sealed manifest + known schedule |
| `sim/rf_synth.py` | rtl_power CSV synthesiser with modelled crystal offsets |
| `sim/cloud/server.py` | Fake vendor cloud (HTTPS, byte-blob endpoint) |
| `sim/inverter/client.py` | MCU-profile TLS client, replays a scenario |
| `sim/asn_fixture.py` | Static IP→ASN table + allowlists |
| `sim/score.py` | Precision / recall / FP-rate against the manifest |
| `detect.py` | CLI entry: input → collector → rules → findings |
| `correlate/` | Layer 1 join (MW-at-risk weighting) — **not yet built** |

## Dependencies

None. Python 3.11+ standard library only — including the pcap reader, which
exists specifically to avoid a scapy dependency. `requirements.txt` is
deliberately empty of packages.

## Design decisions and their costs

| Decision | Why | What it costs |
|---|---|---|
| Metadata-only TLS | No device → no cert → no interception | Cannot see payloads; cloud-mediated attacks invisible |
| One queue, many sources | Sources fail independently; uniform rules | Cross-source correlation must be explicit |
| Learned baselines | Rig constants can change without invalidating thresholds | Needs a clean learning period |
| Injected `asn_lookup` | Fixture now, real data later, no logic change | Indirection at every call site |
| Findings carry `mw_at_risk` | Grid Lockout Layer 2: priority = anomaly × MW | Meaningless until `correlate/` exists |
| Abstain guards | Refuse to assert when the model is unreliable | Recall loss, silently, unless logged |

# Simulation harness

## Why a simulator at all

There is no bench inverter. Everything the Layer 2 detector consumes must be
generated. That creates a specific epistemic hazard, and the harness is
designed around avoiding it.

## The hazard: circular validation

A detector tuned against a generator you also wrote will pass every test and
prove nothing — it has learned to recognise its author, not an attack. Three
mechanisms guard against this.

### 1 · Red/blue split with a sealed manifest

`sim/scenario.py` decides what happens and writes the answer key to
`truth/<seed>.json`. The detector reads only `runs/<seed>.events.json`.

**`truth/` is gitignored.** Committing the manifests would place the answer key
in the repository next to the detector.

Whoever tunes the detector must not read the manifest before scoring.

### 2 · Clean runs

Some seeds inject **nothing**:

```python
for _ in range(rng.randint(0, 4)):   # zero is a legitimate outcome
```

A detector never tested against clean input has an unmeasured false-positive
rate, which is the number an operator actually feels. In the standard 12-seed
set, 3 seeds are clean.

### 3 · Fidelity beyond the detector

The simulator emits properties the detector does not yet key on (SNI, session
duration, dport). Simulating only what you already detect makes it impossible
to discover a detection you had not thought of.

## Fidelity budget

The detector reads only TLS metadata, so the simulator only needs to be
faithful along the axes that are observable.

| Axis | Why it matters | Effort |
|---|---|---|
| Cadence | Drives most detections | must be right |
| Volume envelope | Firmware-pull detection is entirely volume | must be right |
| Destination / ASN | Core allowlist rule | must be right |
| Handshake fingerprint | Only matters if JA3 detection is claimed | optional |
| Payload | Encrypted — unreadable by construction | zero |

## Device profile

`sim/scenario.py::PROFILE`

| Channel | Interval | Jitter | Bytes |
|---|---|---|---|
| `heartbeat` | 60 s | 5 s | 200–400 |
| `telemetry` | 300 s | 15 s | 1 200–8 000 |
| `fw_check` | 86 400 s | 3 600 s | 500–1 500 |

**These constants are assumed, not measured.** Forescout's SUN:DOWN
(27 March 2025) documents real Sungrow / Growatt / SMA cloud behaviour and is
the correct source to replace them with. Doing so converts the profile from
invented to sourced — cheap, and it materially strengthens the claim.

## Network fixture

| IP | ASN | Name | Country | Role |
|---|---|---|---|---|
| 172.28.0.10 | 64500 | VENDOR-CLOUD-PRIMARY | DE | authorised |
| 172.28.0.11 | 64500 | VENDOR-CLOUD-SECONDARY | DE | authorised |
| 172.28.0.12 | 64501 | VENDOR-CDN-FIRMWARE | NL | authorised |
| 172.28.0.20 | 64666 | UNKNOWN-TRANSIT | CN | `new_asn` |
| 172.28.0.21 | 64500 | VENDOR-CLOUD-PRIMARY | CN | `geo_drift` (right ASN, wrong country) |
| 172.28.0.22 | 64777 | COMMERCIAL-VPN | RU | `tunnel_indicator` |

`ALLOWED_ASNS = {64500, 64501}`, `ALLOWED_COUNTRIES = {"DE", "NL"}`

Distinct **IPs**, not distinct ports — ASN drift is an IP-level detection and
would not be exercised by ports alone.

## Injected anomalies

| Kind | Destination | Bytes | Signal |
|---|---|---|---|
| `new_asn` | 172.28.0.20 | 800–20 000 | unallowlisted ASN |
| `geo_drift` | 172.28.0.21 | 800–20 000 | allowed ASN, CN |
| `tunnel_indicator` | 172.28.0.22 | 800–20 000 | VPN-named ASN |
| `off_cycle_burst` | authorised | 1 000–5 000 | timing only |
| `volume_spike` | authorised | 2 M–16 M | size only |

The last two are deliberately hard: an authorised destination with only one
anomalous dimension.

## Two input paths, one Observation stream

| Path | Function | Use |
|---|---|---|
| Replay | `tls_egress.from_events()` | Deterministic; used for scoring |
| Capture | `tls_egress.from_pcap()` | Real packets; proves the capture path |

Both emit identical `Observation` shapes into the same rules engine. Scoring
uses replay because scenario time is exact; the pcap path exists so the capture
code is exercised by the same rules rather than a mock.

## Running the rig live

Terminal 1 — fake cloud:

```
make cloud            # python3 -m sim.cloud.server --bind 127.0.0.1 --port 8443
```

Terminal 2 — capture:

```
sudo tcpdump -i lo0 -w runs/live.pcap 'tcp port 8443'
```

Terminal 3 — drive real TLS sessions:

```
make replay           # --speed 600 = 600 simulated seconds per real second
```

Then:

```
python3 detect.py --pcap runs/live.pcap --out found/live.jsonl
```

`tcpdump` must write **classic pcap** (`-w`), not pcapng. `collectors/pcap.py`
raises a clear error on pcapng rather than misparsing it.

## TLS client fidelity

`sim/inverter/client.py::mcu_context()` constrains the client toward an
embedded profile: TLS 1.2 only, two cipher suites, `OP_NO_TICKET`.

**It is still OpenSSL.** Its JA3 is not an mbedTLS or wolfSSL fingerprint.
No JA3-based detection is claimed anywhere in this repo. To claim one, build
mbedTLS's `ssl_client2` and shell out to it.

## Scoring

`sim/score.py` matches findings to manifest entries by `(kind, time)` within a
tolerance window (default 30 s).

Findings carrying `detail.window_start` are **interval-localised** — a cadence
anomaly lies somewhere within an interval, not at an instant — and match if the
truth time falls anywhere in `[window_start − tol, ts + tol]`.

Reported: per-seed and aggregate precision, recall, and false positives on
clean runs. A single seed is an anecdote; the 12-seed set with 3 clean runs is
a result.

## Reproducing

```
make scenarios        # generate scenarios + sealed manifests + schedules
make detect           # run the detector over each replay
make score            # score against the manifests

# with the operator-known firmware schedule
for s in 4711 1009 2 77 314 1618 2718 8080 9001 13 555 42; do
  python3 detect.py --events runs/$s.events.json \
                    --schedule runs/$s.schedule.json --out found/$s.jsonl
done
python3 -m sim.score --verbose
```

## What the harness proves — and does not

**Proves:** the pipeline works end to end (capture → flow assembly → ASN
attribution → baseline learning → rule evaluation → ranked findings); the rules
fire on the specified traffic shapes; the false-positive rate on clean input is
measured, not assumed.

**Does not prove:** that real inverters produce these shapes. Cadence and volume
constants are assumptions. Say so — the phrasing Grid Lockout already uses works:
*validated against synthetic traffic on assumed device profiles; not validated
against a bench inverter.*

# API reference

All modules are standard-library only. Import paths are relative to the repo root.

---

## `core.events`

The shared vocabulary. Every collector emits `Observation`; the rules engine
emits `Finding`.

### `KINDS`
```python
("new_asn", "geo_drift", "off_cycle_burst", "volume_spike",
 "tunnel_indicator", "excess_emitter", "modbus_write", "attestation_fail")
```
The scenario generator injects by these names and the scorer matches on them,
so generator and detector must agree exactly. `Finding.__post_init__` rejects
anything else — a typo fails loudly at construction rather than silently
scoring as a miss.

### `SEVERITIES`
```python
("info", "low", "medium", "high", "critical")
```

### `class Observation`
| Field | Type | Meaning |
|---|---|---|
| `ts` | `float` | scenario seconds (replay) or epoch (pcap) |
| `source` | `str` | `tls_egress` \| `rf` \| `modbus` |
| `subject` | `str` | device id, source IP, or band |
| `fields` | `dict` | source-specific payload |

`.to_dict()`, `.to_json()`

### `class Finding`
| Field | Type | Meaning |
|---|---|---|
| `ts` | `float` | when |
| `source` | `str` | which collector |
| `subject` | `str` | what |
| `kind` | `str` | must be in `KINDS` |
| `severity` | `str` | must be in `SEVERITIES` |
| `detail` | `dict` | evidence |
| `mw_at_risk` | `float \| None` | from the Layer 1 correlator |

**`.priority`** →
`{"info":0.1,"low":0.3,"medium":1.0,"high":3.0,"critical":10.0}[severity] × (mw_at_risk or 0.001)`

Grid Lockout Layer 2: *alert priority = anomaly × MW behind the device.*

### `write_findings(path, findings)`
Writes JSONL sorted by descending priority.

---

## `core.rules`

### `evaluate(obs, allowed_asns, allowed_countries, baseline=None, volume_factor=8.0, maintenance_windows=None) -> list[Finding]`

Runs every rule. See [RULES.md](RULES.md) for each rule's semantics and blind
spots.

| Parameter | Default | Meaning |
|---|---|---|
| `allowed_asns` | — | ASNs the device may contact |
| `allowed_countries` | — | countries an allowed ASN may announce from |
| `baseline` | learned from `obs` | pre-learned envelope |
| `volume_factor` | `8.0` | multiple of p95 bytes that counts as a spike |
| `maintenance_windows` | `None` | `[(start, end), …]` suppressing timing/volume rules only |

### `class Baseline`
`.learn(obs)` → self. Populates `dst_seen`, `volumes`, `vol_median`,
`vol_p95`, `intervals`, `interval_median`.

### `_log_bands(volumes, min_gap=0.25, max_bands=4)`
Splits sessions into channels at the widest gaps in `log10(bytes)`. Returns
**contiguous** `(lo, hi)` edges in log space.

### `_band_of(nbytes, edges) -> int`

### `_cadence_rule(obs, factor=0.5, claimed=None, maintenance_windows=None)`
Off-cycle detection with deduplication and the firing-rate abstain guard.

---

## `collectors.rf`

### `parse_rtl_power(path) -> list[list[tuple[float, float]]]`
Returns sweeps; each sweep is `[(freq_hz, power_db), …]` sorted by frequency.
Rows sharing a timestamp form one sweep.

### `find_carriers(bins, snr_db=10.0, min_prominence_db=3.0, smooth_bins=3) -> list[Carrier]`
Prominence-based peak detection over a robust (median/MAD) noise floor.

### `class Carrier`
`freq_hz` (linear-power centroid), `power_db` (peak), `width_hz`, `n_bins`.
`.ppm_from(nominal_hz)` → offset in ppm.

### `class KnownEmitter`
`freq_hz`, `tol_hz=2000.0`, `label="baselined"`.

**`.from_baseline(csv_path, label="baselined", tol_hz=2000.0) -> list[KnownEmitter]`**
Learns expected carriers from a capture of the authorised emitter alone,
clustering across sweeps within `tol_hz`.

### `analyse_sweep(bins, ts, band_name, expected_emitters=1, nominal_hz=None, snr_db=10.0, known=None)`
→ `(Observation, list[Finding])`

With `known`, reports **which** carriers are unaccounted (severity `critical`).
Without it, falls back to counting against `expected_emitters`
(`critical` if more than one excess, else `high`).

### `run_file(path, band_name, expected_emitters=1, nominal_hz=None, snr_db=10.0, known=None)`
→ `(list[Observation], list[Finding])`. Replays an rtl_power CSV.

---

## `collectors.pcap`

Minimal classic-pcap reader. Handles Ethernet (with VLAN tags), BSD loopback
(macOS `lo0`), raw IP, and Linux cooked capture. **pcapng is unsupported** and
raises a clear error.

### `read(path) -> Iterator[Packet]`
Yields every TCP/IPv4 packet.

### `class Packet`
`ts`, `src`, `dst`, `sport`, `dport`, `flags`, `payload`, `wire_len`;
properties `.syn`, `.fin`, `.rst`.

### `parse_sni(payload) -> str | None`
Extracts `server_name` from a TLS ClientHello.

---

## `collectors.tls_egress`

### `from_pcap(path, asn_lookup, port=443) -> list[Observation]`
Assembles bidirectional TCP flows, closing on FIN/RST. Flows still open at
end-of-capture are emitted rather than dropped.

### `from_events(path, asn_lookup) -> list[Observation]`
Deterministic replay in scenario time. Used for scoring.

Both emit `fields`: `dst`, `dport`, `asn`, `asn_name`, `cc`, `bytes`,
`duration`, `sni`.

`asn_lookup` is a callable `ip -> (asn, name, country)` — the seam for real ASN
data.

---

## `sim.scenario`

### `build(seed, duration_s=7200.0) -> (list[Event], list[dict])`
Returns events and the ground-truth manifest. Injects 0–4 anomalies; **zero is
a legitimate outcome**.

### `known_schedule(events, pad=120.0) -> list[tuple[float, float]]`
Maintenance windows around **benign** `fw_check` events only. Operator
knowledge, not answer-key leakage — an injected anomaly never appears here.

### `class Event`
`t`, `kind`, `dst`, `nbytes`, `benign`.

### CLI
```
python3 -m sim.scenario --seed N [--duration S] [--events-out P] [--truth-out P]
```
Writes `runs/<seed>.events.json`, `truth/<seed>.json`, `runs/<seed>.schedule.json`.

---

## `sim.rf_synth`

### `class Emitter`
`ppm`, `power_db`, `width_hz`, `drift_ppm_per_s=0.0`.

### `write_csv(path, nominal_hz, emitters, span_hz=200000.0, bin_hz=1000.0, sweeps=10, noise_floor_db=-60.0, noise_sigma_db=1.5, seed=0)`

### `preset(name, rng_seed=0) -> (nominal_hz, list[Emitter])`
`single` · `dual` (8–40 ppm apart) · `dual_close` (3 ppm — deliberately
unresolvable, documents the limit).

### CLI
```
python3 -m sim.rf_synth --preset dual --out runs/rf.csv [--bin-hz 1000] [--span-hz 200000] [--sweeps 10] [--seed 0]
```

---

## `sim.score`

### `score_one(truth_path, found_path, window=30.0) -> dict`
Returns `tp`, `fp`, `fn`, `precision`, `recall`, `clean_run`, `missed`,
`false_positives`.

Findings carrying `detail.window_start` are interval-matched:
`window_start − tol ≤ truth_t ≤ ts + tol`.

### CLI
```
python3 -m sim.score [--truth-dir truth] [--found-dir found] [--window 30] [--verbose]
```

---

## `sim.asn_fixture`

`asn_lookup(ip) -> (asn, name, country)`; `TEST_ASN`, `ALLOWED_ASNS`,
`ALLOWED_COUNTRIES`, `UNKNOWN`.

---

## `sim.cloud.server` / `sim.inverter.client`

```
python3 -m sim.cloud.server --bind 127.0.0.1 --port 8443 [--certdir sim/cloud/certs]
python3 -m sim.inverter.client --events runs/N.events.json [--host H] [--port P] [--speed 60] [--limit N]
```

Cloud: `POST /telemetry`, `GET /blob?n=<bytes>`. Self-signed cert on first run.
Client: `mcu_context()` constrains to TLS 1.2, two ciphers, no tickets — still
OpenSSL, so **no JA3 claims**.

---

## `detect.py`

```
python3 detect.py (--events P | --pcap P) --out P [--volume-factor 8.0] [--schedule P]
```

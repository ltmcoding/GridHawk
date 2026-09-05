# Detection rules

Every rule is stated with what it catches **and what it structurally cannot
see**. The blind spots are not caveats bolted on afterwards; they are the
reason the layered design exists.

Entry point: `core.rules.evaluate(obs, allowed_asns, allowed_countries,
baseline=None, volume_factor=8.0, maintenance_windows=None) -> list[Finding]`

## Baseline learning

`core.rules.Baseline.learn(obs)` derives, from the observation stream itself:

| Attribute | Meaning |
|---|---|
| `dst_seen` | destination → session count |
| `volumes`, `vol_median`, `vol_p95` | session byte-size envelope |
| `intervals`, `interval_median` | inter-session timing |

Learned rather than hardcoded so that changing the simulator's profile
constants does not silently invalidate thresholds. The cost is that a baseline
learned from a window containing an attack is a poisoned baseline — a real
deployment needs a known-clean learning period.

---

## 1 · `new_asn` — destination outside the allowlist

**Fires when** a session's destination ASN is not in `allowed_asns`.
**Severity** `high`. **Source** `tls_egress`.

The core allowlist control. Grid Lockout Layer 2: *"endpoint allowlist, ASN and
destination drift."*

**Cannot see:** an attack arriving through the vendor's own legitimate cloud —
which is exactly what Forescout demonstrated in SUN:DOWN. If the adversary
compromises the vendor's infrastructure, every packet lands on an allowlisted
ASN and this rule is silent by construction.

**Stays armed inside maintenance windows.** A scheduled firmware update
explains timing and volume; it never explains a new destination.

## 2 · `geo_drift` — allowed ASN, unexpected country

**Fires when** the ASN is allowed but the country is not in
`allowed_countries`. **Severity** `medium`.

Catches an allowlisted network announcing from an unexpected region — a weaker
but real signal of infrastructure change.

**Cannot see:** an adversary who routes through the correct country. Geolocation
of IP space is approximate and changes without notice; expect this rule to be
the noisiest in a real deployment.

**Stays armed inside maintenance windows.**

## 3 · `tunnel_indicator` — egress shaped like a proxy or VPN

**Fires when** an out-of-allowlist ASN's name matches `TUNNEL_HINTS`
(`VPN`, `PROXY`, `TOR`, `TUNNEL`). **Severity** `high`.

A specialisation of `new_asn`: same trigger, more specific classification.

**Cannot see:** a tunnel whose ASN is not named like one. Name matching is a
convenience, not a protocol analysis. A real implementation should use
behavioural indicators (packet-size entropy, timing regularity) rather than
WHOIS strings.

## 4 · `volume_spike` — session sized like a firmware image

**Fires when** session bytes exceed `volume_factor` × the learned 95th
percentile. Default `volume_factor = 8.0`. **Severity** `medium`.

Grid Lockout Layer 2: *"volume anomaly consistent with an image pull."*

**Cannot see:** a slow exfiltration spread across many normal-sized sessions.
This rule keys on a single outlier, so anything that stays inside the envelope
is invisible to it.

**Suppressed inside maintenance windows** — a scheduled update legitimately
explains a large transfer.

## 5 · `off_cycle_burst` — connection early against its channel's period

`core.rules._cadence_rule(obs, factor=0.5, claimed=None, maintenance_windows=None)`

**Fires when** the gap between consecutive sessions *in the same channel* is
below `factor` × that channel's median period. Default `factor = 0.5`.
**Severity** `medium`.

### Channel separation

A device multiplexes several logical channels (heartbeat, telemetry, firmware)
over one destination, each with its own period. Pooling them yields a
meaningless cadence, so sessions are first split by byte magnitude:

- `_log_bands(volumes, min_gap=0.25, max_bands=4)` splits at the widest gaps in
  `log10(bytes)`, producing **contiguous** bands.
- `_band_of(nbytes, edges)` assigns a session to a band.

Band edges must be contiguous. An earlier version left holes between bands, and
every session falling in a hole was silently dumped into the final band, where
it polluted that band's cadence with unrelated traffic.

### Interval localisation

An injected session splits one nominal interval into two shorter ones, so
either endpoint could be the intruder. The finding therefore carries
`detail.window_start` and localises the anomaly to the **interval**, not an
instant. `sim/score.py` honours this when matching.

### Deduplication

An injected session also perturbs cadence, so without suppression it is
reported twice — once by the rule that owns it and once here. Findings whose
interval endpoints are already `claimed` by a stronger rule are dropped.
This is deduplication, not threshold tuning: no constant changes.

Measured effect: precision 0.64 → 0.90.

### Abstain guard

Byte-magnitude banding is brittle. When a sparse channel bridges two dense
ones, the split vanishes and unrelated traffic pools into a single band whose
median period is meaningless. Unguarded, this produced **274 false positives**
on one 24-hour run.

Dispersion does **not** catch this. A dominant channel keeps the MAD small
(measured 0.102) while a second channel injects hundreds of short gaps — the
distribution is bimodal, not merely wide.

What catches it is the **firing rate**: a rule flagging a large fraction of all
sessions is mismodelling the channel, not detecting anomalies.

```python
short = [i for i, g in enumerate(gaps, start=1) if g < factor * med]
if len(short) > max(3, 0.05 * len(gaps)):
    continue   # abstain for this band
```

The `max(3, …)` term keeps small bands usable: a band of 24 gaps would
otherwise abstain on a single genuine detection.

**Cost:** real off-cycle bursts in an unseparable band are missed. This is a
deliberate trade of recall for a usable alert stream, and it is *silent* —
a production build should log every abstention.

**Cannot see:** an extra session that happens to land on the cadence, or a
compromise riding an existing legitimate connection.

## 6 · `excess_emitter` — more carriers than documented radios

Emitted by `collectors/rf.py`. See [RF.md](RF.md).

---

## Maintenance windows

`maintenance_windows: list[tuple[float, float]]` — spans the operator
legitimately knows about, from their own change log.

Suppression is **deliberately partial**:

| Rule | Suppressed in window? | Reason |
|---|---|---|
| `new_asn` | **no** | An update never explains a new destination |
| `geo_drift` | **no** | Same |
| `tunnel_indicator` | **no** | Same |
| `volume_spike` | yes | An update explains a large transfer |
| `off_cycle_burst` | yes | An update explains off-cadence timing |

Suppressing everything would publish a predictable blind spot an adversary can
simply wait for. Measured effect of supplying a schedule: **every** false
positive eliminated at both 2 h and 24 h windows, recall unchanged at 1.00.

## Severity and priority

```python
weight = {"info": 0.1, "low": 0.3, "medium": 1.0, "high": 3.0, "critical": 10.0}
priority = weight[severity] * (mw_at_risk or 0.001)
```

`mw_at_risk` is populated by the Layer 1 correlator (not yet built). Until then
priority ranks by severity alone. The intent is Grid Lockout's: *a 501 kW
Sungrow and a 7 kW microinverter raising the same flag are not the same alert.*

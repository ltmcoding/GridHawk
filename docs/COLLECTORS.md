# Collectors

Four sources feed one queue. Two are built.

| Collector | Direction | Protocol | Input available | Status |
|---|---|---|---|---|
| `tls_egress` | outbound (device is **client**) | TLS metadata | replay / pcap | **built** |
| `rf` | emissions | rtl_power sweeps | synthetic / real SDR | **built** |
| `modbus` | inbound, local | SunSpec Modbus TCP | pymodbus emulator | not built |
| `correlate` | — | Layer 1 inventory | **real data** | not built |

---

## `tls_egress` — Layer 2

**The device is the client.** Grid Lockout specifies Layer 2 as a passive tap
watching *outbound* traffic: endpoint allowlist, ASN and geolocation drift,
tunnel indicators, off-cycle bursts, volume anomalies. Every one of those is a
property of the inverter calling a vendor cloud.

### Metadata only — and why

No bench inverter → no firmware extraction → no client certificate → no mTLS
interception → **no payload visibility**.

Two further facts make this permanent rather than temporary:

- A certificate alone is public and decrypts nothing; you need the private key.
- Passive decryption only works with RSA key exchange. TLS 1.3 always uses
  ephemeral key exchange, and so does any well-configured 1.2, so a captured
  session cannot be decrypted after the fact. Interception must be inline.

Observable: destination IP, ASN, country, SNI, session byte volume, duration,
connection cadence.

### Flow assembly

Bidirectional TCP flows keyed on `(client_ip, server_ip, client_port, server_port)`,
normalised so both directions accumulate into one flow. Closed on FIN or RST;
flows still open at end-of-capture are emitted rather than dropped — captures
routinely end mid-session.

### Two input paths

`from_pcap()` proves the capture path; `from_events()` gives deterministic
scenario-time replay for scoring. Identical `Observation` output, same rules
engine — there is no separate test path that could drift from production code.

### Cannot see

- TLS payload contents
- Attacks arriving through the vendor's own legitimate cloud (Forescout SUN:DOWN)
- **An undocumented radio inside the enclosure** — the threat that motivated the
  project. This is Layer 3's job, and the reason the two layers must be separate.

---

## `rf` — Layer 3

Detects N independent emitters in a band; flags carriers that are unaccounted
for. Full treatment in [RF.md](RF.md).

Key points:

- Prominence-based peak detection over a median/MAD noise floor
- Linear-power centroid for sub-bin frequency accuracy
- ppm offset per carrier — the crystal-tolerance view
- **Identification** against a baselined emitter, which catches the case
  counting cannot: authorised radio silent, rogue transmitting
- Measured resolution limit: separation > ~1.3 × carrier occupied bandwidth

### Cannot see

Anything transmitted over the site's own authorised network path — that is
Layer 2's job. Also: bursts falling between sweeps, and harmonics are
misread as independent emitters.

---

## `modbus` — not built

**Highest-value unbuilt collector after `correlate`, and it needs no hardware.**

SunSpec Modbus is mandated by IEEE 1547-2018 and has, in Grid Lockout's words,
*"no encryption, no node authentication, no key management."* Two capabilities
fall out of one parser:

1. **Metrics** — the register map from
   `szlaskidaniel/solar-inverter-modbus-registers`.
2. **Detection** — function codes `0x05`, `0x06`, `0x0F`, `0x10` are **writes**.
   Anyone on the network can issue them. A write from a non-allowlisted IP is
   the strongest unauthorised-control signal available anywhere in this system,
   and it is nearly free once the parser exists.

Plan: `pymodbus` emulator exposing Grid Lockout's proposed **Model 7xx firmware
integrity attestation** block, plus a client polling `AttState` and raising on
`2` (fail) or `3` (stale). That is Layer 5's reference implementation and it
answers the Konstantinou gap directly — the integrity check is computable and
has nowhere to go.

Finding kinds are already reserved: `modbus_write`, `attestation_fail`.

---

## `correlate` — not built

**The highest-priority gap.** It is the only collector backed by *real* data:
Grid Lockout's 2 110 834 resolved installs and 19.64 GW of attributed capacity.

Grid Lockout Layer 2 specifies `alert priority = anomaly × MW behind the device`.
`Finding.mw_at_risk` and `Finding.priority` already exist for this; until the
correlator lands, `mw_at_risk` is `None` and priority ranks by severity alone.

Why it matters: a 501 kW Sungrow and a 7 kW microinverter raising the same flag
are not the same alert. The anomalies are of uncertain provenance; the megawatts
behind them are measured fact.

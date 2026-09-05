# GridHawk — architecture and measured status

GridHawk implements **Layers 2 and 3** of the Grid Lockout stack.
Layer 1 (fleet inventory) is built and lives in the Grid Lockout artifact.

## Collectors

Four sources, one queue, one rules engine. No source knows whether its input
is live hardware, a replayed capture, or the simulator.

| Collector | Direction | Input available to us | Status |
|---|---|---|---|
| `tls_egress` | outbound (device is the **client**) | replayed events / pcap | working |
| `rf` | emissions | `rtl_power` CSV, synthetic or real | working |
| `modbus` | inbound, local | pymodbus emulator | not yet built |
| `correlate` | — | Grid Lockout inventory (real data) | not yet built |

## What we cannot do, and why

No bench inverter → no firmware → no client certificate → **no TLS payload
visibility**. This matches Grid Lockout's own coverage matrix, which already
lists "TLS payload contents" in Layer 2's cannot-see column. Nothing here
claims otherwise.

`tls_egress` is metadata-only: destination, ASN, country, session byte volume,
connection cadence.

## Measured results — TLS egress

12 seeds, 3 of them clean (zero injected anomalies), 2-hour window,
red/blue split (the manifest is sealed until scoring).

| | without firmware schedule | with operator-known schedule |
|---|---|---|
| precision | 0.90 | **1.00** |
| recall | 1.00 | **1.00** |
| false positives on clean runs | 1 of 3 | **0 of 3** |

Supplying the site's own firmware-update schedule removes **every** false
positive at both window lengths (24 h: 11 FPs -> 0, precision 0.69 -> 1.00)
while recall stays at 1.00. Every residual FP was a scheduled firmware check
aliasing into the telemetry cadence, so operator change-log knowledge is worth
more here than any threshold tuning.

**Security note.** Maintenance windows suppress only the TIMING and VOLUME
rules. A scheduled update explains when a session happens and how big it is;
it never explains a NEW DESTINATION. The ASN and geo rules stay armed inside
the window, otherwise it becomes a predictable blind spot an adversary can
simply wait for.

False-positive rate vs. observation window (12 seeds each):

| window | precision | recall | FP per device-day |
|---|---|---|---|
| 2 h | 0.90 | 1.00 | 2.00 |
| 6 h | 0.88 | 0.92 | 1.00 |
| 24 h | 0.69 | 1.00 | 0.92 |
| 72 h | 0.47 | 0.87 | 0.64 |

(without a firmware schedule; with one, 2 h and 24 h both reach 1.00/1.00)

Precision falls with window length because more rare legitimate channels
appear; the per-day alert burden nonetheless improves. **Recall is not the
binding constraint — alert burden is.**

### Known limitation: channel separation

The cadence rule groups sessions into channels by byte magnitude. When a
sparse channel bridges two dense ones the split vanishes, pooling unrelated
traffic into one band whose "period" is meaningless. Left unguarded this
produced 274 false positives on one 24-hour run.

The guard is a firing-rate check: a rule that flags more than ~5% of sessions
is mismodelling the channel, not detecting anomalies, so it abstains for that
band. Cost: genuine off-cycle bursts in an unseparable band are missed. That
is a deliberate trade of recall for a usable alert stream.

## Measured results — RF carrier detection

### Identification beats counting

Baselining the authorised emitter alone -- one capture, taken while you know
no other radio is active -- upgrades the detector from counting carriers to
naming the unaccounted one. Measured on synthetic sweeps:

| case | counting | identification |
|---|---|---|
| authorised alone, drifted 0.2 ppm | silent | silent |
| authorised + rogue | flags | flags, **and names the rogue** (+13.4 ppm, 9.6 kHz off) |
| **authorised silent, rogue only** | **blind** | **flags** |

That third row is the reason to baseline. Counting sees one carrier where one
was expected and says nothing. Identification knows that carrier is not the
one it baselined.

Detects N independent emitters in a band. An enclosure documented to contain
one radio that shows two carriers contains an undocumented transmitter.

Two independent crystals never land on the same frequency: at ±25 ppm tolerance
and 433.92 MHz nominal, two units sit up to ~21 kHz apart.

**Resolution limit (measured, synthetic):** two emitters are resolvable only
when their separation exceeds roughly **1.3× the carrier's own occupied
bandwidth**, and the bin width is at most ~1/4 of that separation. Below that
they merge at *any* bin width — a limit of the sweep, not of the code.

| separation | 250 Hz bins | 1 kHz bins | 5 kHz bins |
|---|---|---|---|
| ≤ 8 ppm (3.5 kHz) | merged | merged | merged |
| 12 ppm (5.2 kHz) | resolved | merged | merged |
| 20 ppm (8.7 kHz) | resolved | resolved | merged |
| 50 ppm (21.7 kHz) | resolved | resolved | resolved |

Carriers modelled at 3 kHz occupied bandwidth.

### RF bench test — band and modulation constraints

The two-transmitter test **cannot use 2.4 GHz Wi-Fi**:

1. The RTL-SDR (R820T2/R828D) tunes ~24 MHz–1.766 GHz. 2.4 GHz is out of range.
2. Its usable instantaneous bandwidth is ~2.4 MHz; a Wi-Fi channel is 20 MHz.
3. Wi-Fi is OFDM — energy spread across the channel with no dominant carrier
   line. There is no spike whose frequency can be measured. Carrier frequency
   offset in Wi-Fi is recovered by the demodulator from pilot subcarriers, not
   visible in a power spectrum.

Use narrowband CW emitters in an RTL-SDR-reachable ISM band instead —
433.92 MHz or 915 MHz. Si5351 clock-generator breakouts are ideal: each
carries its own crystal, so the offset is a genuine independent-oscillator
measurement.

**Measure each transmitter alone first.** Separation depends on the two
specific crystals and is random. Without individual baselines a null result is
ambiguous: undetermined whether the detector failed or the crystals happened
to be close.

## Reproducing

    make scenarios && make detect && make score
    make rf
    python3 -m tests.test_rf

No third-party packages. Python 3.11+ standard library only.

## Honesty notes

- Profile constants (cadence, byte volumes) are **assumed**, not measured.
  Forescout's SUN:DOWN (27 Mar 2025) documents real Sungrow/Growatt/SMA cloud
  behaviour and is the right source to replace them with.
- The simulator's TLS client is constrained-OpenSSL. Its JA3 is **not** an
  mbedTLS or wolfSSL fingerprint. No JA3-based detection is claimed.
- All RF results are synthetic. No signal-level validation against hardware.

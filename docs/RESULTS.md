# Measured results

Every number here is reproducible from this repo. **The RF layer is now validated on real hardware** (see below). The network
layer remains synthetic: there is still no bench inverter. See "Threats to
validity" at the end.

## Method

- 12 seeds: `4711 1009 2 77 314 1618 2718 8080 9001 13 555 42`
- 3 of them clean (zero injected anomalies) — measures false-positive rate
- Red/blue split: manifest sealed in `truth/`, gitignored, not read by the detector
- Matching: `(kind, time)` within 30 s; interval-localised findings matched across their interval
- Default window 7 200 s (2 h)

## Headline — TLS egress

| | without firmware schedule | with operator-known schedule |
|---|---|---|
| precision | 0.90 | **1.00** |
| recall | 1.00 | **1.00** |
| true positives | 18 | 18 |
| false positives | 2 | **0** |
| false negatives | 0 | 0 |
| FPs on clean runs | 1 of 3 | **0 of 3** |

## Per-seed (no schedule)

| seed | truth | tp | fp | fn | precision | recall | note |
|---|---|---|---|---|---|---|---|
| 1009 | 1 | 1 | 0 | 0 | 1.00 | 1.00 | |
| 13 | 1 | 1 | 0 | 0 | 1.00 | 1.00 | |
| 1618 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | |
| 2 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | |
| 2718 | 0 | 0 | 1 | 0 | 0.00 | 1.00 | CLEAN — `fw_check` alias |
| 314 | 2 | 2 | 1 | 0 | 0.67 | 1.00 | `fw_check` alias |
| 42 | 1 | 1 | 0 | 0 | 1.00 | 1.00 | |
| 4711 | 1 | 1 | 0 | 0 | 1.00 | 1.00 | |
| 555 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | |
| 77 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | |
| 8080 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | CLEAN |
| 9001 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | CLEAN |
| **total** | **18** | **18** | **2** | **0** | **0.90** | **1.00** | |

Both false positives were diagnosed, not assumed: the daily `fw_check`
(1 043 B and 643 B) aliasing into a neighbouring channel's cadence.

## Observation window sweep (no schedule)

| window | events | truth | tp | fp | fn | precision | recall | FP / device-day |
|---|---|---|---|---|---|---|---|---|
| 2 h | 1 740 | 18 | 18 | 2 | 0 | 0.90 | 1.00 | 2.00 |
| 6 h | 5 213 | 25 | 23 | 3 | 2 | 0.88 | 0.92 | 1.00 |
| 24 h | 20 792 | 24 | 24 | 11 | 0 | 0.69 | 1.00 | 0.92 |
| 72 h | 62 288 | 23 | 20 | 23 | 3 | 0.47 | 0.87 | 0.64 |

Precision falls with window length because more rare legitimate channels appear,
yet the **per-day alert burden improves**. For an operator, alert burden is the
binding constraint, not recall.

With the firmware schedule supplied, both 2 h and 24 h reach **1.00 / 1.00 with
zero false positives**.

## The abstain guard, quantified

Before and after the firing-rate guard (see [ENGINEERING-LOG.md](ENGINEERING-LOG.md) Bug 4):

| window | FPs before | FPs after | precision before | precision after |
|---|---|---|---|---|
| 2 h | 2 | 2 | 0.90 | 0.90 |
| 6 h | 5 | 3 | 0.83 | 0.88 |
| 24 h | **274** | 11 | 0.08 | 0.69 |
| 72 h | **3 338** | 23 | 0.01 | 0.47 |

Recall cost: 1.00 → 0.92 at 6 h and 1.00 → 0.87 at 72 h. Deliberate.


## Hardware validation — RF (measured, not synthetic)

Raspberry Pi 5, RTL-SDR Blog V4, two Adafruit Feather M0 RadioFruit RFM69HCW
boards flashed with identical firmware and commanded to the identical
frequency (433.920000 MHz). Sweeps at 250 Hz bins across 150 kHz.

### Crystal difference, measured three ways

| measurement | frequency | offset |
|---|---|---|
| board A alone | 433.917479 MHz | **-5.81 ppm** |
| board B alone | 433.918679 MHz | **-3.04 ppm** |
| both together | 433.917477 and 433.918676 | -5.82 and -3.05 |

**Separation: 1,199 Hz — 2.77 ppm of manufacturing difference alone.** The
individual measurements agree with the simultaneous one, which is what allows
each carrier to be attributed to a specific board.

### False-positive rate on real air

Ten sweeps of live 433 MHz spectrum with every transmitter switched off:
**zero carriers detected.** Noise floor -49.3 dB, varying by about 1 dB.

### End-to-end detection, 112 continuous sweeps

| sweeps | state | outcome |
|---|---|---|
| 1-51 (separate run) | authorised only | **0 alerts** |
| 1-24 | authorised + rogue | `CRITICAL`, rogue named |
| **25-33** | **authorised OFF, rogue only** | **still alerts** |
| 34-42 | both off | silent |
| 43-57 | authorised only | silent |
| 58-112 | authorised + rogue | alerts, suppressed to 5 total |

Sweeps 25-33 are the case carrier counting cannot see: one carrier present,
exactly the expected count, but not the baselined one.

### Thermal drift

Both boards drift about **0.15 ppm (~65 Hz) over the first minute** as they
warm, then settle. Well inside the match tolerance, confirming that a baselined
emitter stays recognised across a session.

### What the hardware changed about the design

**Real separations are far tighter than the synthetic tests assumed.** The
simulator used 8-20 kHz; actual parts landed at 1.2 kHz. The 2,000 Hz default
match tolerance would have classified the rogue as the authorised board and
raised nothing -- silently. `--tolerance-hz` exists because of this
measurement, and 400 Hz is the value these boards need.

**A firmware bug produced a convincing wrong answer.** Frequency deviation was
left at the chip default, so the radios transmitted FSK rather than a carrier.
An early two-board reading showed 9,975 Hz of separation -- within 0.35% of
twice the 5,005 Hz default deviation. It looked like a clean result and was an
artifact. Zeroing deviation gave the true 1,199 Hz.

## RF — carrier detection (synthetic)

| test | result |
|---|---|
| single emitter | 1 carrier, no finding |
| two emitters 20.6 ppm apart | 2 carriers, separation 8.93 kHz, `excess_emitter/high` |
| ppm recovery | −29.39 measured vs −29.44 injected (0.05 ppm error) |
| noise only | 0 carriers |
| two emitters 3 ppm apart | 1 carrier — documented resolution limit |

## RF — resolution study

Carriers modelled at 3 kHz occupied bandwidth. "resolved" = 2 carriers on every
sweep of the run.

| separation | 250 Hz | 500 Hz | 1 kHz | 2 kHz | 5 kHz |
|---|---|---|---|---|---|
| 1 ppm (0.43 kHz) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 2 ppm (0.87 kHz) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 3 ppm (1.30 kHz) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 5 ppm (2.17 kHz) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 8 ppm (3.47 kHz) | ✗ | ✗ | ✗ | ✗ | ✗ |
| 12 ppm (5.21 kHz) | ✓ | ✓ | ✗ | ✗ | ✗ |
| 20 ppm (8.68 kHz) | ✓ | ✓ | ✓ | ✓ | ✗ |
| 35 ppm (15.2 kHz) | ✓ | ✓ | ✓ | ✓ | ✗ |
| 50 ppm (21.7 kHz) | ✓ | ✓ | ✓ | ✓ | ✓ |

**Separation must exceed ~1.3 × the carrier's occupied bandwidth**; below that
the pair merges at any bin width. Bin width must then be ≤ ~1/4 of separation.

## RF — identification vs counting

| case | counting | identification |
|---|---|---|
| authorised alone, drifted 0.2 ppm | silent | silent |
| authorised + rogue | flags | flags, **names it** (+13.4 ppm, 9.6 kHz off known) |
| **authorised silent, rogue only** | **blind** | **flags** |

## Test suite

`python3 -m tests.test_rf` → **11/11 passing**, including an assertion that the
3 ppm case remains unresolvable so the documented limit regresses loudly.

## Threats to validity

1. **Profile constants are assumed, not measured.** Cadence and byte volumes are
   invented. Forescout SUN:DOWN documents real vendor cloud behaviour and should
   replace them.
2. **No bench inverter.** The network layer is entirely synthetic. The RF layer
   is now measured on real hardware, but the transmitters are development
   boards standing in for an inverter's own radio -- the measurement is real,
   the subject is not.
3. **Generator and detector share an author.** Mitigated by the sealed manifest,
   clean runs, and simulating properties the detector ignores — but not
   eliminated. An independently written generator would be stronger.
4. **12 seeds is small.** Enough to distinguish 0.90 from 0.64; not enough for a
   confidence interval.
5. **The abstain guard is silent.** Recall lost to abstention is not currently
   logged.
6. **The synthetic carrier model is idealised** — Gaussian envelope, no
   modulation sidebands, phase noise, spurs, or harmonics. Real captures show
   the model was optimistic about separation: actual parts sat 1.2 kHz apart,
   not the 8-20 kHz modelled.
7. **JA3 is not validated.** The simulated client is OpenSSL, not an embedded
   stack, so no fingerprint-based detection is claimed.

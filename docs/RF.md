# RF egress detection (Layer 3)

## Why this layer exists

Grid Lockout, section 08:

> The threat that started this — an undocumented cellular radio inside the
> enclosure — never touches the site network at all. Egress monitoring cannot
> see traffic that does not traverse it.

Layer 3 is the only layer that can observe the failure mode that motivated the
whole project. It is not a second opinion on Layer 2; it covers a disjoint
threat surface.

## The physical principle

Two independent oscillators never land on exactly the same frequency. Crystal
frequency error is a manufacturing tolerance, typically ±10–50 ppm:

```
f_actual = f_nominal × (1 + ppm / 1e6)
```

At 433.92 MHz, a ±25 ppm part sits ±10.8 kHz off nominal, so two nominally
identical transmitters can be ~21 kHz apart. **That frequency gap is the
signature.** An enclosure documented to contain one radio that shows two
distinct carriers contains an undocumented transmitter.

## Detection algorithm

`collectors.rf.find_carriers(bins, snr_db=10.0, min_prominence_db=3.0, smooth_bins=3)`

1. **Robust noise floor.** `floor = median(powers)`, `mad = median(|p − floor|)`.
   A median, not a mean — the carriers are exactly the outliers being hunted, and
   a mean would let them inflate the floor that is supposed to reveal them.
2. **Threshold.** `floor + max(snr_db, 4 × mad)` — whichever is stricter.
3. **Smoothing.** 3-bin moving average, so bin noise does not mint spurious
   local maxima. Power is still read from the *unsmoothed* data.
4. **Peak finding with prominence.** Local maxima above threshold, each
   required to clear `min_prominence_db` above the highest saddle joining it to
   a taller peak.
5. **Extent and centroid.** Walk out to the adjacent minimum or below
   threshold, then take a **linear-power-weighted** centroid. Averaging in dB
   would bias toward the tails.

### Why prominence, not threshold-crossing

The first implementation grouped contiguous runs of bins above threshold. Two
emitters 8.9 kHz apart, each 3 kHz wide, have overlapping skirts: their
above-threshold regions touch, forming **one** run. The detector reported a
single 17 kHz-wide carrier at the midpoint — the arithmetic mean of two real
signals, a frequency at which nothing was transmitting.

Prominence recovers both, because the dip between them is real even though
both sides stay above the noise floor.

## Resolution limit (measured)

Synthetic sweeps, carriers modelled at 3 kHz occupied bandwidth:

| separation | 250 Hz bins | 500 Hz | 1 kHz | 2 kHz | 5 kHz |
|---|---|---|---|---|---|
| 1 ppm (0.43 kHz) | merged | merged | merged | merged | merged |
| 3 ppm (1.30 kHz) | merged | merged | merged | merged | merged |
| 8 ppm (3.47 kHz) | merged | merged | merged | merged | merged |
| 12 ppm (5.21 kHz) | **resolved** | **resolved** | merged | merged | merged |
| 20 ppm (8.68 kHz) | resolved | resolved | **resolved** | **resolved** | merged |
| 35 ppm (15.2 kHz) | resolved | resolved | resolved | resolved | merged |
| 50 ppm (21.7 kHz) | resolved | resolved | resolved | resolved | **resolved** |

**Two rules of thumb:**

1. Separation must exceed roughly **1.3 × the carrier's occupied bandwidth**.
   Below that the pair merges at *any* bin width — a limit of the signal, not
   the algorithm.
2. Bin width must be at most about **1/4 of the separation**.

The first rule is why modulation matters more than bin width. A narrow CW tone
is resolvable at a few kHz of separation; a wideband signal never is.

## Counting vs. identification

Supplying a baseline of the authorised emitter — one capture taken while you
know no other radio is active — converts a counting problem into an
identification problem.

`collectors.rf.KnownEmitter.from_baseline(csv_path, label, tol_hz=2000.0)`

Measured on synthetic sweeps:

| case | counting | identification |
|---|---|---|
| authorised alone, drifted 0.2 ppm | silent | silent |
| authorised + rogue | flags | flags, **and names it** (+13.4 ppm, 9.6 kHz off known) |
| **authorised silent, rogue only** | **blind** | **flags** |

The third row is the reason to baseline. Counting sees one carrier where one was
expected and says nothing. Identification knows that carrier is not the one it
baselined. Identification also survives thermal drift of the authorised emitter
(`tol_hz`, default 2 kHz) and the case where both transmit simultaneously.

## Bench test protocol

### Wi-Fi will not work

The two-transmitter test **cannot** use 2.4 GHz Wi-Fi, for three independent
reasons:

1. **Out of range.** The RTL-SDR in the BOM (RTL2832U + R828D) tunes roughly
   24 MHz – 1.766 GHz. 2.4 GHz is unreachable. Hard blocker.
2. **Bandwidth.** Usable instantaneous bandwidth is ~2.4 MHz; a Wi-Fi channel
   is 20 MHz. You would see a sliver of the channel.
3. **No spectral line.** Wi-Fi is OFDM — energy spread across the channel with
   no dominant carrier. Carrier frequency offset is recovered by the
   demodulator from pilot subcarriers; it does not appear as a measurable spike
   in a power spectrum. Even in range, there would be nothing to measure.

Use **narrowband CW** in an RTL-SDR-reachable ISM band: 433.92 MHz or 915 MHz.

### Emitter options, in order of preference

| Option | Independent crystals? | Notes |
|---|---|---|
| Two Si5351 breakouts | yes | Programmable CW, own crystal each. Ideal |
| Two 433 MHz "RF link" TX modules | yes | Usually **SAW-based**: ±100–200 ppm, so *wider* separation and easier to resolve |
| Two RFM69 / RFM95 breakouts | yes | CW test mode; 915 MHz |
| Two 433/315 MHz remotes already in the building | yes | Key fobs, garage remotes, doorbells, weather stations, TPMS. Zero cost, real hardware |
| One Raspberry Pi, two GPCLK outputs | **no** | Same oscillator — validates the detector, **not** oscillator independence |

### The Raspberry Pi caveat

`rpitx` and the GPIO4/GPCLK0 carrier technique work on Pi 4 and earlier
(including Zero). They do **not** work on the Pi 5: GPIO and clock generation
moved behind the RP1 southbridge. The BOM specifies a Pi 5 — verify before
planning around it.

More fundamentally, one Pi has **one** oscillator. Two clock outputs from the
same board share it, so they cannot demonstrate independent crystal tolerance.
They can demonstrate that the detector separates two carriers, which is a
weaker but still honest claim — label it as such.

An unfiltered square-wave transmitter also emits strong harmonics at 2f, 3f…
which the detector will correctly flag as additional emitters. Keep the wire
short and the duty cycle low, and band-limit the sweep.

### Procedure

1. **Baseline A alone.** Capture emitter A with B powered off.
   `KnownEmitter.from_baseline()` learns its actual carrier.
2. **Re-capture A alone.** The detector must stay silent. *This is the
   false-positive check — do not skip it.* An unstable baseline invalidates
   every step after it.
3. **Capture A + B.** The detector should report B as unaccounted, with its
   ppm offset and its distance from the known carrier.
4. **Capture B alone.** The case counting cannot see, and the strongest single
   demonstration available.

**Measure each emitter individually first.** Separation depends on the two
specific crystals and is random — possibly below the resolution floor. Without
individual baselines, a null result is ambiguous: you cannot distinguish "the
detector failed" from "these two crystals happened to be close."

## rtl_power input format

```
date, time, Hz_low, Hz_high, Hz_step, n_samples, dB, dB, dB, ...
```

Rows sharing a timestamp form one sweep. `parse_rtl_power(path)` returns a list
of sweeps, each `[(freq_hz, power_db), ...]` sorted by frequency.

Suggested capture for a 433.92 MHz test — narrow span, fine bins, fast revisit:

```
rtl_power -f 433.82M:434.02M:250 -i 1 -e 60 out.csv
```

Wide sweeps are the enemy here: `rtl_power` crawls, and a bursty transmitter
can land entirely between sweeps.

## Known limitations

- **All results are synthetic.** No signal-level validation against hardware.
- Carrier shape is modelled Gaussian; real emitters have modulation sidebands,
  phase noise, and spurs.
- No thermal drift modelling in the presets (`Emitter.drift_ppm_per_s` exists
  but defaults to 0).
- No harmonic rejection: a harmonic of a legitimate emitter reads as a
  separate carrier.
- Sweep-rate aliasing is not modelled — a burst between sweeps is invisible.

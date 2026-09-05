"""Synthesise rtl_power CSV sweeps containing N independent emitters.

Models the physics the two-transmitter test relies on: every emitter has its
own crystal, and crystal frequency error is a manufacturing tolerance -- so
two nominally-identical transmitters land at slightly different frequencies.

    f_actual = f_nominal * (1 + ppm / 1e6)

At 433.92 MHz a +/-25 ppm part is +/-10.8 kHz off nominal, so two units can sit
~20 kHz apart.  With a 1 kHz bin width that is ~20 bins of separation: clearly
two spikes.  With a 25 kHz bin width they merge into one and the test fails --
which is why bin_hz matters more than any other knob here.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from dataclasses import dataclass


@dataclass
class Emitter:
    ppm: float           # crystal error vs nominal
    power_db: float      # peak power above the noise floor
    width_hz: float      # occupied bandwidth (CW is narrow; OFDM is not)
    drift_ppm_per_s: float = 0.0   # thermal drift over the run


def _carrier_shape(f: float, centre: float, width_hz: float) -> float:
    """Gaussian-ish spectral envelope, in linear power."""
    sigma = max(width_hz, 1.0) / 2.355   # FWHM -> sigma
    return math.exp(-0.5 * ((f - centre) / sigma) ** 2)


def synth_sweep(
    nominal_hz: float,
    emitters: list[Emitter],
    span_hz: float,
    bin_hz: float,
    noise_floor_db: float,
    noise_sigma_db: float,
    t: float,
    rng: random.Random,
) -> list[tuple[float, float]]:
    lo = nominal_hz - span_hz / 2.0
    n = int(span_hz / bin_hz)
    out: list[tuple[float, float]] = []
    for i in range(n):
        f = lo + i * bin_hz
        lin = 0.0
        for e in emitters:
            ppm = e.ppm + e.drift_ppm_per_s * t
            centre = nominal_hz * (1.0 + ppm / 1e6)
            lin += (10.0 ** (e.power_db / 10.0)) * _carrier_shape(f, centre, e.width_hz)
        p_db = noise_floor_db + rng.gauss(0.0, noise_sigma_db)
        if lin > 0:
            p_db = 10.0 * math.log10(10.0 ** (p_db / 10.0) + lin)
        out.append((f, p_db))
    return out


def write_csv(
    path: str,
    nominal_hz: float,
    emitters: list[Emitter],
    span_hz: float = 200_000.0,
    bin_hz: float = 1_000.0,
    sweeps: int = 10,
    noise_floor_db: float = -60.0,
    noise_sigma_db: float = 1.5,
    seed: int = 0,
) -> None:
    rng = random.Random(seed)
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        for s in range(sweeps):
            bins = synth_sweep(
                nominal_hz, emitters, span_hz, bin_hz,
                noise_floor_db, noise_sigma_db, float(s), rng,
            )
            lo = bins[0][0]
            hi = bins[-1][0] + bin_hz
            w.writerow(
                [f"2026-09-05", f"13:{s // 60:02d}:{s % 60:02d}",
                 f"{lo:.0f}", f"{hi:.0f}", f"{bin_hz:.2f}", "64"]
                + [f"{p:.2f}" for _, p in bins]
            )


# Preset scenarios for the bench test.
def preset(name: str, rng_seed: int = 0) -> tuple[float, list[Emitter]]:
    rng = random.Random(rng_seed)
    if name == "single":
        return 433_920_000.0, [Emitter(ppm=rng.uniform(-25, 25), power_db=-25, width_hz=3_000)]
    if name == "dual":
        # Two independent parts from the same reel: correlated but not equal.
        a = rng.uniform(-25, 25)
        b = a + rng.choice([-1, 1]) * rng.uniform(8, 40)
        return 433_920_000.0, [
            Emitter(ppm=a, power_db=-25, width_hz=3_000),
            Emitter(ppm=b, power_db=-28, width_hz=3_000),
        ]
    if name == "dual_close":
        # Worst case: parts that happen to be near each other. Tests resolution.
        a = rng.uniform(-25, 25)
        return 433_920_000.0, [
            Emitter(ppm=a, power_db=-25, width_hz=3_000),
            Emitter(ppm=a + 3.0, power_db=-27, width_hz=3_000),
        ]
    raise SystemExit(f"unknown preset: {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="synthesise rtl_power CSV")
    ap.add_argument("--preset", default="dual", choices=["single", "dual", "dual_close"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--bin-hz", type=float, default=1_000.0)
    ap.add_argument("--span-hz", type=float, default=200_000.0)
    ap.add_argument("--sweeps", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    nominal, emitters = preset(a.preset, a.seed)
    write_csv(a.out, nominal, emitters, span_hz=a.span_hz, bin_hz=a.bin_hz,
              sweeps=a.sweeps, seed=a.seed)
    print(f"wrote {a.out}: nominal={nominal/1e6:.4f} MHz, {len(emitters)} emitter(s)")
    for e in emitters:
        print(f"  ppm={e.ppm:+.2f} -> {nominal*(1+e.ppm/1e6)/1e6:.6f} MHz  @{e.power_db} dB")


if __name__ == "__main__":
    main()

"""Check the receive chain against real air before trusting it.

Run this whenever the hardware setup changes -- new antenna, new location, new
gain setting -- and always once before a demo.

It answers three questions:

  1. Does the SDR actually produce sweeps?
  2. What is the noise floor here, and how much headroom is there?
  3. Does the detector stay quiet when nothing is transmitting?

That third one matters most. A detector that invents carriers out of noise
would flag an undocumented radio in an empty room, and you would not know until
someone asked. Running this with every transmitter switched off is the
false-positive check, and the number it prints is worth quoting.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import rf_live
from collectors.rf import (
    DEFAULT_SNR_DB, _detection_threshold, _median, find_carriers, parse_rtl_power,
)


DEFAULT_NOMINAL_HZ = 433_920_000.0
DEFAULT_SPAN_HZ = 150_000.0
DEFAULT_BIN_HZ = 250.0
DEFAULT_SWEEPS = 10
DEFAULT_INTEGRATION_S = 1.0

# A transmitter this far above the floor is comfortably detectable without
# risking front-end overload. Below it, move the antenna closer or raise gain;
# far above it, back the transmitter off or you will get spurious carriers.
COMFORTABLE_SIGNAL_MARGIN_DB = 20.0


def _summarise_sweep(sweep, index, nominal_hz, snr_db):
    """Print one sweep's floor, threshold and carriers. Returns the carriers."""
    powers = []
    for _frequency, power in sweep:
        powers.append(power)

    noise_floor = _median(powers)
    threshold = _detection_threshold(powers, snr_db)
    carriers = find_carriers(sweep, snr_db=snr_db)

    print(f"  sweep {index:>2}  floor {noise_floor:7.1f} dB   "
          f"threshold {threshold:7.1f} dB   carriers {len(carriers)}")

    for carrier in carriers:
        offset_ppm = carrier.ppm_from(nominal_hz)
        above_floor = carrier.power_db - noise_floor
        print(f"           {carrier.freq_hz / 1e6:.6f} MHz  {carrier.power_db:+6.1f} dB  "
              f"({above_floor:+.1f} dB over floor, {offset_ppm:+.2f} ppm)")

    return carriers, noise_floor


def _verdict(total_carriers: int, sweep_count: int, floors: list[float]) -> None:
    """Interpret the numbers rather than leaving the reader to do it."""
    print()
    print("=" * 64)

    average_floor = sum(floors) / len(floors) if floors else 0.0
    print(f"  average noise floor : {average_floor:.1f} dB")
    print(f"  sweeps captured     : {sweep_count}")
    print(f"  carriers seen       : {total_carriers}")
    print()

    if total_carriers == 0:
        print("  CLEAN AIR -- no carriers detected.")
        print()
        print("  This is the right answer with every transmitter switched off,")
        print("  and it is your false-positive check: the detector does not")
        print("  invent signals out of noise. Quote this number.")
        print()
        print(f"  For a transmitter to be comfortably detectable it should land")
        print(f"  around {average_floor + COMFORTABLE_SIGNAL_MARGIN_DB:.0f} dB "
              f"({COMFORTABLE_SIGNAL_MARGIN_DB:.0f} dB over the floor).")
    else:
        print("  SIGNALS PRESENT.")
        print()
        print("  If your transmitters are off, these are real devices nearby --")
        print("  key fobs, weather stations, doorbells, tyre sensors all live in")
        print("  this band. That is a working receive chain, not a fault.")
        print()
        print("  But baseline in a quieter spot or a narrower span if you can:")
        print("  a stray emitter inside your span will be treated as unaccounted")
        print("  and raise an alert during the demo.")
    print("=" * 64)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nominal", type=float, default=DEFAULT_NOMINAL_HZ)
    parser.add_argument("--span", type=float, default=DEFAULT_SPAN_HZ)
    parser.add_argument("--bin-hz", type=float, default=DEFAULT_BIN_HZ)
    parser.add_argument("--sweeps", type=int, default=DEFAULT_SWEEPS)
    parser.add_argument("--integration", type=float, default=DEFAULT_INTEGRATION_S)
    parser.add_argument("--gain", default=rf_live.DEFAULT_GAIN_DB)
    parser.add_argument("--device", type=int, default=0)
    parser.add_argument("--snr-db", type=float, default=DEFAULT_SNR_DB)
    parser.add_argument("--replay", default=None,
                        help="analyse a recorded CSV instead of capturing")
    args = parser.parse_args()

    low_hz = args.nominal - args.span / 2.0
    high_hz = args.nominal + args.span / 2.0

    if args.replay:
        print(f"Reading {args.replay} (replay, no radio)\n")
        sweeps = parse_rtl_power(args.replay)[: args.sweeps]
    else:
        if not rf_live.is_available():
            print("rtl_power not found. Install the SDR tools:\n"
                  "  sudo apt install rtl-sdr", file=sys.stderr)
            return 1
        print(f"Capturing {args.sweeps} sweeps across "
              f"{low_hz / 1e6:.4f}-{high_hz / 1e6:.4f} MHz "
              f"at {args.bin_hz:.0f} Hz bins, gain {args.gain}\n")
        sweeps = []
        for sweep in rf_live.stream_sweeps(low_hz, high_hz, args.bin_hz,
                                           args.integration, args.gain,
                                           args.device, max_sweeps=args.sweeps):
            sweeps.append(sweep)

    if not sweeps:
        print("No sweeps captured. Check that the SDR is plugged in and that "
              "'rtl_test' sees it.", file=sys.stderr)
        return 1

    print(f"{len(sweeps)} sweeps, {len(sweeps[0])} bins each\n")

    total_carriers = 0
    floors = []
    for index, sweep in enumerate(sweeps):
        carriers, floor = _summarise_sweep(sweep, index, args.nominal, args.snr_db)
        total_carriers += len(carriers)
        floors.append(floor)

    _verdict(total_carriers, len(sweeps), floors)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

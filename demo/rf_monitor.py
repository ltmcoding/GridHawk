"""Live RF monitoring for the demo: baseline one radio, then watch for others.

Two modes:

  baseline  Listen while ONLY the authorised radio transmits, and record where
            it actually sits. This is the measurement that turns the detector
            from "how many radios are there?" into "which radio is that?"

  monitor   Listen continuously. Any carrier that does not match the baseline
            is an unaccounted transmitter, and each one raises an alert.

Run baseline first, with the second board powered off.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

# Work whether invoked as "python3 demo/rf_monitor.py" or "python3 -m demo.rf_monitor".
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors import rf_live
from collectors.rf import (
    analyse_sweep, carriers_from_sweeps, save_baseline, load_baseline,
)
from sinks.webhook import AlertSink


DEFAULT_NOMINAL_HZ = 433_920_000.0

# Narrow span, fine bins. A wide sweep crawls, and a bursty signal can slip
# between passes; we also need fine bins to separate two nearby crystals.
DEFAULT_SPAN_HZ = 150_000.0
DEFAULT_BIN_HZ = 250.0
DEFAULT_INTEGRATION_S = 1.0

DEFAULT_BASELINE_SWEEPS = 12

# Alerts repeat every sweep while a rogue keeps transmitting. Hold off on
# re-alerting about the same frequency for this long.
ALERT_REPEAT_SUPPRESSION_S = 20.0
SAME_EMITTER_TOLERANCE_HZ = 3_000.0


def _band_edges(nominal_hz: float, span_hz: float) -> tuple[float, float]:
    half = span_hz / 2.0
    return nominal_hz - half, nominal_hz + half


def _describe(carrier: dict, nominal_hz: float) -> str:
    megahertz = carrier["freq_hz"] / 1e6
    return (f"{megahertz:.6f} MHz  {carrier['power_db']:+6.1f} dB  "
            f"{carrier['ppm']:+8.2f} ppm")


def run_baseline(args) -> int:
    """Record where the authorised radio actually transmits."""
    low_hz, high_hz = _band_edges(args.nominal, args.span)
    print(f"Baselining {args.sweeps} sweeps across "
          f"{low_hz/1e6:.4f}-{high_hz/1e6:.4f} MHz")
    print("Only the AUTHORISED radio should be transmitting right now.\n")

    sweeps = []
    for sweep in rf_live.stream_sweeps(low_hz, high_hz, args.bin_hz,
                                       args.integration, args.gain,
                                       args.device, max_sweeps=args.sweeps):
        sweeps.append(sweep)
        print(f"  sweep {len(sweeps)}/{args.sweeps}")

    emitters = carriers_from_sweeps(sweeps, label="authorised-radio")
    if not emitters:
        print("\nNo carrier found. Check that the radio is transmitting, that "
              "the antenna is attached, and that the band covers its frequency.")
        return 1

    save_baseline(args.baseline_file, emitters)
    print(f"\nBaselined {len(emitters)} emitter(s) -> {args.baseline_file}")
    for emitter in emitters:
        offset_ppm = (emitter.freq_hz - args.nominal) / args.nominal * 1e6
        print(f"  {emitter.freq_hz/1e6:.6f} MHz  ({offset_ppm:+.2f} ppm from nominal)")

    if len(emitters) > 1:
        print("\nWARNING: more than one carrier was baselined. If the second "
              "board was already transmitting, it has now been recorded as "
              "authorised. Power it off and baseline again.")
    return 0


def run_monitor(args) -> int:
    """Watch the band and alert on anything that is not the baselined radio."""
    if not os.path.exists(args.baseline_file):
        print(f"No baseline at {args.baseline_file}.\n"
              f"Run the baseline step first, with only the authorised radio on:\n"
              f"  python3 demo/rf_monitor.py baseline", file=sys.stderr)
        return 1

    known = load_baseline(args.baseline_file)
    print(f"Loaded {len(known)} baselined emitter(s):")
    for emitter in known:
        print(f"  {emitter.freq_hz/1e6:.6f} MHz  (+/-{emitter.tol_hz/1000:.1f} kHz)")

    sink = AlertSink(args.alert_url, source_name="pi-rf-monitor")
    if args.alert_url:
        print(f"Alerts -> {args.alert_url}")
    else:
        print("Alerts -> console only (pass --alert-url to post them)")

    low_hz, high_hz = _band_edges(args.nominal, args.span)
    print(f"Monitoring {low_hz/1e6:.4f}-{high_hz/1e6:.4f} MHz. Ctrl-C to stop.\n")

    last_alert_time: dict[float, float] = {}
    sweep_number = 0

    try:
        for sweep in rf_live.stream_sweeps(low_hz, high_hz, args.bin_hz,
                                           args.integration, args.gain,
                                           args.device):
            sweep_number += 1
            observation, findings = analyse_sweep(
                sweep,
                ts=time.time(),
                band_name=args.band_name,
                nominal_hz=args.nominal,
                known=known,
            )

            carriers = observation.fields["carriers"]
            unknown_count = observation.fields.get("n_unknown", 0)
            summary = f"sweep {sweep_number:>4}  carriers={len(carriers)}"
            if unknown_count:
                summary += f"  UNACCOUNTED={unknown_count}"
            print(summary)
            for carrier in carriers:
                print(f"      {_describe(carrier, args.nominal)}")

            for finding in findings:
                frequency = finding.detail["freq_hz"]

                # Suppress repeats about the same carrier so a continuously
                # transmitting rogue does not flood the dashboard.
                suppressed = False
                for seen_frequency, seen_time in list(last_alert_time.items()):
                    if abs(seen_frequency - frequency) <= SAME_EMITTER_TOLERANCE_HZ:
                        if time.time() - seen_time < ALERT_REPEAT_SUPPRESSION_S:
                            suppressed = True
                        else:
                            del last_alert_time[seen_frequency]
                        break

                if not suppressed:
                    sink.send(finding)
                    last_alert_time[frequency] = time.time()

    except KeyboardInterrupt:
        print(f"\nstopped after {sweep_number} sweeps; "
              f"{sink.sent_count} alert(s) delivered, {sink.failed_count} failed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["baseline", "monitor"])
    parser.add_argument("--baseline-file", default="demo/baseline.json")
    parser.add_argument("--alert-url", default=None)
    parser.add_argument("--nominal", type=float, default=DEFAULT_NOMINAL_HZ)
    parser.add_argument("--span", type=float, default=DEFAULT_SPAN_HZ)
    parser.add_argument("--bin-hz", type=float, default=DEFAULT_BIN_HZ)
    parser.add_argument("--integration", type=float, default=DEFAULT_INTEGRATION_S)
    parser.add_argument("--gain", default=rf_live.DEFAULT_GAIN_DB)
    parser.add_argument("--device", type=int, default=0)
    parser.add_argument("--sweeps", type=int, default=DEFAULT_BASELINE_SWEEPS)
    parser.add_argument("--band-name", default="ISM-433")
    args = parser.parse_args()

    try:
        if args.mode == "baseline":
            return run_baseline(args)
        return run_monitor(args)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

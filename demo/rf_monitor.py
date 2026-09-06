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
    DEFAULT_MATCH_TOLERANCE_HZ, analyse_sweep, carriers_from_sweeps,
    save_baseline, load_baseline,
)
from correlate.inventory import Inventory, enrich, rank
from sinks.webhook import AlertSink, frequency_identity


DEFAULT_NOMINAL_HZ = 433_920_000.0

# Narrow span, fine bins. A wide sweep crawls, and a bursty signal can slip
# between passes; we also need fine bins to separate two nearby crystals.
DEFAULT_SPAN_HZ = 150_000.0
DEFAULT_BIN_HZ = 250.0
DEFAULT_INTEGRATION_S = 1.0

DEFAULT_BASELINE_SWEEPS = 12

# A rogue transmitting continuously appears on every sweep. Report it once,
# then hold off, or it buries everything else on the dashboard.
ALERT_REPEAT_SUPPRESSION_S = 20.0

# Two measurements of one carrier land a little apart every sweep, so alerts
# are grouped into buckets this wide before deciding they are "the same".
SAME_EMITTER_TOLERANCE_HZ = 3_000.0


def _sweep_source(args, max_sweeps=None):
    """Sweeps from the radio, or from a recording when --replay is given.

    The fallback exists because a live demo with no fallback is a demo that can
    fail in front of an audience. Detection and alerting are identical either
    way -- only where the sweeps come from changes.
    """
    if args.replay:
        source = rf_live.replay_sweeps(args.replay, loop=max_sweeps is None)
        if max_sweeps is None:
            return source

        def limited():
            """Stop the looping replay after the requested number of sweeps."""
            for index, sweep in enumerate(source):
                if index >= max_sweeps:
                    return
                yield sweep
        return limited()

    low_hz, high_hz = _band_edges(args.nominal, args.span)
    return rf_live.stream_sweeps(low_hz, high_hz, args.bin_hz, args.integration,
                                 args.gain, args.device, max_sweeps=max_sweeps)


def _replay_pace(args) -> None:
    """Slow a replay to roughly the rate a real sweep would arrive."""
    if args.replay:
        time.sleep(args.integration)


def _band_edges(nominal_hz: float, span_hz: float) -> tuple[float, float]:
    """Low and high edges of the span to sweep, centred on nominal."""
    half = span_hz / 2.0
    return nominal_hz - half, nominal_hz + half


def _describe(carrier: dict, nominal_hz: float) -> str:
    """One carrier as a console line: frequency, power, and crystal error."""
    megahertz = carrier["freq_hz"] / 1e6
    return (f"{megahertz:.6f} MHz  {carrier['power_db']:+6.1f} dB  "
            f"{carrier['ppm']:+8.2f} ppm")


def run_baseline(args) -> int:
    """Record where the authorised radio actually transmits."""
    if args.replay:
        print(f"Baselining {args.sweeps} sweeps from {args.replay} (REPLAY MODE)\n")
    else:
        low_hz, high_hz = _band_edges(args.nominal, args.span)
        print(f"Baselining {args.sweeps} sweeps across "
              f"{low_hz/1e6:.4f}-{high_hz/1e6:.4f} MHz")
        print("Only the AUTHORISED radio should be transmitting right now.\n")

    sweeps = []
    for sweep in _sweep_source(args, max_sweeps=args.sweeps):
        sweeps.append(sweep)
        print(f"  sweep {len(sweeps)}/{args.sweeps}")

    emitters = carriers_from_sweeps(sweeps, tol_hz=args.tolerance_hz,
                                    label="authorised-radio")
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

    # A tolerance wider than the gap between two transmitters silently swallows
    # the second one: it matches the baseline and never raises an alert. That
    # failure is invisible -- the detector simply stays quiet -- so it is worth
    # saying out loud how far apart a second radio must be to be seen.
    print(f"\nMatch tolerance: +/-{args.tolerance_hz:.0f} Hz")
    print(f"  A second transmitter closer than {args.tolerance_hz:.0f} Hz to the "
          f"baselined one will be treated as the SAME radio and NOT flagged.")
    print(f"  Measure both alone first; if they are less than "
          f"{2 * args.tolerance_hz:.0f} Hz apart, lower --tolerance-hz.")
    return 0


def _print_sweep(sweep_number: int, observation, nominal_hz: float) -> None:
    """Show what this sweep saw, so the audience can follow along."""
    carriers = observation.fields["carriers"]
    unaccounted = observation.fields.get("n_unknown", 0)

    summary = f"sweep {sweep_number:>4}  carriers={len(carriers)}"
    if unaccounted:
        summary += f"  UNACCOUNTED={unaccounted}"
    print(summary)

    for carrier in carriers:
        print(f"      {_describe(carrier, nominal_hz)}")


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

    inventory = None
    if args.inventory and os.path.exists(args.inventory):
        inventory = Inventory.load(args.inventory)
        print(f"Inventory: {len(inventory.records)} device(s), "
              f"{inventory.total_mw():.3f} MW total")

    sink = AlertSink(args.alert_url, source_name="pi-rf-monitor",
                     suppress_repeats_for=ALERT_REPEAT_SUPPRESSION_S,
                     identity_of=frequency_identity(SAME_EMITTER_TOLERANCE_HZ))
    if args.alert_url:
        print(f"Alerts -> {args.alert_url}")
    else:
        print("Alerts -> console only (pass --alert-url to post them)")

    if args.replay:
        print("REPLAY MODE -- sweeps read from a recording, no radio in use.")
    else:
        low_hz, high_hz = _band_edges(args.nominal, args.span)
        print(f"Monitoring {low_hz/1e6:.4f}-{high_hz/1e6:.4f} MHz.")
    print("Ctrl-C to stop.\n")

    sweep_number = 0

    try:
        for sweep in _sweep_source(args):
            sweep_number += 1
            _replay_pace(args)
            observation, findings = analyse_sweep(
                sweep,
                ts=time.time(),
                band_name=args.band_name,
                nominal_hz=args.nominal,
                known=known,
            )

            _print_sweep(sweep_number, observation, args.nominal)

            if inventory is not None and findings:
                findings = rank(enrich(findings, inventory))

            sink.send_all(findings)

    except KeyboardInterrupt:
        print(f"\nstopped after {sweep_number} sweeps; "
              f"{sink.sent_count} alert(s) delivered, {sink.failed_count} failed, "
              f"{sink.suppressed_count} suppressed as repeats")
    return 0


def main() -> int:
    """Parse arguments and run the requested mode."""
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
    parser.add_argument("--replay", default=None,
                        help="read sweeps from a recorded CSV instead of the radio")
    parser.add_argument("--inventory", default="demo/inventory.json",
                        help="Layer 1 join: weights alerts by capacity at risk")
    parser.add_argument("--tolerance-hz", type=float, default=DEFAULT_MATCH_TOLERANCE_HZ,
                        help="how far a carrier may sit from a baselined one and "
                             "still count as the same radio; MUST be well under "
                             "half the gap between your transmitters")
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

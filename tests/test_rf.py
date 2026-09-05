"""Carrier-detection tests.  Run: python3 -m tests.test_rf"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sim.rf_synth import Emitter, write_csv
from collectors.rf import run_file

NOM = 433_920_000.0
OK = []


def check(name, cond):
    OK.append((name, bool(cond)))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


def carriers(path, **kw):
    obs, _ = run_file(path, "ISM-433", expected_emitters=1, nominal_hz=NOM)
    return [o.fields["n_carriers"] for o in obs]


def main():
    os.makedirs("runs/t", exist_ok=True)
    print("RF carrier detection")

    write_csv("runs/t/one.csv", NOM, [Emitter(0.0, -25, 3000)], sweeps=5, seed=3)
    check("single emitter -> 1 carrier", all(c == 1 for c in carriers("runs/t/one.csv")))

    write_csv("runs/t/two.csv", NOM,
              [Emitter(-12.0, -25, 3000), Emitter(14.0, -27, 3000)], sweeps=5, seed=3)
    check("two emitters 26 ppm apart -> 2 carriers", all(c == 2 for c in carriers("runs/t/two.csv")))

    _, finds = run_file("runs/t/two.csv", "ISM-433", expected_emitters=1, nominal_hz=NOM)
    check("excess emitter raises a finding", len(finds) > 0)
    check("finding kind is excess_emitter", finds and finds[0].kind == "excess_emitter")

    write_csv("runs/t/noise.csv", NOM, [], sweeps=5, seed=3)
    check("noise only -> 0 carriers", all(c == 0 for c in carriers("runs/t/noise.csv")))

    # Known limit: separation below ~1.3x the carrier's own bandwidth is
    # unresolvable at any bin width.  Asserted so a regression is visible.
    write_csv("runs/t/close.csv", NOM,
              [Emitter(0.0, -25, 3000), Emitter(3.0, -27, 3000)], bin_hz=250.0, sweeps=3, seed=3)
    check("3 ppm (1.3 kHz) unresolvable vs 3 kHz-wide carriers (known limit)",
          all(c == 1 for c in carriers("runs/t/close.csv")))

    test_identification()

    failed = [n for n, ok in OK if not ok]
    print(f"\n{len(OK) - len(failed)}/{len(OK)} passed")
    return 1 if failed else 0




def test_identification():
    """Baselined-emitter identification, incl. the case counting cannot see."""
    from collectors.rf import KnownEmitter
    print("\nKnown-emitter identification")
    write_csv("runs/t/base.csv", NOM, [Emitter(-8.8, -25, 3000)], sweeps=6, seed=21)
    known = KnownEmitter.from_baseline("runs/t/base.csv")
    check("baseline learns exactly one reference", len(known) == 1)

    write_csv("runs/t/solo.csv", NOM, [Emitter(-8.6, -24, 3000)], sweeps=6, seed=99)
    _, f = run_file("runs/t/solo.csv", "ISM-433", nominal_hz=NOM, known=known)
    check("authorised emitter alone -> silent", len(f) == 0)

    write_csv("runs/t/rogue.csv", NOM,
              [Emitter(-8.7, -25, 3000), Emitter(13.4, -28, 3000)], sweeps=6, seed=99)
    _, f = run_file("runs/t/rogue.csv", "ISM-433", nominal_hz=NOM, known=known)
    check("authorised + rogue -> flagged", len(f) > 0)

    write_csv("runs/t/only.csv", NOM, [Emitter(13.4, -28, 3000)], sweeps=6, seed=99)
    _, f_id = run_file("runs/t/only.csv", "ISM-433", nominal_hz=NOM, known=known)
    _, f_ct = run_file("runs/t/only.csv", "ISM-433", expected_emitters=1, nominal_hz=NOM)
    check("rogue alone: identification flags it", len(f_id) > 0)
    check("rogue alone: counting is blind (documents the gap)", len(f_ct) == 0)


if __name__ == "__main__":
    raise SystemExit(main())

"""Score detector output against the sealed manifest.

Matching is by (kind, time) within a tolerance window.  A finding whose kind
does not appear in the manifest is a false positive; a manifest entry with no
matching finding is a miss.  Clean seeds (zero anomalies) contribute only to
the false-positive rate, which is the number an operator actually feels.
"""

from __future__ import annotations

import argparse
import json
import glob
import os


def score_one(truth_path: str, found_path: str, window: float = 30.0) -> dict:
    truth = json.load(open(truth_path))["anomalies"]
    found = [json.loads(l) for l in open(found_path) if l.strip()]

    unmatched = list(found)
    tp, missed = 0, []
    for t in truth:
        hit = None
        for f in unmatched:
            if f["kind"] != t["kind"]:
                continue
            ws = f.get("detail", {}).get("window_start")
            if ws is not None:
                # Interval-localised finding: the anomaly lies somewhere in
                # (window_start, ts].  Credit a hit anywhere in that span.
                if ws - window <= t["t"] <= f["ts"] + window:
                    hit = f
                    break
            elif abs(f["ts"] - t["t"]) <= window:
                hit = f
                break
        if hit is not None:
            unmatched.remove(hit)
            tp += 1
        else:
            missed.append(t)
    fp = len(unmatched)
    fn = len(missed)
    return {
        "seed": os.path.basename(truth_path).split(".")[0],
        "n_truth": len(truth), "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if (tp + fp) else (1.0 if not truth else 0.0),
        "recall": tp / (tp + fn) if (tp + fn) else 1.0,
        "clean_run": len(truth) == 0,
        "missed": missed,
        "false_positives": [{"kind": f["kind"], "ts": f["ts"]} for f in unmatched],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth-dir", default="truth")
    ap.add_argument("--found-dir", default="found")
    ap.add_argument("--window", type=float, default=30.0)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    rows = []
    for tp_path in sorted(glob.glob(os.path.join(a.truth_dir, "*.json"))):
        seed = os.path.basename(tp_path).split(".")[0]
        fp_path = os.path.join(a.found_dir, f"{seed}.jsonl")
        if not os.path.exists(fp_path):
            continue
        rows.append(score_one(tp_path, fp_path, a.window))

    if not rows:
        raise SystemExit("no scored runs -- generate scenarios and detect first")

    TP = sum(r["tp"] for r in rows); FP = sum(r["fp"] for r in rows); FN = sum(r["fn"] for r in rows)
    clean = [r for r in rows if r["clean_run"]]
    clean_fp = sum(r["fp"] for r in clean)

    print(f"{'seed':>8} {'truth':>6} {'tp':>4} {'fp':>4} {'fn':>4}  {'prec':>6} {'recall':>7}  note")
    print("-" * 62)
    for r in rows:
        note = "CLEAN" if r["clean_run"] else ""
        print(f"{r['seed']:>8} {r['n_truth']:>6} {r['tp']:>4} {r['fp']:>4} {r['fn']:>4} "
              f"{r['precision']:>6.2f} {r['recall']:>7.2f}  {note}")
        if a.verbose:
            for m in r["missed"]:
                print(f"           MISS  {m['kind']} @ t={m['t']:.0f}")
            for f in r["false_positives"]:
                print(f"           FP    {f['kind']} @ t={f['ts']:.0f}")
    print("-" * 62)
    prec = TP / (TP + FP) if (TP + FP) else 1.0
    rec = TP / (TP + FN) if (TP + FN) else 1.0
    print(f"{'TOTAL':>8} {sum(r['n_truth'] for r in rows):>6} {TP:>4} {FP:>4} {FN:>4} "
          f"{prec:>6.2f} {rec:>7.2f}")
    print(f"\nclean runs: {len(clean)}/{len(rows)}   false positives on clean runs: {clean_fp}")
    if clean_fp == 0 and clean:
        print("  -> no false positives on any clean run")


if __name__ == "__main__":
    main()

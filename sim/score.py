"""Score detector output against the sealed ground-truth manifest.

A finding counts as correct when it names the same anomaly KIND at roughly the
same TIME as a manifest entry. Anything left over on the detector's side is a
false positive; anything left over on the manifest's side is a miss.

Clean runs -- seeds where the generator injected nothing -- contribute only to
the false-positive count. That number is the one an operator actually feels,
and a detector never tested against clean input has never measured it.
"""

from __future__ import annotations

import argparse
import glob
import json
import os


# How far apart a finding and a manifest entry may be and still be the same
# event. Generous, because a detector localises an anomaly rather than
# timestamping it exactly.
DEFAULT_MATCH_WINDOW_S = 30.0

# Findings carrying this key describe an INTERVAL rather than an instant: a
# cadence anomaly lies somewhere between two sessions, and either could be the
# intruder. Matching then spans the whole interval.
INTERVAL_START_KEY = "window_start"


def _load_findings(path: str) -> list[dict]:
    """Read a JSON Lines findings file, skipping blank lines."""
    findings = []
    with open(path) as handle:
        for line in handle:
            if line.strip():
                findings.append(json.loads(line))
    return findings


def _matches(finding: dict, anomaly: dict, window: float) -> bool:
    """True when this finding plausibly describes this anomaly."""
    if finding["kind"] != anomaly["kind"]:
        return False

    anomaly_time = anomaly["t"]
    interval_start = finding.get("detail", {}).get(INTERVAL_START_KEY)

    if interval_start is not None:
        # Interval-localised: credit a hit anywhere across the span.
        return interval_start - window <= anomaly_time <= finding["ts"] + window

    return abs(finding["ts"] - anomaly_time) <= window


def score_one(truth_path: str, found_path: str,
              window: float = DEFAULT_MATCH_WINDOW_S) -> dict:
    """Compare one run's findings against its manifest."""
    with open(truth_path) as handle:
        anomalies = json.load(handle)["anomalies"]
    findings = _load_findings(found_path)

    unclaimed_findings = list(findings)
    true_positives = 0
    missed = []

    for anomaly in anomalies:
        matching_finding = None
        for finding in unclaimed_findings:
            if _matches(finding, anomaly, window):
                matching_finding = finding
                break

        if matching_finding is not None:
            unclaimed_findings.remove(matching_finding)
            true_positives += 1
        else:
            missed.append(anomaly)

    false_positives = len(unclaimed_findings)
    false_negatives = len(missed)

    # With nothing to find and nothing reported, the run is perfect; with
    # nothing found but anomalies present, precision is undefined and scored 0.
    if true_positives + false_positives > 0:
        precision = true_positives / (true_positives + false_positives)
    elif not anomalies:
        precision = 1.0
    else:
        precision = 0.0

    if true_positives + false_negatives > 0:
        recall = true_positives / (true_positives + false_negatives)
    else:
        recall = 1.0

    false_positive_summary = []
    for finding in unclaimed_findings:
        false_positive_summary.append({"kind": finding["kind"], "ts": finding["ts"]})

    return {
        "seed": os.path.basename(truth_path).split(".")[0],
        "n_truth": len(anomalies),
        "tp": true_positives,
        "fp": false_positives,
        "fn": false_negatives,
        "precision": precision,
        "recall": recall,
        "clean_run": len(anomalies) == 0,
        "missed": missed,
        "false_positives": false_positive_summary,
    }


def _collect_rows(truth_dir: str, found_dir: str, window: float) -> list[dict]:
    """Score every run that has both a manifest and a findings file."""
    rows = []
    for truth_path in sorted(glob.glob(os.path.join(truth_dir, "*.json"))):
        seed = os.path.basename(truth_path).split(".")[0]
        found_path = os.path.join(found_dir, f"{seed}.jsonl")
        if os.path.exists(found_path):
            rows.append(score_one(truth_path, found_path, window))
    return rows


def _print_report(rows: list[dict], verbose: bool) -> None:
    header = (f"{'seed':>8} {'truth':>6} {'tp':>4} {'fp':>4} {'fn':>4}  "
              f"{'prec':>6} {'recall':>7}  note")
    print(header)
    print("-" * 62)

    total_true_positives = 0
    total_false_positives = 0
    total_false_negatives = 0
    total_anomalies = 0
    clean_runs = 0
    false_positives_on_clean_runs = 0

    for row in rows:
        total_true_positives += row["tp"]
        total_false_positives += row["fp"]
        total_false_negatives += row["fn"]
        total_anomalies += row["n_truth"]
        if row["clean_run"]:
            clean_runs += 1
            false_positives_on_clean_runs += row["fp"]
            note = "CLEAN"
        else:
            note = ""

        print(f"{row['seed']:>8} {row['n_truth']:>6} {row['tp']:>4} {row['fp']:>4} "
              f"{row['fn']:>4} {row['precision']:>6.2f} {row['recall']:>7.2f}  {note}")

        if verbose:
            for anomaly in row["missed"]:
                print(f"           MISS  {anomaly['kind']} @ t={anomaly['t']:.0f}")
            for finding in row["false_positives"]:
                print(f"           FP    {finding['kind']} @ t={finding['ts']:.0f}")

    print("-" * 62)

    if total_true_positives + total_false_positives > 0:
        precision = total_true_positives / (total_true_positives + total_false_positives)
    else:
        precision = 1.0
    if total_true_positives + total_false_negatives > 0:
        recall = total_true_positives / (total_true_positives + total_false_negatives)
    else:
        recall = 1.0

    print(f"{'TOTAL':>8} {total_anomalies:>6} {total_true_positives:>4} "
          f"{total_false_positives:>4} {total_false_negatives:>4} "
          f"{precision:>6.2f} {recall:>7.2f}")
    print(f"\nclean runs: {clean_runs}/{len(rows)}   "
          f"false positives on clean runs: {false_positives_on_clean_runs}")
    if clean_runs > 0 and false_positives_on_clean_runs == 0:
        print("  -> no false positives on any clean run")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth-dir", default="truth")
    parser.add_argument("--found-dir", default="found")
    parser.add_argument("--window", type=float, default=DEFAULT_MATCH_WINDOW_S)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    rows = _collect_rows(args.truth_dir, args.found_dir, args.window)
    if not rows:
        raise SystemExit("no scored runs -- generate scenarios and detect first")

    _print_report(rows, args.verbose)


if __name__ == "__main__":
    main()

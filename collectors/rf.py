"""RF egress detection (Grid Lockout Layer 3).

Reads rtl_power CSV sweeps and counts distinct RF carriers in a band.  The
detection this exists to serve: an enclosure documented to contain ONE radio
that shows TWO independent carriers contains an undocumented transmitter.

Two independent oscillators never land on exactly the same frequency.  Crystal
manufacturing tolerance is +/-10..50 ppm, so two nominally-identical emitters
sit tens of kHz apart -- resolvable given a fine enough bin width.  That
frequency gap IS the signature; see estimate_ppm().

Input format (rtl_power):
    date, time, Hz_low, Hz_high, Hz_step, n_samples, dB, dB, dB, ...
Rows sharing a timestamp form one sweep.
"""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass

from core.events import Observation, Finding


@dataclass
class KnownEmitter:
    """A carrier we have baselined and therefore expect to see.

    Baselining one emitter alone converts this from a COUNTING problem into an
    IDENTIFICATION problem, which is strictly stronger: counting only notices
    that a band is too crowded, whereas identification names which carrier is
    unaccounted for -- and still works if the authorised emitter is silent, has
    drifted with temperature, or if both emitters transmit at once.
    """

    freq_hz: float
    tol_hz: float = 2_000.0
    label: str = "baselined"

    @classmethod
    def from_baseline(cls, csv_path: str, label: str = "baselined",
                      tol_hz: float = 2_000.0) -> list["KnownEmitter"]:
        """Learn expected carriers from a capture of the authorised emitter alone."""
        sweeps = parse_rtl_power(csv_path)
        seen: list[list[float]] = []
        for sweep in sweeps:
            for c in find_carriers(sweep):
                for grp in seen:
                    if abs(grp[0] - c.freq_hz) <= tol_hz:
                        grp.append(c.freq_hz)
                        break
                else:
                    seen.append([c.freq_hz])
        return [cls(freq_hz=sum(g) / len(g), tol_hz=tol_hz, label=label) for g in seen]


@dataclass
class Carrier:
    """One detected emitter."""

    freq_hz: float      # power-weighted centroid, not just the peak bin
    power_db: float     # peak power
    width_hz: float     # -3 dB-ish width from the bins above threshold
    n_bins: int

    def ppm_from(self, nominal_hz: float) -> float:
        return (self.freq_hz - nominal_hz) / nominal_hz * 1e6


def _median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if not n:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def parse_rtl_power(path: str) -> list[list[tuple[float, float]]]:
    """Return a list of sweeps; each sweep is [(freq_hz, power_db), ...]."""
    sweeps: dict[str, list[tuple[float, float]]] = {}
    order: list[str] = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 7:
                continue
            try:
                stamp = f"{row[0].strip()} {row[1].strip()}"
                lo = float(row[2])
                step = float(row[4])
                powers = [float(c) for c in row[6:] if c.strip() != ""]
            except ValueError:
                continue  # header or malformed line
            if stamp not in sweeps:
                sweeps[stamp] = []
                order.append(stamp)
            for i, p in enumerate(powers):
                sweeps[stamp].append((lo + i * step, p))
    return [sorted(sweeps[s]) for s in order]


def _smooth(vals: list[float], k: int = 3) -> list[float]:
    """Moving average -- keeps bin noise from minting spurious local maxima."""
    if k <= 1 or len(vals) < k:
        return list(vals)
    half = k // 2
    out = []
    for i in range(len(vals)):
        lo = max(0, i - half)
        hi = min(len(vals), i + half + 1)
        out.append(sum(vals[lo:hi]) / (hi - lo))
    return out


def _prominence(powers: list[float], idx: int) -> float:
    """Height of a peak above the highest saddle joining it to a taller peak.

    This is what separates two carriers whose skirts overlap: both sit above
    the noise threshold continuously, but the dip between them is real.
    """
    n = len(powers)
    peak = powers[idx]

    left_min = peak
    i = idx - 1
    while i >= 0 and powers[i] <= peak:
        left_min = min(left_min, powers[i])
        i -= 1
    if i < 0:
        left_min = min(left_min, powers[0])

    right_min = peak
    j = idx + 1
    while j < n and powers[j] <= peak:
        right_min = min(right_min, powers[j])
        j += 1
    if j >= n:
        right_min = min(right_min, powers[-1])

    return peak - max(left_min, right_min)


def find_carriers(
    bins: list[tuple[float, float]],
    snr_db: float = 10.0,
    min_prominence_db: float = 3.0,
    smooth_bins: int = 3,
) -> list[Carrier]:
    """Locate carriers as prominent local maxima above a robust noise floor.

    Threshold-crossing alone is not enough: two emitters ~1 FWHM apart form a
    single contiguous above-threshold run with a dip in the middle.  Requiring
    prominence recovers both.  The cost is that emitters closer than roughly
    one bin width remain unresolvable -- a genuine limit of the sweep, not of
    this code.  Narrow the bin width to resolve closer pairs.
    """
    if len(bins) < 5:
        return []
    freqs = [f for f, _ in bins]
    raw = [p for _, p in bins]
    step = freqs[1] - freqs[0] if len(freqs) > 1 else 1.0

    floor = _median(raw)
    mad = _median([abs(p - floor) for p in raw]) or 0.5
    threshold = floor + max(snr_db, 4.0 * mad)

    sm = _smooth(raw, smooth_bins)

    peaks: list[int] = []
    for i in range(1, len(sm) - 1):
        if sm[i] < threshold:
            continue
        if sm[i] >= sm[i - 1] and sm[i] > sm[i + 1]:
            if _prominence(sm, i) >= min_prominence_db:
                peaks.append(i)

    carriers: list[Carrier] = []
    for i in peaks:
        # Extent: walk out until below threshold or until the curve turns back up
        # (the saddle between this carrier and its neighbour).
        lo = i
        while lo > 0 and sm[lo - 1] < sm[lo] and sm[lo - 1] >= threshold:
            lo -= 1
        hi = i
        while hi < len(sm) - 1 and sm[hi + 1] < sm[hi] and sm[hi + 1] >= threshold:
            hi += 1

        num = den = 0.0
        for k in range(lo, hi + 1):
            lin = 10.0 ** (raw[k] / 10.0)
            num += freqs[k] * lin
            den += lin
        if den <= 0:
            continue
        carriers.append(
            Carrier(
                freq_hz=num / den,
                power_db=raw[i],
                width_hz=(hi - lo + 1) * step,
                n_bins=hi - lo + 1,
            )
        )

    carriers.sort(key=lambda c: c.freq_hz)
    return carriers


def estimate_ppm(carriers: list[Carrier], nominal_hz: float) -> list[float]:
    """Per-carrier offset from nominal, in ppm -- the crystal-tolerance view."""
    return [c.ppm_from(nominal_hz) for c in carriers]


def analyse_sweep(
    bins: list[tuple[float, float]],
    ts: float,
    band_name: str,
    expected_emitters: int = 1,
    nominal_hz: float | None = None,
    snr_db: float = 10.0,
    known: list["KnownEmitter"] | None = None,
) -> tuple[Observation, list[Finding]]:
    """One sweep -> one Observation, plus Findings for unaccounted carriers.

    With `known` supplied we report WHICH carrier is unexplained.  Without it we
    fall back to counting against `expected_emitters`.
    """
    carriers = find_carriers(bins, snr_db=snr_db)
    detail = {
        "carriers": [
            {
                "freq_hz": round(c.freq_hz, 1),
                "power_db": round(c.power_db, 2),
                "width_hz": round(c.width_hz, 1),
                "ppm": round(c.ppm_from(nominal_hz), 3) if nominal_hz else None,
            }
            for c in carriers
        ],
        "n_carriers": len(carriers),
        "expected": expected_emitters,
    }
    if len(carriers) >= 2:
        seps = [
            carriers[i + 1].freq_hz - carriers[i].freq_hz
            for i in range(len(carriers) - 1)
        ]
        detail["separations_hz"] = [round(s, 1) for s in seps]

    if known:
        unknown = []
        for c in carriers:
            match = min(known, key=lambda k: abs(k.freq_hz - c.freq_hz), default=None)
            if match is None or abs(match.freq_hz - c.freq_hz) > match.tol_hz:
                unknown.append(c)
        detail["n_unknown"] = len(unknown)
        detail["known_refs"] = [
            {"freq_hz": round(k.freq_hz, 1), "label": k.label} for k in known
        ]

    obs = Observation(ts=ts, source="rf", subject=band_name, fields=detail)

    findings: list[Finding] = []
    if known:
        for c in unknown:
            nearest = min((abs(k.freq_hz - c.freq_hz) for k in known), default=0.0)
            findings.append(Finding(
                ts=ts, source="rf", subject=band_name,
                kind="excess_emitter", severity="critical",
                detail={"freq_hz": round(c.freq_hz, 1),
                        "power_db": round(c.power_db, 2),
                        "ppm": round(c.ppm_from(nominal_hz), 3) if nominal_hz else None,
                        "offset_from_nearest_known_hz": round(nearest, 1),
                        "identified": False},
            ))
        return obs, findings

    if len(carriers) > expected_emitters:
        excess = len(carriers) - expected_emitters
        findings.append(
            Finding(
                ts=ts,
                source="rf",
                subject=band_name,
                kind="excess_emitter",
                # Layer 3 catches the one thing egress monitoring structurally
                # cannot, so an excess carrier is never a low-severity event.
                severity="critical" if excess > 1 else "high",
                detail=detail,
            )
        )
    return obs, findings


def run_file(
    path: str,
    band_name: str,
    expected_emitters: int = 1,
    nominal_hz: float | None = None,
    snr_db: float = 10.0,
    known: list["KnownEmitter"] | None = None,
) -> tuple[list[Observation], list[Finding]]:
    """Replay an rtl_power CSV through the detector."""
    obs_all: list[Observation] = []
    find_all: list[Finding] = []
    for i, sweep in enumerate(parse_rtl_power(path)):
        o, f = analyse_sweep(
            sweep,
            ts=float(i),
            band_name=band_name,
            expected_emitters=expected_emitters,
            nominal_hz=nominal_hz,
            snr_db=snr_db,
            known=known,
        )
        obs_all.append(o)
        find_all.extend(f)
    return obs_all, find_all

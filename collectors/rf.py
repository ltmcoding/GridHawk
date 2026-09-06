"""RF egress detection: find radio transmitters by looking at a spectrum sweep.

This is Grid Lockout Layer 3. It exists to catch the one thing network
monitoring structurally cannot: an undocumented radio inside the enclosure,
which never puts a single packet on the site network.

THE IDEA
--------
Every radio's frequency is set by a crystal, and crystals are manufactured to a
tolerance -- typically 10 to 50 parts per million. So a transmitter never sits
exactly on its nominal frequency:

    actual_frequency = nominal_frequency * (1 + ppm / 1_000_000)

Two radios therefore never land on the same frequency. At 433.92 MHz a 25 ppm
part is about 10.8 kHz off nominal, so two units can be ~21 kHz apart. That gap
is the signature: an enclosure documented to hold ONE radio that shows TWO
carriers holds an undocumented transmitter.

INPUT
-----
`rtl_power` CSV, one row per frequency segment:

    date, time, hz_low, hz_high, hz_step, samples, dB, dB, dB, ...

Rows sharing a timestamp together form one sweep across the band.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass

from core.events import Observation, Finding


# --------------------------------------------------------------------------
# Tunable thresholds
# --------------------------------------------------------------------------

# A carrier must rise this far above the noise floor to count.
DEFAULT_SNR_DB = 10.0

# How far a peak must stand above the dip separating it from a taller peak.
# This is what lets two overlapping carriers be counted as two.
DEFAULT_MIN_PROMINENCE_DB = 3.0

# Width of the moving average applied before peak-hunting, so that bin noise
# does not create imaginary peaks.
DEFAULT_SMOOTHING_BINS = 3

# The detection threshold sits at the noise floor plus whichever is larger:
# DEFAULT_SNR_DB, or this multiple of the noise's own spread.
NOISE_SPREAD_MULTIPLIER = 4.0

# Fallback spread when the noise is so flat the measured spread is zero.
MINIMUM_NOISE_SPREAD_DB = 0.5

# A sweep shorter than this cannot support peak detection.
MINIMUM_BINS_FOR_ANALYSIS = 5

# How far a measured carrier may sit from a baselined one and still be
# considered the same radio. Covers thermal drift of the authorised emitter.
DEFAULT_MATCH_TOLERANCE_HZ = 2_000.0

# rtl_power rows begin with six metadata columns before the power readings.
RTL_POWER_METADATA_COLUMNS = 6

PARTS_PER_MILLION = 1_000_000.0


# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------

@dataclass
class Carrier:
    """One transmitter found in a sweep."""

    freq_hz: float          # power-weighted centre, finer than the bin width
    power_db: float         # power at the peak bin
    width_hz: float         # how much of the band it occupies
    n_bins: int

    def ppm_from(self, nominal_hz: float) -> float:
        """How far off nominal this carrier sits, in parts per million."""
        offset = self.freq_hz - nominal_hz
        return offset / nominal_hz * PARTS_PER_MILLION


@dataclass
class KnownEmitter:
    """A carrier we have measured before and therefore expect to see.

    Baselining the authorised radio -- one capture taken while you know nothing
    else is transmitting -- turns a COUNTING problem into an IDENTIFICATION
    problem. Counting only notices that a band is too crowded. Identification
    names the carrier that is unaccounted for, and still works when the
    authorised radio is silent, has drifted with temperature, or is transmitting
    at the same moment as the intruder.
    """

    freq_hz: float
    tol_hz: float = DEFAULT_MATCH_TOLERANCE_HZ
    label: str = "baselined"

    @classmethod
    def from_baseline(cls, csv_path: str,
                      label: str = "baselined",
                      tol_hz: float = DEFAULT_MATCH_TOLERANCE_HZ) -> list["KnownEmitter"]:
        """Learn the expected carriers from a capture of the authorised radio alone.

        The same carrier appears once per sweep with slightly different measured
        centres, so nearby measurements are grouped and averaged.
        """
        sweeps = parse_rtl_power(csv_path)

        groups: list[list[float]] = []
        for sweep in sweeps:
            for carrier in find_carriers(sweep):
                joined_existing_group = False
                for group in groups:
                    if abs(group[0] - carrier.freq_hz) <= tol_hz:
                        group.append(carrier.freq_hz)
                        joined_existing_group = True
                        break
                if not joined_existing_group:
                    groups.append([carrier.freq_hz])

        emitters = []
        for group in groups:
            average_frequency = sum(group) / len(group)
            emitters.append(cls(freq_hz=average_frequency, tol_hz=tol_hz, label=label))
        return emitters


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _smooth(values: list[float], window: int = DEFAULT_SMOOTHING_BINS) -> list[float]:
    """Moving average, so single-bin noise does not look like a peak."""
    if window <= 1 or len(values) < window:
        return list(values)

    half_window = window // 2
    smoothed = []
    for index in range(len(values)):
        start = max(0, index - half_window)
        end = min(len(values), index + half_window + 1)
        neighbourhood = values[start:end]
        smoothed.append(sum(neighbourhood) / len(neighbourhood))
    return smoothed


def _prominence(powers: list[float], peak_index: int) -> float:
    """How far a peak stands above the dip joining it to any taller peak.

    This is the measurement that separates two carriers whose skirts overlap.
    Both may sit above the noise threshold continuously, forming one unbroken
    run of loud bins -- but the dip between them is real, and prominence sees
    it. Threshold crossing alone would report a single carrier at a frequency
    where nothing is actually transmitting.
    """
    peak_power = powers[peak_index]

    # Walk left until the signal rises above this peak, tracking the lowest
    # point along the way. That low point is the saddle on this side.
    lowest_on_left = peak_power
    index = peak_index - 1
    while index >= 0 and powers[index] <= peak_power:
        if powers[index] < lowest_on_left:
            lowest_on_left = powers[index]
        index -= 1
    if index < 0 and powers[0] < lowest_on_left:
        lowest_on_left = powers[0]

    lowest_on_right = peak_power
    index = peak_index + 1
    while index < len(powers) and powers[index] <= peak_power:
        if powers[index] < lowest_on_right:
            lowest_on_right = powers[index]
        index += 1
    if index >= len(powers) and powers[-1] < lowest_on_right:
        lowest_on_right = powers[-1]

    # The higher of the two saddles is the one that matters.
    higher_saddle = max(lowest_on_left, lowest_on_right)
    return peak_power - higher_saddle


# --------------------------------------------------------------------------
# Reading sweeps
# --------------------------------------------------------------------------

def parse_rtl_power(path: str) -> list[list[tuple[float, float]]]:
    """Read an rtl_power CSV into sweeps of (frequency_hz, power_db) pairs."""
    sweeps_by_timestamp: dict[str, list[tuple[float, float]]] = {}
    timestamp_order: list[str] = []

    with open(path, newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < RTL_POWER_METADATA_COLUMNS + 1:
                continue

            try:
                timestamp = f"{row[0].strip()} {row[1].strip()}"
                frequency_low = float(row[2])
                frequency_step = float(row[4])

                powers = []
                for cell in row[RTL_POWER_METADATA_COLUMNS:]:
                    if cell.strip() != "":
                        powers.append(float(cell))
            except ValueError:
                continue        # header line or malformed row

            if timestamp not in sweeps_by_timestamp:
                sweeps_by_timestamp[timestamp] = []
                timestamp_order.append(timestamp)

            for offset, power in enumerate(powers):
                frequency = frequency_low + offset * frequency_step
                sweeps_by_timestamp[timestamp].append((frequency, power))

    sweeps = []
    for timestamp in timestamp_order:
        sweeps.append(sorted(sweeps_by_timestamp[timestamp]))
    return sweeps


# --------------------------------------------------------------------------
# Finding carriers
# --------------------------------------------------------------------------

def _detection_threshold(powers: list[float], snr_db: float) -> float:
    """Power level a bin must exceed to be considered part of a carrier.

    The noise floor is a MEDIAN, not an average. The carriers are precisely the
    outliers we are hunting, and an average would let them lift the very floor
    that is supposed to reveal them.
    """
    noise_floor = _median(powers)

    deviations = []
    for power in powers:
        deviations.append(abs(power - noise_floor))
    noise_spread = _median(deviations)
    if noise_spread == 0:
        noise_spread = MINIMUM_NOISE_SPREAD_DB

    margin = max(snr_db, NOISE_SPREAD_MULTIPLIER * noise_spread)
    return noise_floor + margin


def _carrier_extent(smoothed: list[float], peak_index: int, threshold: float) -> tuple[int, int]:
    """Bin range belonging to one carrier: walk downhill from its peak."""
    low_index = peak_index
    while low_index > 0:
        previous = smoothed[low_index - 1]
        if previous >= smoothed[low_index] or previous < threshold:
            break               # started climbing again, or fell into noise
        low_index -= 1

    high_index = peak_index
    while high_index < len(smoothed) - 1:
        following = smoothed[high_index + 1]
        if following >= smoothed[high_index] or following < threshold:
            break
        high_index += 1

    return low_index, high_index


def _weighted_centre(frequencies, powers_db, low_index, high_index) -> float:
    """Centre of a carrier, weighted by power in LINEAR units.

    Averaging decibels would weight the quiet tails as heavily as the loud
    centre and pull the answer off the true frequency.
    """
    weighted_sum = 0.0
    total_weight = 0.0
    for index in range(low_index, high_index + 1):
        linear_power = 10.0 ** (powers_db[index] / 10.0)
        weighted_sum += frequencies[index] * linear_power
        total_weight += linear_power

    if total_weight <= 0:
        return frequencies[low_index]
    return weighted_sum / total_weight


def find_carriers(bins: list[tuple[float, float]],
                  snr_db: float = DEFAULT_SNR_DB,
                  min_prominence_db: float = DEFAULT_MIN_PROMINENCE_DB,
                  smooth_bins: int = DEFAULT_SMOOTHING_BINS) -> list[Carrier]:
    """Locate every transmitter in one sweep.

    Emitters closer together than roughly one bin width cannot be separated.
    That is a limit of the sweep itself, not of this code -- narrow the bin
    width to resolve closer pairs.
    """
    if len(bins) < MINIMUM_BINS_FOR_ANALYSIS:
        return []

    frequencies = []
    powers = []
    for frequency, power in bins:
        frequencies.append(frequency)
        powers.append(power)

    bin_width = frequencies[1] - frequencies[0]
    threshold = _detection_threshold(powers, snr_db)
    smoothed = _smooth(powers, smooth_bins)

    # A peak is a bin louder than both neighbours, above the threshold, and
    # standing clear of the dip separating it from any taller peak.
    peak_indices = []
    for index in range(1, len(smoothed) - 1):
        if smoothed[index] < threshold:
            continue
        rises_from_left = smoothed[index] >= smoothed[index - 1]
        falls_to_right = smoothed[index] > smoothed[index + 1]
        if not (rises_from_left and falls_to_right):
            continue
        if _prominence(smoothed, index) >= min_prominence_db:
            peak_indices.append(index)

    carriers = []
    for peak_index in peak_indices:
        low_index, high_index = _carrier_extent(smoothed, peak_index, threshold)
        centre = _weighted_centre(frequencies, powers, low_index, high_index)
        bin_count = high_index - low_index + 1
        carriers.append(Carrier(
            freq_hz=centre,
            power_db=powers[peak_index],
            width_hz=bin_count * bin_width,
            n_bins=bin_count,
        ))

    carriers.sort(key=_carrier_frequency)
    return carriers


def _carrier_frequency(carrier: Carrier) -> float:
    """Sort key for carriers."""
    return carrier.freq_hz


def estimate_ppm(carriers: list[Carrier], nominal_hz: float) -> list[float]:
    """Each carrier's offset from nominal -- the crystal-tolerance view."""
    offsets = []
    for carrier in carriers:
        offsets.append(carrier.ppm_from(nominal_hz))
    return offsets


# --------------------------------------------------------------------------
# Turning carriers into findings
# --------------------------------------------------------------------------

def _describe_carriers(carriers: list[Carrier], nominal_hz: float | None,
                       noise_floor_db: float | None = None) -> list[dict]:
    """Carrier list rendered for a Finding's detail field."""
    described = []
    for carrier in carriers:
        if nominal_hz is not None:
            ppm = round(carrier.ppm_from(nominal_hz), 3)
        else:
            ppm = None
        entry = {
            "freq_hz": round(carrier.freq_hz, 1),
            "power_db": round(carrier.power_db, 2),
            "width_hz": round(carrier.width_hz, 1),
            "ppm": ppm,
        }
        if noise_floor_db is not None:
            # How far this carrier stands above the noise is what the spectrum
            # strip uses for spike height, so a marginal signal looks marginal.
            entry["over_floor_db"] = round(carrier.power_db - noise_floor_db, 1)
        described.append(entry)
    return described


def _unaccounted_carriers(carriers: list[Carrier],
                          known: list[KnownEmitter]) -> list[Carrier]:
    """Carriers that do not match any baselined emitter."""
    unaccounted = []
    for carrier in carriers:
        matched = False
        for emitter in known:
            if abs(emitter.freq_hz - carrier.freq_hz) <= emitter.tol_hz:
                matched = True
                break
        if not matched:
            unaccounted.append(carrier)
    return unaccounted


def _distance_to_nearest_known(carrier: Carrier, known: list[KnownEmitter]) -> float:
    """How far this carrier sits from the closest baselined emitter."""
    if not known:
        return 0.0
    distances = []
    for emitter in known:
        distances.append(abs(emitter.freq_hz - carrier.freq_hz))
    return min(distances)


def _sweep_detail(carriers: list[Carrier], expected_emitters: int,
                  nominal_hz: float | None,
                  noise_floor_db: float | None = None) -> dict:
    """The description of a sweep shared by every outcome."""
    detail = {
        "carriers": _describe_carriers(carriers, nominal_hz, noise_floor_db),
        "n_carriers": len(carriers),
        "expected": expected_emitters,
    }

    if len(carriers) >= 2:
        separations = []
        for index in range(len(carriers) - 1):
            gap = carriers[index + 1].freq_hz - carriers[index].freq_hz
            separations.append(round(gap, 1))
        detail["separations_hz"] = separations

    return detail


def _findings_by_identification(carriers: list[Carrier],
                                known: list[KnownEmitter],
                                ts: float,
                                band_name: str,
                                nominal_hz: float | None,
                                detail: dict) -> list[Finding]:
    """Report carriers that match no baselined emitter.

    Stronger than counting, because it still fires when the authorised radio is
    silent and only the intruder is transmitting -- the total is one, which
    counting would accept.
    """
    unaccounted = _unaccounted_carriers(carriers, known)
    detail["n_unknown"] = len(unaccounted)

    known_references = []
    for emitter in known:
        known_references.append({
            "freq_hz": round(emitter.freq_hz, 1),
            "label": emitter.label,
        })
    detail["known_refs"] = known_references

    findings = []
    for carrier in unaccounted:
        if nominal_hz is not None:
            ppm = round(carrier.ppm_from(nominal_hz), 3)
        else:
            ppm = None
        findings.append(Finding(
            ts=ts,
            source="rf",
            subject=band_name,
            kind="excess_emitter",
            severity="critical",
            detail={
                "freq_hz": round(carrier.freq_hz, 1),
                "power_db": round(carrier.power_db, 2),
                "ppm": ppm,
                "offset_from_nearest_known_hz": round(
                    _distance_to_nearest_known(carrier, known), 1),
                "identified": False,
            },
        ))
    return findings


def _findings_by_counting(carriers: list[Carrier], expected_emitters: int,
                          ts: float, band_name: str, detail: dict) -> list[Finding]:
    """Report that the band holds more carriers than it should.

    Weaker than identification: it knows how many radios belong here, but not
    which ones.
    """
    if len(carriers) <= expected_emitters:
        return []

    # Layer 3 catches what network monitoring structurally cannot, so an
    # unexplained carrier is never a low-severity event.
    excess_count = len(carriers) - expected_emitters
    if excess_count > 1:
        severity = "critical"
    else:
        severity = "high"

    return [Finding(
        ts=ts,
        source="rf",
        subject=band_name,
        kind="excess_emitter",
        severity=severity,
        detail=detail,
    )]


def analyse_sweep(bins: list[tuple[float, float]],
                  ts: float,
                  band_name: str,
                  expected_emitters: int = 1,
                  nominal_hz: float | None = None,
                  snr_db: float = DEFAULT_SNR_DB,
                  known: list[KnownEmitter] | None = None) -> tuple[Observation, list[Finding]]:
    """Analyse one sweep into an Observation plus any Findings.

    Supplying `known` selects identification; otherwise we fall back to counting.
    """
    carriers = find_carriers(bins, snr_db=snr_db)
    noise_floor_db = _median([power for _frequency, power in bins])
    detail = _sweep_detail(carriers, expected_emitters, nominal_hz, noise_floor_db)
    detail["noise_floor_db"] = round(noise_floor_db, 1)

    if known:
        findings = _findings_by_identification(
            carriers, known, ts, band_name, nominal_hz, detail)
    else:
        findings = _findings_by_counting(
            carriers, expected_emitters, ts, band_name, detail)

    observation = Observation(ts=ts, source="rf", subject=band_name, fields=detail)
    return observation, findings


def run_file(path: str,
             band_name: str,
             expected_emitters: int = 1,
             nominal_hz: float | None = None,
             snr_db: float = DEFAULT_SNR_DB,
             known: list[KnownEmitter] | None = None) -> tuple[list[Observation], list[Finding]]:
    """Replay a whole rtl_power CSV through the detector."""
    all_observations = []
    all_findings = []

    for sweep_index, sweep in enumerate(parse_rtl_power(path)):
        observation, findings = analyse_sweep(
            sweep,
            ts=float(sweep_index),
            band_name=band_name,
            expected_emitters=expected_emitters,
            nominal_hz=nominal_hz,
            snr_db=snr_db,
            known=known,
        )
        all_observations.append(observation)
        all_findings.extend(findings)

    return all_observations, all_findings


# --------------------------------------------------------------------------
# Saving and reloading a baseline
# --------------------------------------------------------------------------

def save_baseline(path: str, emitters: list[KnownEmitter]) -> None:
    """Write baselined emitters to disk so a later run can compare against them."""
    records = []
    for emitter in emitters:
        records.append({
            "freq_hz": emitter.freq_hz,
            "tol_hz": emitter.tol_hz,
            "label": emitter.label,
        })
    with open(path, "w") as handle:
        json.dump({"emitters": records}, handle, indent=1)


def load_baseline(path: str) -> list[KnownEmitter]:
    """Read emitters previously written by save_baseline."""
    with open(path) as handle:
        records = json.load(handle)["emitters"]

    emitters = []
    for record in records:
        emitters.append(KnownEmitter(
            freq_hz=record["freq_hz"],
            tol_hz=record["tol_hz"],
            label=record["label"],
        ))
    return emitters


def carriers_from_sweeps(sweeps, tol_hz: float = DEFAULT_MATCH_TOLERANCE_HZ,
                         label: str = "baselined") -> list[KnownEmitter]:
    """Learn emitters from sweeps already in memory (the live-capture path).

    Same clustering as KnownEmitter.from_baseline, which reads from a file.
    """
    groups: list[list[float]] = []
    for sweep in sweeps:
        for carrier in find_carriers(sweep):
            joined_existing_group = False
            for group in groups:
                if abs(group[0] - carrier.freq_hz) <= tol_hz:
                    group.append(carrier.freq_hz)
                    joined_existing_group = True
                    break
            if not joined_existing_group:
                groups.append([carrier.freq_hz])

    emitters = []
    for group in groups:
        emitters.append(KnownEmitter(
            freq_hz=sum(group) / len(group), tol_hz=tol_hz, label=label))
    return emitters

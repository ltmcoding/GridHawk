"""Detection rules that turn a stream of Observations into Findings.

Each rule is a small function that answers one question about one session, so
you can read them in isolation. `evaluate()` is only the wiring that runs them
in order.

Two ideas run through the whole file:

1. Baselines are LEARNED from the observations, never hardcoded. If the device
   profile changes, the thresholds follow it instead of silently going stale.

2. Every rule documents what it CANNOT see. The blind spots are the reason the
   layered design exists, so they are recorded next to the code that has them.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from core.events import Observation, Finding


# --------------------------------------------------------------------------
# Tunable thresholds.  All of them live here so a reviewer can see every knob
# in one place instead of hunting for numbers buried in the logic.
# --------------------------------------------------------------------------

# A session is a "volume spike" when it is this many times larger than the
# 95th-percentile session we have already seen.
VOLUME_SPIKE_FACTOR = 8.0

# The percentile used as the "normal large session" reference point.
VOLUME_PERCENTILE = 0.95

# A session is "off cycle" when the gap before it is shorter than this
# fraction of its channel's usual period.  Natural jitter never gets close to
# half a period; an injected session almost always does.
CADENCE_EARLY_FRACTION = 0.5

# Abstain guards for the cadence rule.  If a rule fires on more than
# CADENCE_MAX_FIRING_RATE of all gaps, it is mismodelling the channel rather
# than finding anomalies, so it declines to report anything for that channel.
# CADENCE_MIN_FIRINGS keeps small channels usable: without it, a channel with
# only ~20 gaps would abstain on a single genuine detection.
CADENCE_MAX_FIRING_RATE = 0.05
CADENCE_MIN_FIRINGS = 3

# A channel needs at least this many sessions before its period means anything.
MIN_SESSIONS_FOR_CADENCE = 6

# Channel splitting.  Two byte sizes belong to different channels when their
# log10 sizes differ by at least CHANNEL_MIN_LOG_GAP (0.25 is a factor of ~1.8).
CHANNEL_MIN_LOG_GAP = 0.25
CHANNEL_MAX_COUNT = 4

# Timestamps are rounded to this many decimals when matching a session against
# findings another rule already produced, so float noise cannot cause a miss.
TIMESTAMP_MATCH_DECIMALS = 3

# ASN names containing any of these are treated as tunnels rather than merely
# unknown networks.
TUNNEL_NAME_HINTS = ("VPN", "PROXY", "TOR", "TUNNEL")


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _median(values) -> float:
    """Median, with 0.0 for an empty input instead of an exception."""
    if not values:
        return 0.0
    return statistics.median(values)


def _observation_timestamp(observation: Observation) -> float:
    """Sort key.  A named function reads better here than a lambda."""
    return observation.ts


def _session_id(observation: Observation) -> tuple[float, str]:
    """Identity used to check whether another rule already owns this session."""
    return (round(observation.ts, TIMESTAMP_MATCH_DECIMALS), observation.subject)


def _is_in_maintenance_window(timestamp: float, windows) -> bool:
    """True when the timestamp falls inside any operator-declared window."""
    if not windows:
        return False
    for start, end in windows:
        if start <= timestamp <= end:
            return True
    return False


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

class Baseline:
    """The device's normal behaviour, learned from the observations themselves.

    A baseline learned from a window that contains an attack is a poisoned
    baseline. A real deployment needs a known-clean learning period.
    """

    def __init__(self) -> None:
        self.sessions_per_destination: dict[str, int] = defaultdict(int)
        self.session_sizes: list[int] = []
        self.gaps_between_sessions: list[float] = []
        self.size_median = 0.0
        self.size_percentile = 0.0
        self.gap_median = 0.0

    def learn(self, observations: list[Observation]) -> "Baseline":
        previous_timestamp = None

        for observation in observations:
            destination = observation.fields["dst"]
            self.sessions_per_destination[destination] += 1
            self.session_sizes.append(observation.fields["bytes"])

            if previous_timestamp is not None:
                self.gaps_between_sessions.append(observation.ts - previous_timestamp)
            previous_timestamp = observation.ts

        self.size_median = _median(self.session_sizes)
        self.gap_median = _median(self.gaps_between_sessions)

        if self.session_sizes:
            sorted_sizes = sorted(self.session_sizes)
            # Clamp so the index stays valid for very short inputs.
            index = int(VOLUME_PERCENTILE * len(sorted_sizes))
            if index > len(sorted_sizes) - 1:
                index = len(sorted_sizes) - 1
            self.size_percentile = sorted_sizes[index]

        return self


# --------------------------------------------------------------------------
# Channel splitting
#
# A device multiplexes several logical channels (heartbeat, telemetry,
# firmware) over one destination, each with its own period.  Measuring a single
# "period" across all of them is meaningless, so sessions are grouped by byte
# size first.  Sizes cluster by orders of magnitude, so the split happens in
# log10 space.
# --------------------------------------------------------------------------

def split_into_channels(session_sizes: list[int]) -> list[tuple[float, float]]:
    """Return channel boundaries as (low, high) pairs in log10(bytes) space.

    The boundaries are CONTIGUOUS on purpose.  An earlier version left holes
    between them, and every session landing in a hole was silently assigned to
    the last channel, where it polluted that channel's period with unrelated
    traffic.
    """
    distinct_log_sizes = set()
    for size in session_sizes:
        distinct_log_sizes.add(math.log10(max(size, 1)))
    log_sizes = sorted(distinct_log_sizes)

    if len(log_sizes) < 2:
        return [(-1e9, 1e9)]          # everything in one channel

    # Measure the gap between each pair of neighbouring sizes.
    gaps_with_position = []
    for position in range(len(log_sizes) - 1):
        gap = log_sizes[position + 1] - log_sizes[position]
        gaps_with_position.append((gap, position))
    gaps_with_position.sort(reverse=True)

    # Cut at the widest gaps, but only where the gap is genuinely wide.
    cut_positions = []
    for gap, position in gaps_with_position[: CHANNEL_MAX_COUNT - 1]:
        if gap >= CHANNEL_MIN_LOG_GAP:
            cut_positions.append(position)
    cut_positions.sort()

    boundaries = []
    low_edge = log_sizes[0] - 1e-9    # nudge so the smallest size is included
    for position in cut_positions:
        high_edge = (log_sizes[position] + log_sizes[position + 1]) / 2.0
        boundaries.append((low_edge, high_edge))
        low_edge = high_edge          # next channel starts where this one ended
    boundaries.append((low_edge, 1e9))

    return boundaries


def channel_of(session_bytes: int, boundaries: list[tuple[float, float]]) -> int:
    """Index of the channel a session belongs to."""
    log_size = math.log10(max(session_bytes, 1))
    for index, (low, high) in enumerate(boundaries):
        if low < log_size <= high:
            return index
    return len(boundaries) - 1


# --------------------------------------------------------------------------
# Per-session rules.  Each returns a Finding, or None when it has nothing
# to say about this session.
# --------------------------------------------------------------------------

def check_destination(observation: Observation, allowed_asns: set[int]) -> Finding | None:
    """Flag a session to a network outside the allowlist.

    Cannot see: an attack arriving through the vendor's OWN legitimate cloud.
    That traffic lands on an allowlisted ASN, so this rule is silent by
    construction -- which is exactly what Forescout demonstrated in SUN:DOWN.
    """
    asn = observation.fields["asn"]
    if asn in allowed_asns:
        return None

    asn_name = observation.fields["asn_name"]
    looks_like_a_tunnel = False
    for hint in TUNNEL_NAME_HINTS:
        if hint in asn_name.upper():
            looks_like_a_tunnel = True
            break

    if looks_like_a_tunnel:
        kind = "tunnel_indicator"
    else:
        kind = "new_asn"

    return Finding(
        ts=observation.ts,
        source="tls_egress",
        subject=observation.subject,
        kind=kind,
        severity="high",
        detail={
            "dst": observation.fields["dst"],
            "asn": asn,
            "asn_name": asn_name,
            "cc": observation.fields["cc"],
        },
    )


def check_country(observation: Observation, allowed_countries: set[str]) -> Finding | None:
    """Flag an allowlisted network announcing from an unexpected country.

    Cannot see: an adversary routing through the expected country.  IP
    geolocation is approximate and changes without notice, so expect this to be
    the noisiest rule in a real deployment.
    """
    country = observation.fields["cc"]
    if country in allowed_countries:
        return None

    return Finding(
        ts=observation.ts,
        source="tls_egress",
        subject=observation.subject,
        kind="geo_drift",
        severity="medium",
        detail={
            "dst": observation.fields["dst"],
            "asn": observation.fields["asn"],
            "cc": country,
            "expected": sorted(allowed_countries),
        },
    )


def check_volume(observation: Observation, baseline: Baseline,
                 spike_factor: float = VOLUME_SPIKE_FACTOR) -> Finding | None:
    """Flag a session far larger than normal -- the shape of a firmware pull.

    Cannot see: slow exfiltration spread across many normal-sized sessions.
    This rule keys on a single outlier, so anything staying inside the envelope
    is invisible to it.
    """
    if baseline.size_percentile <= 0:
        return None

    session_bytes = observation.fields["bytes"]
    if session_bytes <= spike_factor * baseline.size_percentile:
        return None

    return Finding(
        ts=observation.ts,
        source="tls_egress",
        subject=observation.subject,
        kind="volume_spike",
        severity="medium",
        detail={
            "bytes": session_bytes,
            "baseline_p95": baseline.size_percentile,
            "factor": round(session_bytes / max(baseline.size_percentile, 1), 1),
        },
    )


# --------------------------------------------------------------------------
# Cadence rule (operates on the whole stream, not one session)
# --------------------------------------------------------------------------

def _group_sessions_by_channel(observations: list[Observation]) -> dict[int, list[Observation]]:
    """Split the stream into channels by session size, newest grouping first."""
    all_sizes = []
    for observation in observations:
        all_sizes.append(observation.fields["bytes"])
    boundaries = split_into_channels(all_sizes)

    grouped: dict[int, list[Observation]] = defaultdict(list)
    for observation in observations:
        index = channel_of(observation.fields["bytes"], boundaries)
        grouped[index].append(observation)
    return grouped


def _consecutive_gaps(sessions: list[Observation]):
    """Pair each session with the one before it, and measure the gap between.

    Returned so that pairs[i] and gaps[i] always describe the same interval.
    An earlier version kept these in separately-indexed lists, which was easy
    to get wrong by one.
    """
    pairs = []
    gaps = []
    for position in range(1, len(sessions)):
        earlier = sessions[position - 1]
        later = sessions[position]
        pairs.append((earlier, later))
        gaps.append(later.ts - earlier.ts)
    return pairs, gaps


def _should_abstain(early_count: int, gap_count: int) -> bool:
    """True when the cadence rule is firing too often to be believed.

    Channel splitting by byte size is brittle. When a sparse channel bridges two
    dense ones the split vanishes, and unrelated traffic pools into a single
    channel whose "period" is meaningless. Unguarded, this produced 274 false
    positives on one 24-hour run.

    Measuring the SPREAD of the gaps does not catch it: a dominant channel keeps
    the spread small while a second channel injects hundreds of short gaps, so
    the mixture is bimodal rather than wide. What does catch it is the FIRING
    RATE -- a rule flagging a large share of all sessions is mismodelling the
    channel, not finding anomalies.

    Cost: genuine off-cycle bursts inside an unseparable channel are missed, and
    the abstention is currently silent. A production build should log it; a
    detector that quietly stops detecting is worse than one that fails loudly.
    """
    limit = CADENCE_MAX_FIRING_RATE * gap_count
    if limit < CADENCE_MIN_FIRINGS:
        limit = CADENCE_MIN_FIRINGS
    return early_count > limit


def _is_already_explained(earlier: Observation, later: Observation,
                          already_explained: set) -> bool:
    """True when a stronger rule already owns either end of this interval.

    One session, one finding: an injected session perturbs cadence as well as
    tripping whichever rule caught it, and reporting both would double-count.
    """
    if _session_id(later) in already_explained:
        return True
    if _session_id(earlier) in already_explained:
        return True
    return False


def _cadence_findings_for_channel(channel_index: int,
                                  sessions: list[Observation],
                                  already_explained: set,
                                  maintenance_windows,
                                  early_fraction: float) -> list[Finding]:
    """Off-cycle findings for one channel, or none if the channel is unreliable."""
    if len(sessions) < MIN_SESSIONS_FOR_CADENCE:
        return []

    sessions.sort(key=_observation_timestamp)
    pairs, gaps = _consecutive_gaps(sessions)

    usual_period = _median(gaps)
    if usual_period <= 0:
        return []

    early_positions = []
    for position, gap in enumerate(gaps):
        if gap < early_fraction * usual_period:
            early_positions.append(position)

    if _should_abstain(len(early_positions), len(gaps)):
        return []

    findings = []
    for position in early_positions:
        earlier, later = pairs[position]
        gap = gaps[position]

        if _is_already_explained(earlier, later, already_explained):
            continue

        # A scheduled firmware update legitimately explains odd timing.
        if _is_in_maintenance_window(later.ts, maintenance_windows):
            continue
        if _is_in_maintenance_window(earlier.ts, maintenance_windows):
            continue

        findings.append(Finding(
            ts=later.ts,
            source="tls_egress",
            subject=later.subject,
            kind="off_cycle_burst",
            severity="medium",
            detail={
                "interval": round(gap, 1),
                "channel_period": round(usual_period, 1),
                "ratio": round(gap / usual_period, 3),
                "window_start": round(earlier.ts, TIMESTAMP_MATCH_DECIMALS),
                "band": channel_index,
                "bytes": later.fields["bytes"],
            },
        ))
    return findings


def check_cadence(observations: list[Observation],
                  already_explained: set | None = None,
                  maintenance_windows=None,
                  early_fraction: float = CADENCE_EARLY_FRACTION) -> list[Finding]:
    """Flag sessions arriving early against their own channel's period.

    An injected session splits one normal interval into two shorter ones, so at
    least one gap ends up under half the period while natural jitter never does.

    The anomaly belongs to the INTERVAL, not to an instant -- either endpoint
    could be the intruder -- so each finding carries `window_start` and the
    scorer credits a match anywhere across that span.

    Cannot see: an extra session that happens to land on the cadence, or a
    compromise riding an existing legitimate connection.
    """
    if already_explained is None:
        already_explained = set()
    if len(observations) < MIN_SESSIONS_FOR_CADENCE:
        return []

    findings = []
    for channel_index, sessions in _group_sessions_by_channel(observations).items():
        findings.extend(_cadence_findings_for_channel(
            channel_index, sessions, already_explained,
            maintenance_windows, early_fraction,
        ))
    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def evaluate(observations: list[Observation],
             allowed_asns: set[int],
             allowed_countries: set[str],
             baseline: Baseline | None = None,
             volume_factor: float = VOLUME_SPIKE_FACTOR,
             maintenance_windows=None) -> list[Finding]:
    """Run every rule over the stream and return the findings, unranked.

    Maintenance windows suppress the TIMING and VOLUME rules only.  A scheduled
    firmware update explains when a session happens and how large it is; it
    never explains a NEW DESTINATION.  Suppressing the destination rules too
    would publish a predictable blind spot an adversary could simply wait for.
    """
    if baseline is None:
        baseline = Baseline().learn(observations)

    findings: list[Finding] = []

    for observation in observations:
        # Destination first: it is the strongest signal, and a session that
        # fails it needs no further explanation.
        destination_finding = check_destination(observation, allowed_asns)
        if destination_finding is not None:
            findings.append(destination_finding)
            continue

        country_finding = check_country(observation, allowed_countries)
        if country_finding is not None:
            findings.append(country_finding)
            continue

        if _is_in_maintenance_window(observation.ts, maintenance_windows):
            continue

        volume_finding = check_volume(observation, baseline, volume_factor)
        if volume_finding is not None:
            findings.append(volume_finding)

    # The cadence rule runs last so it can see which sessions the rules above
    # already explained, and skip them.
    already_explained = set()
    for finding in findings:
        already_explained.add((round(finding.ts, TIMESTAMP_MATCH_DECIMALS), finding.subject))

    cadence_findings = check_cadence(
        observations,
        already_explained=already_explained,
        maintenance_windows=maintenance_windows,
    )
    findings.extend(cadence_findings)

    return findings

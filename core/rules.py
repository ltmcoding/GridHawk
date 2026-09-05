"""Detection rules over the Observation stream.

Baselines are learned from the observations themselves rather than hardcoded,
so a rig whose profile constants change does not silently invalidate the
thresholds.  Every rule states what it cannot see.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from core.events import Observation, Finding

TUNNEL_HINTS = ("VPN", "PROXY", "TOR", "TUNNEL")


def _median(xs):
    return statistics.median(xs) if xs else 0.0



def _log_bands(volumes: list[int], min_gap: float = 0.25, max_bands: int = 4):
    """Split sessions into channels by byte magnitude.

    A device multiplexes several logical channels (heartbeat, telemetry,
    firmware) over one destination, each with its own period.  Pooling them
    gives a meaningless cadence, so we separate by size first -- splitting at
    the widest gaps in log10(bytes).
    """
    ls = sorted({math.log10(max(v, 1)) for v in volumes})
    if len(ls) < 2:
        return [(-1e9, 1e9)]
    gaps = sorted(((ls[i + 1] - ls[i], i) for i in range(len(ls) - 1)), reverse=True)
    cuts = sorted(i for g, i in gaps[: max_bands - 1] if g >= min_gap)
    # Bands MUST be contiguous: a gap between them silently dumps every
    # session that falls in the hole into the final band, where it pollutes
    # that band's cadence with unrelated traffic.
    edges, prev_hi = [], ls[0] - 1e-9
    for c in cuts:
        hi = (ls[c] + ls[c + 1]) / 2.0
        edges.append((prev_hi, hi))
        prev_hi = hi
    edges.append((prev_hi, 1e9))
    return edges


def _band_of(nbytes: int, edges) -> int:
    x = math.log10(max(nbytes, 1))
    for i, (lo, hi) in enumerate(edges):
        if lo < x <= hi:
            return i
    return len(edges) - 1


class Baseline:
    """Learned per-device envelope: destinations, cadence, volume."""

    def __init__(self) -> None:
        self.dst_seen: dict[str, int] = defaultdict(int)
        self.intervals: list[float] = []
        self.volumes: list[int] = []
        self.vol_median = 0.0
        self.vol_p95 = 0.0
        self.interval_median = 0.0

    def learn(self, obs: list[Observation]) -> "Baseline":
        last_t = None
        for o in obs:
            self.dst_seen[o.fields["dst"]] += 1
            self.volumes.append(o.fields["bytes"])
            if last_t is not None:
                self.intervals.append(o.ts - last_t)
            last_t = o.ts
        self.vol_median = _median(self.volumes)
        if self.volumes:
            s = sorted(self.volumes)
            self.vol_p95 = s[min(len(s) - 1, int(0.95 * len(s)))]
        self.interval_median = _median(self.intervals)
        return self


def _in_window(ts: float, windows) -> bool:
    return any(lo <= ts <= hi for lo, hi in (windows or ()))


def evaluate(
    obs: list[Observation],
    allowed_asns: set[int],
    allowed_countries: set[str],
    baseline: Baseline | None = None,
    volume_factor: float = 8.0,
    maintenance_windows: list[tuple[float, float]] | None = None,
) -> list[Finding]:
    """Run every rule over the stream.  Returns findings, unranked."""
    bl = baseline or Baseline().learn(obs)
    findings: list[Finding] = []

    for o in obs:
        f = o.fields
        dst, asn, cc, name = f["dst"], f["asn"], f["cc"], f["asn_name"]

        # --- destination allowlist -------------------------------------
        # Cannot see: a push arriving through the vendor's own legitimate
        # cloud, which is exactly what Forescout demonstrated.
        if asn not in allowed_asns:
            findings.append(Finding(
                ts=o.ts, source="tls_egress", subject=o.subject,
                kind="tunnel_indicator" if any(h in name.upper() for h in TUNNEL_HINTS)
                     else "new_asn",
                severity="high",
                detail={"dst": dst, "asn": asn, "asn_name": name, "cc": cc},
            ))
            continue      # one finding per session; ASN is the stronger signal

        # --- country drift on an allowed ASN ---------------------------
        if cc not in allowed_countries:
            findings.append(Finding(
                ts=o.ts, source="tls_egress", subject=o.subject,
                kind="geo_drift", severity="medium",
                detail={"dst": dst, "asn": asn, "cc": cc,
                        "expected": sorted(allowed_countries)},
            ))
            continue

        # --- volume anomaly consistent with an image pull ---------------
        # A scheduled firmware update explains TIMING and VOLUME.  It never
        # explains a NEW DESTINATION, so the ASN and geo rules above stay armed
        # inside maintenance windows -- otherwise the window becomes a
        # predictable blind spot an adversary can simply wait for.
        if _in_window(o.ts, maintenance_windows):
            continue
        if bl.vol_p95 > 0 and f["bytes"] > volume_factor * bl.vol_p95:
            findings.append(Finding(
                ts=o.ts, source="tls_egress", subject=o.subject,
                kind="volume_spike", severity="medium",
                detail={"bytes": f["bytes"], "baseline_p95": bl.vol_p95,
                        "factor": round(f["bytes"] / max(bl.vol_p95, 1), 1)},
            ))

    # One session, one finding.  An injected session also perturbs cadence,
    # but re-reporting it as a second anomaly is double-counting -- the
    # stronger rule already owns that session.  This is deduplication, not
    # threshold tuning: no constant changes.
    claimed = {(round(f.ts, 3), f.subject) for f in findings}
    findings.extend(_cadence_rule(obs, claimed=claimed,
                                  maintenance_windows=maintenance_windows))
    return findings


def _cadence_rule(obs: list[Observation], factor: float = 0.5,
                  claimed: set | None = None,
                  maintenance_windows: list[tuple[float, float]] | None = None) -> list[Finding]:
    """Off-cycle connections: a session arriving early against its channel's period.

    An injected session splits one nominal interval into two shorter ones, so
    at least one gap is under half the period -- while natural jitter never is.
    The anomaly is localised to the INTERVAL, not to an instant: either endpoint
    could be the intruder.  window_start carries that, and the scorer honours it.

    Cannot see: an extra session that happens to land on the cadence, or a
    compromise that rides an existing legitimate connection.
    """
    if len(obs) < 6:
        return []
    edges = _log_bands([o.fields["bytes"] for o in obs])
    by_band: dict[int, list[Observation]] = defaultdict(list)
    for o in obs:
        by_band[_band_of(o.fields["bytes"], edges)].append(o)

    out: list[Finding] = []
    for band, items in by_band.items():
        if len(items) < 6:
            continue
        items.sort(key=lambda o: o.ts)
        gaps = [items[i].ts - items[i - 1].ts for i in range(1, len(items))]
        med = _median(gaps)
        if med <= 0:
            continue
        # ABSTAIN GUARD.  Byte-magnitude banding is brittle: when a sparse
        # channel bridges two dense ones, the split vanishes and unrelated
        # traffic pools into one band whose "median period" is meaningless.
        # Dispersion does not catch this -- a dominant channel keeps the MAD
        # small while a second channel injects hundreds of short gaps, so the
        # mixture is bimodal rather than merely wide.  What does catch it is
        # the firing RATE: an anomaly rule that flags a large fraction of all
        # sessions is not detecting anomalies, it is mismodelling the channel.
        # Cost: real off-cycle bursts in an unseparable band are missed -- a
        # recall loss taken knowingly over an unusable alert stream.
        short = [i for i, g in enumerate(gaps, start=1) if g < factor * med]
        if len(short) > max(3, 0.05 * len(gaps)):
            continue

        claimed = claimed or set()
        for i in short:
            g = gaps[i - 1]
            # Skip if either endpoint of the interval is already explained.
            if ((round(items[i].ts, 3), items[i].subject) in claimed
                    or (round(items[i - 1].ts, 3), items[i - 1].subject) in claimed):
                continue
            if (_in_window(items[i].ts, maintenance_windows)
                    or _in_window(items[i - 1].ts, maintenance_windows)):
                continue
            if True:
                out.append(Finding(
                    ts=items[i].ts, source="tls_egress", subject=items[i].subject,
                    kind="off_cycle_burst", severity="medium",
                    detail={"interval": round(g, 1), "channel_period": round(med, 1),
                            "ratio": round(g / med, 3),
                            "window_start": round(items[i - 1].ts, 3),
                            "band": band, "bytes": items[i].fields["bytes"]},
                ))
    return out

"""Loading operator-declared maintenance windows.

A window says "the site owner scheduled a firmware update here," which lets the
timing and volume rules stand down. Two time bases exist and they are NOT
interchangeable:

  scenario time   seconds from the start of a simulated run (0, 300, 4500...)
  wall-clock time Unix epoch seconds (1757030400...)

Replayed scenarios use the first. Live capture stamps packets with the second.
Handing a scenario schedule to a live monitor places every window decades in the
past, so suppression silently never fires -- the worst kind of failure, because
nothing looks wrong. This module refuses that combination instead.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


# Any timestamp below this is far too small to be a real epoch time (it would be
# 1970). Values under it are therefore scenario-relative.
EPOCH_PLAUSIBILITY_THRESHOLD = 1_000_000_000.0    # 2001-09-09

ISO_KEY = "maintenance_windows_iso"
EPOCH_KEY = "maintenance_windows"


class ScheduleTimeBaseError(ValueError):
    """Raised when a schedule's time base does not match how it will be used."""


def _parse_iso(text: str) -> float:
    """Turn an ISO 8601 timestamp into epoch seconds.

    A trailing 'Z' is accepted; naive timestamps are read as UTC.
    """
    cleaned = text.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    moment = datetime.fromisoformat(cleaned)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def load_windows(path: str) -> list[tuple[float, float]]:
    """Read maintenance windows from JSON.

    Accepts either numeric windows under "maintenance_windows", or ISO 8601
    strings under "maintenance_windows_iso", which are converted to epoch time.
    """
    with open(path) as handle:
        document = json.load(handle)

    windows: list[tuple[float, float]] = []

    for start_text, end_text in document.get(ISO_KEY, []):
        windows.append((_parse_iso(start_text), _parse_iso(end_text)))

    for start, end in document.get(EPOCH_KEY, []):
        windows.append((float(start), float(end)))

    return windows


def looks_like_scenario_time(windows: list[tuple[float, float]]) -> bool:
    """True when these windows are measured from the start of a run, not the epoch."""
    for start, _end in windows:
        if start >= EPOCH_PLAUSIBILITY_THRESHOLD:
            return False
    return bool(windows)


def load_windows_for_live_capture(path: str) -> list[tuple[float, float]]:
    """Load windows and insist they are wall-clock times.

    Live capture stamps packets with epoch seconds, so a scenario-relative
    schedule would match nothing at all.
    """
    windows = load_windows(path)
    if looks_like_scenario_time(windows):
        raise ScheduleTimeBaseError(
            f"{path} holds scenario-relative times (measured from the start of a "
            f"simulated run), but live capture timestamps packets in Unix epoch "
            f"seconds. Every window would land decades in the past and suppress "
            f"nothing.\n\n"
            f"For live monitoring, write absolute times instead:\n"
            f'  {{"maintenance_windows_iso": '
            f'[["2026-09-06T02:00:00Z", "2026-09-06T03:00:00Z"]]}}'
        )
    return windows


def window_starting_now(duration_s: float) -> list[tuple[float, float]]:
    """A single window beginning now -- handy for demonstrating suppression live."""
    import time
    start = time.time()
    return [(start, start + duration_s)]

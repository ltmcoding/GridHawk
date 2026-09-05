"""Post findings to an HTTP endpoint.

An alert that only prints to a terminal on the Raspberry Pi is not an alert.
This is the piece that carries a finding off the device to wherever the
operator is actually looking.

Delivery is best-effort on purpose. A monitoring tool that crashes because its
alert endpoint is unreachable has turned a small problem into an outage, so
failures are reported and then swallowed.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from core.events import Finding


DEFAULT_TIMEOUT_S = 5.0
CONTENT_TYPE = "application/json"

# Zero means "report every finding". Any positive value holds off on repeating
# the same alert for that many seconds.
NO_SUPPRESSION = 0.0


def default_identity(finding: Finding) -> tuple:
    """What makes two findings "the same alert" for suppression purposes.

    Kind and subject alone. Callers with a finer notion pass their own.
    """
    return (finding.kind, finding.subject)


def destination_identity(finding: Finding) -> tuple:
    """Identity for network findings: the same device calling the same place."""
    return (finding.kind, finding.subject, finding.detail.get("dst"))


def frequency_identity(bucket_hz: float):
    """Build an identity for RF findings, tolerant of small frequency drift.

    A carrier is re-measured slightly differently on every sweep, so exact
    frequency matching would treat one transmitter as an endless series of new
    ones. Rounding into buckets makes "close enough" an exact dictionary hit.
    """
    def identity(finding: Finding) -> tuple:
        """Kind, subject, and which frequency bucket this carrier fell in."""
        frequency = finding.detail.get("freq_hz", 0.0)
        return (finding.kind, finding.subject, round(frequency / bucket_hz))
    return identity


class AlertSink:
    """Sends findings to an endpoint, optionally suppressing repeats."""

    def __init__(self, url: str | None, source_name: str = "gridhawk",
                 timeout: float = DEFAULT_TIMEOUT_S, verbose: bool = True,
                 suppress_repeats_for: float = NO_SUPPRESSION,
                 identity_of=default_identity):
        """Configure delivery. A url of None means console-only."""
        self.url = url
        self.source_name = source_name
        self.timeout = timeout
        self.verbose = verbose
        self.suppress_repeats_for = suppress_repeats_for
        self.identity_of = identity_of

        self.sent_count = 0
        self.failed_count = 0
        self.suppressed_count = 0
        self._last_sent_at: dict[tuple, float] = {}

    def is_suppressed(self, finding: Finding) -> bool:
        """True when this alert was already reported recently.

        Without this, a device that keeps calling an unauthorised endpoint --
        or a rogue radio that keeps transmitting -- raises the same alert every
        window and buries everything else on the dashboard.
        """
        if self.suppress_repeats_for <= NO_SUPPRESSION:
            return False

        identity = self.identity_of(finding)
        last_sent = self._last_sent_at.get(identity)
        if last_sent is None:
            return False
        return (time.time() - last_sent) < self.suppress_repeats_for

    def send(self, finding: Finding) -> bool:
        """Deliver one finding. Returns True when the endpoint accepted it."""
        if self.is_suppressed(finding):
            self.suppressed_count += 1
            return False

        self._last_sent_at[self.identity_of(finding)] = time.time()

        if self.verbose:
            self._print_locally(finding)

        if not self.url:
            return False        # console-only mode

        return self._post(finding)

    def send_all(self, findings: list[Finding]) -> int:
        """Deliver several findings, returning how many were accepted."""
        accepted = 0
        for finding in findings:
            if self.send(finding):
                accepted += 1
        return accepted

    def _post(self, finding: Finding) -> bool:
        """The HTTP call itself, with every failure treated as non-fatal."""
        payload = finding.to_dict()
        payload["reporter"] = self.source_name

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": CONTENT_TYPE},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                accepted = 200 <= response.status < 300
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            print(f"  [alert] delivery failed: {error}", file=sys.stderr)
            self.failed_count += 1
            return False

        if accepted:
            self.sent_count += 1
        else:
            self.failed_count += 1
        return accepted

    def _print_locally(self, finding: Finding) -> None:
        """Show the alert on the console too, so the demo works unattended."""
        print(f"  [ALERT] {finding.severity.upper():<8} {finding.kind}")
        for key, value in sorted(finding.detail.items()):
            if isinstance(value, (dict, list)):
                continue        # keep the console line-oriented
            print(f"          {key}: {value}")

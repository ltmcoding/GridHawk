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
import urllib.error
import urllib.request

from core.events import Finding


DEFAULT_TIMEOUT_S = 5.0
CONTENT_TYPE = "application/json"


class AlertSink:
    """Sends findings to an endpoint, keeping a tally of what happened."""

    def __init__(self, url: str | None, source_name: str = "gridhawk",
                 timeout: float = DEFAULT_TIMEOUT_S, verbose: bool = True):
        self.url = url
        self.source_name = source_name
        self.timeout = timeout
        self.verbose = verbose
        self.sent_count = 0
        self.failed_count = 0

    def send(self, finding: Finding) -> bool:
        """Deliver one finding. Returns True when the endpoint accepted it."""
        payload = finding.to_dict()
        payload["reporter"] = self.source_name

        if self.verbose:
            self._print_locally(finding)

        if not self.url:
            return False        # console-only mode

        encoded = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=encoded,
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

    def send_all(self, findings: list[Finding]) -> int:
        """Deliver several findings, returning how many were accepted."""
        accepted = 0
        for finding in findings:
            if self.send(finding):
                accepted += 1
        return accepted

    def _print_locally(self, finding: Finding) -> None:
        """Show the alert on the console too, so the demo works unattended."""
        headline = f"  [ALERT] {finding.severity.upper():<8} {finding.kind}"
        print(headline)
        for key, value in sorted(finding.detail.items()):
            if isinstance(value, (dict, list)):
                continue        # keep the console line-oriented
            print(f"          {key}: {value}")

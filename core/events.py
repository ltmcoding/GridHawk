"""Normalised records shared by every collector.

Every source — RF, Modbus, TLS egress — emits Observations onto one queue.
The rules engine consumes Observations and emits Findings.  Nothing
downstream of a collector knows whether its input was live hardware, a
replayed capture, or the simulator: that is the whole point of the split.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

# Anomaly vocabulary.  The scenario generator injects these by name and the
# scorer matches on them, so generator and detector must agree exactly.
KINDS = (
    "new_asn",           # destination ASN outside the allowlist
    "geo_drift",         # known ASN, unexpected country
    "off_cycle_burst",   # connection well outside the learned cadence
    "volume_spike",      # session bytes consistent with a firmware image pull
    "tunnel_indicator",  # egress shape suggesting a proxy/tunnel
    "excess_emitter",    # RF: more carriers present than documented radios
    "modbus_write",      # unauthenticated write to a holding register
    "attestation_fail",  # SunSpec firmware-integrity model reports fail/stale
)

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Observation:
    """One raw measurement from one collector."""

    ts: float
    source: str            # 'tls_egress' | 'modbus' | 'rf'
    subject: str           # device id, source IP, or band under watch
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


@dataclass
class Finding:
    """A rule firing on one or more Observations."""

    ts: float
    source: str
    subject: str
    kind: str
    severity: str
    detail: dict[str, Any] = field(default_factory=dict)
    # Populated by the correlator from the Layer 1 inventory.  A 501 kW
    # Sungrow and a 7 kW microinverter raising the same flag are not the
    # same alert, and this field is what encodes that.
    mw_at_risk: float | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown finding kind: {self.kind!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")

    @property
    def priority(self) -> float:
        """Grid Lockout Layer 2: alert priority = anomaly x MW behind device."""
        weight = {"info": 0.1, "low": 0.3, "medium": 1.0, "high": 3.0, "critical": 10.0}
        return weight[self.severity] * (self.mw_at_risk or 0.001)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["priority"] = round(self.priority, 6)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


def write_findings(path: str, findings: list[Finding]) -> None:
    with open(path, "w") as fh:
        for f in sorted(findings, key=lambda x: -x.priority):
            fh.write(f.to_json() + "\n")

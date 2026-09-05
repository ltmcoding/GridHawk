"""Layer 1 join: weight each alert by the capacity sitting behind the device.

Grid Lockout's Layer 2 specification says:

    alert priority = anomaly x MW behind the device

which is the whole operational reason the inventory matters. A 501 kW Sungrow
and a 7 kW microinverter raising the identical flag are not the identical alert,
and only the inventory knows the difference.

Anomalies are of uncertain provenance. The megawatts behind them are measured
fact, drawn from interconnection records. That asymmetry is why this layer
carries the ranking.
"""

from __future__ import annotations

import json

from core.events import Finding


# Devices absent from the inventory still deserve an alert -- they are simply
# unranked. This nominal figure keeps them at the bottom rather than dropping
# them, because an unknown device on the network is itself worth noticing.
UNKNOWN_DEVICE_MW = 0.001

KILOWATTS_PER_MEGAWATT = 1000.0


class Inventory:
    """Devices resolved to their capacity, vendor, and corporate parent."""

    def __init__(self, records: dict[str, dict]):
        self.records = records

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path) as handle:
            document = json.load(handle)

        records = {}
        for identifier, record in document.items():
            if identifier.startswith("_"):
                continue        # comment keys
            records[identifier] = record
        return cls(records)

    def lookup(self, subject: str) -> dict | None:
        """Find a device by whatever identifies it in the observation stream."""
        return self.records.get(subject)

    def capacity_mw(self, subject: str) -> float:
        record = self.lookup(subject)
        if record is None:
            return UNKNOWN_DEVICE_MW
        return float(record.get("capacity_mw", UNKNOWN_DEVICE_MW))

    def total_mw(self) -> float:
        total = 0.0
        for record in self.records.values():
            total += float(record.get("capacity_mw", 0.0))
        return total


def enrich(findings: list[Finding], inventory: Inventory) -> list[Finding]:
    """Attach capacity and device identity to each finding, in place.

    Sets `mw_at_risk`, which `Finding.priority` multiplies by severity, and adds
    the vendor and location to the detail so an operator sees what the alert is
    actually about rather than an anonymous address.
    """
    for finding in findings:
        record = inventory.lookup(finding.subject)

        if record is None:
            finding.mw_at_risk = UNKNOWN_DEVICE_MW
            finding.detail["device"] = "not in inventory"
            continue

        finding.mw_at_risk = float(record.get("capacity_mw", UNKNOWN_DEVICE_MW))

        vendor = record.get("vendor", "unknown vendor")
        model = record.get("model", "")
        if model:
            finding.detail["device"] = f"{vendor} {model}"
        else:
            finding.detail["device"] = vendor

        capacity_kw = finding.mw_at_risk * KILOWATTS_PER_MEGAWATT
        finding.detail["capacity_kw"] = round(capacity_kw, 1)

        for optional_field in ("county", "parent_country", "segment"):
            if optional_field in record:
                finding.detail[optional_field] = record[optional_field]

    return findings


def _finding_priority(finding: Finding) -> float:
    """Sort key: most urgent first."""
    return -finding.priority


def rank(findings: list[Finding]) -> list[Finding]:
    """Order findings by severity weighted by capacity at risk."""
    return sorted(findings, key=_finding_priority)


def summarise(findings: list[Finding]) -> dict:
    """Totals worth putting on a dashboard."""
    total_mw = 0.0
    by_severity: dict[str, int] = {}

    for finding in findings:
        total_mw += finding.mw_at_risk or 0.0
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    return {
        "n_findings": len(findings),
        "mw_at_risk": round(total_mw, 3),
        "by_severity": by_severity,
    }

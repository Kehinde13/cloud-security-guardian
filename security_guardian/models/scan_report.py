"""Typed, in-memory report for a completed scan of all supported scanners."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from security_guardian.models.finding import Finding, Severity


ScannerType = Literal["storage", "firewall", "iam"]
SCANNER_TYPES: tuple[ScannerType, ...] = ("storage", "firewall", "iam")


@dataclass
class ScanReport:
    timestamp: datetime
    findings_by_scanner: dict[ScannerType, list[Finding]]
    total_findings: int = field(init=False)
    findings_by_severity: dict[Severity, list[Finding]] = field(init=False)
    findings: list[Finding] = field(init=False)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("ScanReport timestamp must be timezone-aware")
        self.timestamp = self.timestamp.astimezone(timezone.utc)
        if set(self.findings_by_scanner) != set(SCANNER_TYPES):
            raise ValueError("ScanReport requires storage, firewall, and iam groups")
        # Copy containers, retaining the original Finding objects and their order.
        self.findings_by_scanner = {
            scanner: list(self.findings_by_scanner[scanner]) for scanner in SCANNER_TYPES
        }
        self.findings = [finding for group in self.findings_by_scanner.values() for finding in group]
        self.total_findings = len(self.findings)
        self.findings_by_severity = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for finding in self.findings:
            self.findings_by_severity[finding.severity].append(finding)

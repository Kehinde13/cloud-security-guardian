"""Run all local scanners and return a complete report or a contextual error."""

from datetime import datetime, timezone
from pathlib import Path

from security_guardian.models.finding import Finding
from security_guardian.models.scan_report import ScanReport, ScannerType
from security_guardian.scanners.storage import DEFAULT_INPUT as STORAGE_INPUT, scan_buckets
from security_guardian.scanners.firewall import DEFAULT_INPUT as FIREWALL_INPUT, scan_firewalls
from security_guardian.scanners.iam import DEFAULT_INPUT as IAM_INPUT, scan_iam


class ScanError(RuntimeError):
    """A scanner failed; the original exception is available through __cause__."""

    def __init__(self, scanner: ScannerType, path: str | Path, cause: Exception) -> None:
        self.scanner = scanner
        self.path = path
        super().__init__(f"{scanner} scanner failed for {path}: {cause}")


def run_scan(
    *,
    storage_path: str | Path = STORAGE_INPUT,
    firewall_path: str | Path = FIREWALL_INPUT,
    iam_path: str | Path = IAM_INPUT,
) -> ScanReport:
    """Scan local snapshots in storage/firewall/iam order, failing without a report.

    Defaults use the existing fictional samples. Timestamp records completion in
    UTC. Findings are preserved without sorting, rewriting, or deduplicating.
    """
    groups: dict[ScannerType, list[Finding]] = {}
    for name, scanner, path in (
        ("storage", scan_buckets, storage_path),
        ("firewall", scan_firewalls, firewall_path),
        ("iam", scan_iam, iam_path),
    ):
        try:
            groups[name] = scanner(path)
        except Exception as exc:
            raise ScanError(name, path, exc) from exc
    return ScanReport(timestamp=datetime.now(timezone.utc), findings_by_scanner=groups)

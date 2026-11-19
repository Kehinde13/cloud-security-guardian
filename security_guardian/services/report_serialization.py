"""Validated schema 1.0 serialization and atomic local report export."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from security_guardian.models.finding import Finding
from security_guardian.models.scan_report import ScanReport, SCANNER_TYPES


SCHEMA_VERSION = "1.0"
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
_FINDING_FIELDS = ("resource", "severity", "issue", "recommendation", "evidence")


def _require(condition, message):
    if not condition:
        raise ValueError(f"Invalid security report: {message}")


def _keys(value, keys, location):
    _require(isinstance(value, dict) and set(value) == set(keys),
             f"{location} must contain exactly {', '.join(keys)}")


def _counts(value, keys, location):
    _keys(value, keys, location)
    _require(all(type(count) is int and count >= 0 for count in value.values()),
             f"{location} values must be non-negative integers")


def validate_report_dict(data: dict) -> None:
    """Validate a schema 1.0 dictionary without interpreting any finding content."""
    _keys(data, ("schema_version", "timestamp", "total_findings", "severity_counts",
                 "scanner_counts", "findings"), "report")
    _require(data["schema_version"] == SCHEMA_VERSION, "unsupported schema_version")
    stamp = data["timestamp"]
    _require(isinstance(stamp, str), "timestamp must be an ISO 8601 UTC string")
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid security report: timestamp must be ISO 8601 UTC") from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0
             and "T" in stamp, "timestamp must be timezone-aware UTC")
    _require(type(data["total_findings"]) is int and data["total_findings"] >= 0,
             "total_findings must be a non-negative integer")
    _counts(data["severity_counts"], SEVERITIES, "severity_counts")
    _counts(data["scanner_counts"], SCANNER_TYPES, "scanner_counts")
    _require(isinstance(data["findings"], list), "findings must be a list")
    severity_counts = dict.fromkeys(SEVERITIES, 0)
    scanner_counts = dict.fromkeys(SCANNER_TYPES, 0)
    for index, finding in enumerate(data["findings"]):
        loc = f"findings[{index}]"
        _keys(finding, ("scanner", *_FINDING_FIELDS), loc)
        for field in ("resource", "severity", "issue", "recommendation", "scanner"):
            _require(isinstance(finding[field], str), f"{loc}.{field} must be a string")
        _require(finding["evidence"] is None or isinstance(finding["evidence"], str),
                 f"{loc}.evidence must be a string or null")
        _require(finding["severity"] in SEVERITIES, f"{loc}.severity is unsupported")
        _require(finding["scanner"] in SCANNER_TYPES, f"{loc}.scanner is unsupported")
        severity_counts[finding["severity"]] += 1
        scanner_counts[finding["scanner"]] += 1
    _require(data["total_findings"] == len(data["findings"]), "total_findings is inconsistent")
    _require(data["severity_counts"] == severity_counts, "severity_counts are inconsistent")
    _require(data["scanner_counts"] == scanner_counts, "scanner_counts are inconsistent")


def report_to_dict(report: ScanReport) -> dict:
    """Return an independent JSON-compatible snapshot, rejecting stale model groups."""
    _require(isinstance(report, ScanReport), "expected ScanReport")
    _require(isinstance(report.timestamp, datetime) and report.timestamp.tzinfo is not None
             and report.timestamp.utcoffset() is not None, "timestamp must be timezone-aware")
    _keys(report.findings_by_scanner, SCANNER_TYPES, "findings_by_scanner")
    _keys(report.findings_by_severity, SEVERITIES, "findings_by_severity")
    _require(isinstance(report.findings, list), "findings must be a list")
    entries = []
    flattened = []
    for scanner in SCANNER_TYPES:
        group = report.findings_by_scanner[scanner]
        _require(isinstance(group, list), f"{scanner} findings must be a list")
        for finding in group:
            _require(isinstance(finding, Finding), "scanner groups must contain Finding objects")
            entries.append({"scanner": scanner, **{key: getattr(finding, key) for key in _FINDING_FIELDS}})
            flattened.append(finding)
    _require(report.findings == flattened, "findings disagree with scanner groups or ordering")
    data = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": report.timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "total_findings": report.total_findings,
        "severity_counts": {},
        "scanner_counts": {scanner: len(report.findings_by_scanner[scanner]) for scanner in SCANNER_TYPES},
        "findings": entries,
    }
    for severity in SEVERITIES:
        group = report.findings_by_severity[severity]
        _require(isinstance(group, list), f"{severity} findings must be a list")
        _require(group == [f for f in flattened if f.severity == severity],
                 f"{severity} group is inconsistent")
        data["severity_counts"][severity] = len(group)
    validate_report_dict(data)
    return data


def report_to_json(report: ScanReport) -> str:
    """Return deterministic, indented JSON; evidence remains opaque text or null."""
    return json.dumps(report_to_dict(report), ensure_ascii=True, allow_nan=False, indent=2) + "\n"


def export_report(report: ScanReport, path: str | Path, *, overwrite: bool = False) -> Path:
    """Publish a complete UTF-8 .json file atomically; never clobber by default.

    Validation precedes filesystem changes. A same-directory temporary file is
    flushed and synced before atomic publication. No-clobber publication requires
    filesystem hard-link support; unsupported filesystems fail safely.
    """
    _require(type(overwrite) is bool, "overwrite must be a boolean")
    path = Path(path)
    if path.suffix.lower() != ".json":
        raise ValueError("Report export path must have a .json extension")
    payload = report_to_json(report)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".security-report-", suffix=".tmp",
                                         delete=False) as output:
            temporary = Path(output.name)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if overwrite:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
    except FileExistsError as exc:
        raise FileExistsError(f"Report export refused: destination already exists: {path}") from exc
    except OSError as exc:
        raise OSError(f"Report export failed for {path}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                raise OSError(f"Report export temporary-file cleanup failed for {path}: {exc}") from exc
    return path

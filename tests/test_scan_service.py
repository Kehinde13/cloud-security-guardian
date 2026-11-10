from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import socket
from unittest.mock import Mock

import pytest

from security_guardian.models.finding import Finding
from security_guardian.models.scan_report import ScanReport
from security_guardian.services import scan_service


@pytest.fixture
def paths(tmp_path):
    result = {}
    for scanner, key in (("storage", "buckets"), ("firewall", "firewalls"), ("iam", "policies")):
        path = tmp_path / f"{scanner}.json"
        path.write_text(json.dumps({key: []}), encoding="utf-8")
        result[f"{scanner}_path"] = path
    return result


def test_empty_real_scans(paths):
    report = scan_service.run_scan(**paths)
    assert report.total_findings == 0
    assert report.findings == []
    assert report.findings_by_severity == {"HIGH": [], "MEDIUM": [], "LOW": []}
    assert report.findings_by_scanner == {"storage": [], "firewall": [], "iam": []}


def test_grouping_order_preservation_and_path_forwarding(paths, monkeypatch):
    first = Finding("bucket", "MEDIUM", "original issue", "original advice", '{"raw": true}')
    second = Finding("rule", "HIGH", "issue", "advice")
    third = Finding("account", "LOW", "issue", "advice", "evidence")
    originals = [first, second, third]
    before = [asdict(f) for f in originals]
    calls = []
    for name, function, findings in (("storage", "scan_buckets", [first, first]),
                                     ("firewall", "scan_firewalls", [second]),
                                     ("iam", "scan_iam", [third])):
        def scanner(path, name=name, findings=findings):
            calls.append((name, path))
            return findings
        monkeypatch.setattr(scan_service, function, scanner)
    report = scan_service.run_scan(**paths)
    assert calls == [(name, paths[f"{name}_path"]) for name in ("storage", "firewall", "iam")]
    assert report.total_findings == 4
    assert report.findings == [first, first, second, third]
    assert report.findings_by_severity == {"HIGH": [second], "MEDIUM": [first, first], "LOW": [third]}
    assert report.findings_by_scanner == {"storage": [first, first], "firewall": [second], "iam": [third]}
    assert all(actual is expected for actual, expected in zip(report.findings, [first, first, second, third]))
    assert report.findings_by_severity["HIGH"][0] is second
    assert report.findings_by_scanner["storage"][0] is first
    assert [asdict(f) for f in originals] == before


@pytest.mark.parametrize("scanner", ["storage", "firewall", "iam"])
def test_missing_input_identifies_scanner(paths, tmp_path, scanner):
    missing = tmp_path / "missing.json"
    paths[f"{scanner}_path"] = str(missing)
    with pytest.raises(scan_service.ScanError, match=f"{scanner} scanner failed") as caught:
        scan_service.run_scan(**paths)
    assert caught.value.scanner == scanner
    assert str(missing) in str(caught.value)
    assert isinstance(caught.value.__cause__, FileNotFoundError)


@pytest.mark.parametrize("scanner", ["storage", "firewall", "iam"])
def test_malformed_input(paths, scanner):
    paths[f"{scanner}_path"].write_text("{", encoding="utf-8")
    with pytest.raises(scan_service.ScanError, match=f"{scanner} scanner failed") as caught:
        scan_service.run_scan(**paths)
    assert isinstance(caught.value.__cause__, ValueError)


@pytest.mark.parametrize("failed_index", [0, 1, 2])
def test_failure_never_returns_partial_report(paths, monkeypatch, failed_index):
    names = ("storage", "firewall", "iam")
    functions = ("scan_buckets", "scan_firewalls", "scan_iam")
    cause = RuntimeError("simulated scanner failure")
    mocks = []
    for index, function in enumerate(functions):
        mock = Mock(side_effect=cause) if index == failed_index else Mock(return_value=[])
        monkeypatch.setattr(scan_service, function, mock)
        mocks.append(mock)
    report_constructor = Mock()
    monkeypatch.setattr(scan_service, "ScanReport", report_constructor)
    with pytest.raises(scan_service.ScanError) as caught:
        scan_service.run_scan(**paths)
    assert caught.value.scanner == names[failed_index]
    assert caught.value.__cause__ is cause
    assert "simulated scanner failure" in str(caught.value)
    assert [mock.call_count for mock in mocks] == [int(i <= failed_index) for i in range(3)]
    report_constructor.assert_not_called()


def test_utc_completion_timestamp(paths):
    before = datetime.now(timezone.utc)
    report = scan_service.run_scan(**paths)
    after = datetime.now(timezone.utc)
    assert report.timestamp.tzinfo is timezone.utc
    assert before <= report.timestamp <= after


def test_report_normalizes_aware_timestamp_and_copies_containers():
    stamp = datetime(2026, 11, 10, 12, tzinfo=timezone(timedelta(hours=1)))
    groups = {"iam": [], "storage": [], "firewall": []}
    report = ScanReport(stamp, groups)
    assert report.timestamp == datetime(2026, 11, 10, 11, tzinfo=timezone.utc)
    assert list(report.findings_by_scanner) == ["storage", "firewall", "iam"]
    groups["storage"].append(Finding("x", "LOW", "issue", "advice"))
    assert report.findings_by_scanner["storage"] == []


def test_report_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        ScanReport(datetime(2026, 11, 10), {"storage": [], "firewall": [], "iam": []})


def test_report_requires_all_scanners():
    with pytest.raises(ValueError, match="requires storage, firewall, and iam"):
        ScanReport(datetime.now(timezone.utc), {"storage": []})


def test_sample_totals_determinism_and_read_only(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Network access attempted")
    for function in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, function, forbidden)
    inputs = (scan_service.STORAGE_INPUT, scan_service.FIREWALL_INPUT, scan_service.IAM_INPUT)
    before = [path.read_bytes() for path in inputs]
    monkeypatch.chdir(tmp_path)
    first = scan_service.run_scan()
    second = scan_service.run_scan()
    assert first.total_findings == 17
    assert {k: len(v) for k, v in first.findings_by_scanner.items()} == {"storage": 5, "firewall": 6, "iam": 6}
    assert {k: len(v) for k, v in first.findings_by_severity.items()} == {"HIGH": 11, "MEDIUM": 6, "LOW": 0}
    first_data, second_data = asdict(first), asdict(second)
    first_data.pop("timestamp")
    second_data.pop("timestamp")
    assert first_data == second_data
    assert [path.read_bytes() for path in inputs] == before

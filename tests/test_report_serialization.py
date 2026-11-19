import copy
from datetime import datetime, timedelta, timezone
import json
import socket

import pytest

from security_guardian.models.finding import Finding
from security_guardian.models.scan_report import ScanReport
from security_guardian.services import report_serialization as serialization
from security_guardian.services.scan_service import run_scan


@pytest.fixture
def report():
    return ScanReport(datetime(2026, 11, 10, 12, tzinfo=timezone.utc), {
        "storage": [Finding("bucket", "HIGH", "issue", "advice", None)],
        "firewall": [Finding("rule", "MEDIUM", "issue", "advice", '{"data": true}')],
        "iam": [Finding("account", "LOW", "issue", "advice", "")],
    })


def test_dictionary_structure_counts_and_preservation(report):
    data = serialization.report_to_dict(report)
    assert list(data) == ["schema_version", "timestamp", "total_findings", "severity_counts", "scanner_counts", "findings"]
    assert data["schema_version"] == "1.0"
    assert data["timestamp"] == "2026-11-10T12:00:00.000000Z"
    assert data["total_findings"] == 3
    assert data["severity_counts"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert data["scanner_counts"] == {"storage": 1, "firewall": 1, "iam": 1}
    for entry, scanner, finding in zip(data["findings"], ("storage", "firewall", "iam"), report.findings):
        assert entry == {"scanner": scanner, **vars(finding)}
    data["findings"][0]["issue"] = "changed"
    assert report.findings[0].issue == "issue"


def test_json_determinism_and_optional_evidence(report):
    text = serialization.report_to_json(report)
    assert text == serialization.report_to_json(report)
    data = json.loads(text)
    assert data == serialization.report_to_dict(report)
    assert [f["evidence"] for f in data["findings"]] == [None, '{"data": true}', ""]


def test_unicode_special_characters_and_untrusted_text(report):
    content = '\"\\\n<script>alert(1)</script> ${SECRET} $(whoami) café 日本語 🔐'
    for field in ("resource", "issue", "recommendation", "evidence"):
        setattr(report.findings[0], field, content)
    result = json.loads(serialization.report_to_json(report))["findings"][0]
    for field in ("resource", "issue", "recommendation", "evidence"):
        assert result[field] == content


def test_empty_report():
    report = ScanReport(datetime.now(timezone.utc), {"storage": [], "firewall": [], "iam": []})
    data = serialization.report_to_dict(report)
    assert data["findings"] == [] and data["total_findings"] == 0
    assert list(data["severity_counts"].values()) == [0, 0, 0]
    assert list(data["scanner_counts"].values()) == [0, 0, 0]


def test_normalizes_utc(report):
    report.timestamp = datetime(2026, 11, 10, 13, tzinfo=timezone(timedelta(hours=1)))
    assert serialization.report_to_dict(report)["timestamp"] == "2026-11-10T12:00:00.000000Z"


@pytest.mark.parametrize("field,value", [
    ("total_findings", 99), ("total_findings", True), ("timestamp", "today"),
    ("timestamp", datetime(2026, 1, 1)), ("findings", []), ("findings", None),
    ("findings_by_scanner", {}), ("findings_by_severity", {}),
])
def test_invalid_model_fields(report, field, value):
    setattr(report, field, value)
    with pytest.raises(ValueError, match="Invalid security report"):
        serialization.report_to_dict(report)


def test_stale_group_rejected(report):
    report.findings_by_severity["HIGH"] = []
    with pytest.raises(ValueError, match="group is inconsistent"):
        serialization.report_to_dict(report)


@pytest.mark.parametrize("field,value", [("resource", None), ("issue", 5), ("recommendation", []),
                                        ("evidence", {}), ("severity", "CRITICAL")])
def test_invalid_finding_fields(report, field, value):
    setattr(report.findings[0], field, value)
    with pytest.raises(ValueError):
        serialization.report_to_dict(report)


@pytest.mark.parametrize("field,value", [
    ("schema_version", "2.0"), ("timestamp", "bad"), ("timestamp", 5),
    ("timestamp", "2026-01-01T00:00:00"), ("timestamp", "2026-01-01T01:00:00+01:00"),
    ("total_findings", 0), ("total_findings", True), ("total_findings", -1),
    ("severity_counts", {"HIGH": 2, "MEDIUM": 0, "LOW": 1}),
    ("severity_counts", {"HIGH": True, "MEDIUM": 1, "LOW": 1}),
    ("scanner_counts", {"storage": 0, "firewall": 1, "iam": 2}),
    ("scanner_counts", {}), ("findings", {}),
])
def test_invalid_serialized_fields(report, field, value):
    data = serialization.report_to_dict(report)
    data[field] = value
    with pytest.raises(ValueError, match="Invalid security report"):
        serialization.validate_report_dict(data)


@pytest.mark.parametrize("field,value", [("scanner", "unknown"), ("severity", "critical"),
                                        ("evidence", []), ("resource", None)])
def test_invalid_serialized_finding(report, field, value):
    data = serialization.report_to_dict(report)
    data["findings"][0][field] = value
    with pytest.raises(ValueError):
        serialization.validate_report_dict(data)


def test_missing_and_extra_keys(report):
    data = serialization.report_to_dict(report)
    for bad in (None, [], {**data, "extra": 1}, {k: v for k, v in data.items() if k != "findings"}):
        with pytest.raises(ValueError):
            serialization.validate_report_dict(bad)


def test_export_and_existing_file_protection(report, tmp_path):
    path = tmp_path / "report.json"
    assert serialization.export_report(report, path) == path
    before = path.read_bytes()
    assert json.loads(before) == serialization.report_to_dict(report)
    report.findings[0].issue = "new issue"
    with pytest.raises(FileExistsError, match="already exists"):
        serialization.export_report(report, path)
    assert path.read_bytes() == before
    serialization.export_report(report, path, overwrite=True)
    assert json.loads(path.read_text())["findings"][0]["issue"] == "new issue"
    assert list(tmp_path.iterdir()) == [path]


def test_invalid_report_leaves_no_files(report, tmp_path):
    report.total_findings = 999
    with pytest.raises(ValueError):
        serialization.export_report(report, tmp_path / "report.json")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("operation", ["fsync", "link", "replace"])
def test_writing_or_publication_failure(report, tmp_path, monkeypatch, operation):
    path = tmp_path / "report.json"
    if operation == "replace":
        path.write_text("existing content")
    def fail(*args, **kwargs):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(serialization.os, operation, fail)
    with pytest.raises(OSError, match="Report export failed.*simulated disk failure"):
        serialization.export_report(report, path, overwrite=operation == "replace")
    if operation == "replace":
        assert path.read_text() == "existing content"
        assert list(tmp_path.iterdir()) == [path]
    else:
        assert list(tmp_path.iterdir()) == []


def test_write_failure_cleanup(report, tmp_path, monkeypatch):
    real = serialization.tempfile.NamedTemporaryFile
    class BrokenWriter:
        def __enter__(self):
            self.file = real(dir=tmp_path, delete=False, mode="w")
            self.name = self.file.name
            return self
        def write(self, text):
            self.file.write("partial")
            raise OSError("write failed")
        def __exit__(self, *args):
            self.file.close()
    monkeypatch.setattr(serialization.tempfile, "NamedTemporaryFile", lambda **kwargs: BrokenWriter())
    with pytest.raises(OSError, match="Report export failed"):
        serialization.export_report(report, tmp_path / "report.json")
    assert list(tmp_path.iterdir()) == []


def test_missing_parent_and_extension(report, tmp_path):
    with pytest.raises(OSError, match="Report export failed"):
        serialization.export_report(report, tmp_path / "missing" / "report.json")
    with pytest.raises(ValueError, match=".json extension"):
        serialization.export_report(report, tmp_path / "report.txt")


def test_atomic_no_clobber_race(report, tmp_path, monkeypatch):
    real_link = serialization.os.link
    path = tmp_path / "report.json"
    def competing_writer(source, destination):
        path.write_text("competitor")
        real_link(source, destination)
    monkeypatch.setattr(serialization.os, "link", competing_writer)
    with pytest.raises(FileExistsError):
        serialization.export_report(report, path)
    assert path.read_text() == "competitor"
    assert list(tmp_path.iterdir()) == [path]


def test_sample_export_without_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Network call attempted")
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, forbidden)
    report = run_scan()
    path = serialization.export_report(report, tmp_path / "sample.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    serialization.validate_report_dict(data)
    assert data["total_findings"] == 17
    assert data["severity_counts"] == {"HIGH": 11, "MEDIUM": 6, "LOW": 0}
    assert data["scanner_counts"] == {"storage": 5, "firewall": 6, "iam": 6}
    assert [f["scanner"] for f in data["findings"]] == ["storage"] * 5 + ["firewall"] * 6 + ["iam"] * 6
    assert serialization.report_to_json(copy.deepcopy(report)) == serialization.report_to_json(report)

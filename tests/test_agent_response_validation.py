"""Pure validation against synthetic and real local reports, never live AI."""
import copy
from datetime import datetime, timezone
import socket
import traceback
import pytest
from agents.cloud_security_guardian.response_validation import validate_analysis, AnalysisValidationError
from agents.cloud_security_guardian.agent import root_agent
from agents.cloud_security_guardian.tools import scan_security_configuration
from security_guardian.models.finding import Finding
from security_guardian.models.scan_report import ScanReport
from security_guardian.services.report_serialization import report_to_dict


def explain(source):
    return dict(executive_summary="Synthetic analysis", total_findings=source["total_findings"],
                severity_counts=copy.deepcopy(source["severity_counts"]),
                findings=[dict(finding_index=i, scanner=f["scanner"], resource=f["resource"],
                    severity=f["severity"], explanation="Synthetic explanation",
                    potential_implications="Potential risk, not verified", recommended_action="Human review")
                    for i, f in enumerate(source["findings"])],
                analysis_limitations=["Fictional snapshots only"])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network or credential discovery attempted")
    import google.auth
    monkeypatch.setattr(google.auth, "default", forbidden)
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def source():
    return report_to_dict(ScanReport(datetime.now(timezone.utc), {
        "storage": [Finding("same-resource", "HIGH", "issue one", "review", "original evidence"),
                    Finding("same-resource", "MEDIUM", "issue two", "review", None)],
        "firewall": [], "iam": []}))


def test_same_resource_distinct_findings_and_no_mutation(source):
    candidate = explain(source)
    candidate["findings"].reverse()
    before = copy.deepcopy((source, candidate))
    result = validate_analysis(candidate, source)
    assert result.model_dump() == candidate
    assert (source, candidate) == before
    result.findings[0].explanation = "changed"
    result.analysis_limitations.append("new")
    assert (source, candidate) == before


@pytest.mark.parametrize("change", ["total", "counts", "out_of_range", "duplicate", "missing",
                                    "fabricated", "resource", "scanner", "severity"])
def test_inconsistent_analysis(source, change):
    data = explain(source)
    if change == "total": data["total_findings"] = 99
    elif change == "counts": data["severity_counts"] = dict(HIGH=0, MEDIUM=2, LOW=0)
    elif change == "out_of_range": data["findings"][0]["finding_index"] = 2
    elif change == "duplicate": data["findings"][1] = copy.deepcopy(data["findings"][0])
    elif change == "missing": data["findings"].pop()
    elif change == "fabricated": data["findings"].append({**data["findings"][0], "finding_index": 9})
    elif change == "resource": data["findings"][0]["resource"] = "fabricated"
    elif change == "scanner": data["findings"][0]["scanner"] = "iam"
    elif change == "severity": data["findings"][0]["severity"] = "LOW"
    before = copy.deepcopy((source, data))
    with pytest.raises(AnalysisValidationError): validate_analysis(data, source)
    assert (source, data) == before


@pytest.mark.parametrize("bad", [None, {}, {"status": "error", "error": {"message": "private"}},
                                 {"status": "success", "report": {}}])
def test_invalid_source_and_tool_envelopes(bad):
    with pytest.raises(AnalysisValidationError, match="Invalid authoritative report"):
        validate_analysis({}, bad)


def test_inconsistent_source(source):
    source["total_findings"] = 99
    with pytest.raises(AnalysisValidationError, match="Invalid authoritative report"):
        validate_analysis(explain(source), source)


def test_safe_schema_errors(source):
    bad = explain(source)
    bad["findings"][0]["finding_index"] = "PRIVATE_SECRET"
    with pytest.raises(AnalysisValidationError) as error:
        validate_analysis(bad, source)
    assert "PRIVATE_SECRET" not in str(error.value)
    assert "PRIVATE_SECRET" not in "".join(traceback.format_exception(error.value))
    with pytest.raises(AnalysisValidationError): validate_analysis("private", source)


def test_empty_report():
    source = report_to_dict(ScanReport(datetime.now(timezone.utc), dict(storage=[], firewall=[], iam=[])))
    assert validate_analysis(explain(source), source).findings == []
    bad = explain(source)
    bad["total_findings"] = 1
    with pytest.raises(AnalysisValidationError): validate_analysis(bad, source)


def test_real_sample_report():
    response = scan_security_configuration()
    assert response["status"] == "success"
    source = response["report"]
    assert source["total_findings"] == 17
    assert source["severity_counts"] == dict(HIGH=11, MEDIUM=6, LOW=0)
    assert len(validate_analysis(explain(source), source).findings) == 17
    assert root_agent.tools == [scan_security_configuration]
    assert root_agent.output_schema is None

"""Synthetic structure checks; no model requests."""
import copy
import pytest
from pydantic import ValidationError
from agents.cloud_security_guardian.response_models import SecurityAnalysis


def candidate():
    return dict(executive_summary="Synthetic analysis", total_findings=1,
                severity_counts=dict(HIGH=1, MEDIUM=0, LOW=0),
                findings=[dict(finding_index=0, scanner="storage", resource="bucket",
                    severity="HIGH", explanation="Observed configuration",
                    potential_implications="Potential access", recommended_action="Review access")],
                analysis_limitations=["Local snapshots only"])


def test_valid_model_and_json_schema():
    value = candidate()
    assert SecurityAnalysis.model_validate(value).model_dump() == value
    assert SecurityAnalysis.model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize("field", list(candidate()))
def test_missing_required_fields(field):
    value = candidate()
    del value[field]
    with pytest.raises(ValidationError):
        SecurityAnalysis.model_validate(value)


@pytest.mark.parametrize("path,value", [
    (("extra",), "unexpected"), (("severity_counts", "EXTRA"), 0),
    (("findings", 0, "evidence"), "cannot replace original evidence"),
    (("total_findings",), -1), (("total_findings",), True),
    (("total_findings",), "1"), (("total_findings",), 1.0),
    (("severity_counts", "HIGH"), True), (("severity_counts", "LOW"), -1),
    (("severity_counts", "HIGH"), "1"), (("executive_summary",), 5),
    (("executive_summary",), " "), (("analysis_limitations",), []),
    (("analysis_limitations",), "unknown"), (("analysis_limitations",), [None]),
    (("findings",), {}), (("findings", 0, "severity"), "CRITICAL"),
    (("findings", 0, "scanner"), "other"), (("findings", 0, "resource"), 1),
    (("findings", 0, "finding_index"), -1), (("findings", 0, "finding_index"), True),
    (("findings", 0, "finding_index"), "0"), (("findings", 0, "explanation"), ""),
])
def test_rejects_invalid_structure(path, value):
    data = copy.deepcopy(candidate())
    parent = data
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(ValidationError):
        SecurityAnalysis.model_validate(data)


@pytest.mark.parametrize("field", list(candidate()["findings"][0]))
def test_missing_finding_fields(field):
    data = candidate()
    del data["findings"][0][field]
    with pytest.raises(ValidationError):
        SecurityAnalysis.model_validate(data)

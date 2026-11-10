import pytest

from security_guardian.models.finding import Finding


@pytest.mark.parametrize("severity", ["HIGH", "MEDIUM", "LOW"])
def test_finding_accepts_supported_severities(severity: str) -> None:
    finding = Finding(
        resource="example-bucket",
        severity=severity,  # type: ignore[arg-type]
        issue="Bucket is publicly accessible",
        recommendation="Restrict access to authorized users",
    )

    assert finding.severity == severity


@pytest.mark.parametrize("severity", ["CRITICAL", "high", ""])
def test_finding_rejects_unsupported_severities(severity: str) -> None:
    with pytest.raises(ValueError, match="severity must be one of: HIGH, MEDIUM, LOW"):
        Finding(
            resource="example-bucket",
            severity=severity,  # type: ignore[arg-type]
            issue="Bucket is publicly accessible",
            recommendation="Restrict access to authorized users",
        )


def test_finding_stores_fields_and_defaults_evidence_to_none() -> None:
    finding = Finding(
        resource="example-bucket",
        severity="MEDIUM",
        issue="Encryption is disabled",
        recommendation="Enable encryption",
    )

    assert finding.resource == "example-bucket"
    assert finding.issue == "Encryption is disabled"
    assert finding.recommendation == "Enable encryption"
    assert finding.evidence is None


def test_finding_accepts_evidence() -> None:
    finding = Finding(
        resource="example-bucket",
        severity="LOW",
        issue="Bucket has no labels",
        recommendation="Add ownership labels",
        evidence="Labels: []",
    )

    assert finding.evidence == "Labels: []"

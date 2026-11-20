"""Pure consistency checks, without model execution or prose fact checking."""
from pydantic import ValidationError
from security_guardian.services.report_serialization import validate_report_dict
from .response_models import SecurityAnalysis


class AnalysisValidationError(ValueError):
    """Fixed safe message; excludes candidate and source content."""


def validate_analysis(candidate: dict, source_report: dict) -> SecurityAnalysis:
    """Validate a full analysis against a serialized successful report dictionary.

    Pass the report member of a successful tool response, not its envelope.
    Inputs remain unchanged. Returns a fresh validated model, not corrected data.
    References apply only to the supplied report's ordering. Prose is unverified.
    """
    try:
        validate_report_dict(source_report)
    except (ValueError, TypeError, OverflowError):
        raise AnalysisValidationError("Invalid authoritative report.") from None
    if type(candidate) is not dict:
        raise AnalysisValidationError("Analysis must be a structured dictionary.")
    try:
        analysis = SecurityAnalysis.model_validate(candidate)
    except ValidationError:
        raise AnalysisValidationError("Analysis does not satisfy the response schema.") from None
    if analysis.total_findings != source_report["total_findings"]:
        raise AnalysisValidationError("Analysis total does not match the report.")
    if analysis.severity_counts.model_dump() != source_report["severity_counts"]:
        raise AnalysisValidationError("Analysis severity counts do not match the report.")
    source_findings = source_report["findings"]
    seen = set()
    for finding in analysis.findings:
        index = finding.finding_index
        if index >= len(source_findings):
            raise AnalysisValidationError("Finding reference is outside the report.")
        if index in seen:
            raise AnalysisValidationError("Duplicate finding reference.")
        seen.add(index)
        original = source_findings[index]
        for field in ("scanner", "resource", "severity"):
            if getattr(finding, field) != original[field]:
                raise AnalysisValidationError("Finding identity or severity does not match the report.")
    if seen != set(range(len(source_findings))):
        raise AnalysisValidationError("Analysis must represent every source finding exactly once.")
    return analysis

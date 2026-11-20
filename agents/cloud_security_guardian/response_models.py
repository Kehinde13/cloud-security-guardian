"""Strict full-scan explanations, separate from authoritative scanner data."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Count = Annotated[int, Field(ge=0)]
Text = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True,
                              revalidate_instances="always")


class SeverityCounts(_StrictModel):
    HIGH: Count
    MEDIUM: Count
    LOW: Count


class FindingExplanation(_StrictModel):
    finding_index: Count = Field(description="Zero-based index in this source report only.")
    scanner: Literal["storage", "firewall", "iam"]
    resource: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    explanation: Text
    potential_implications: Text
    recommended_action: Text


class SecurityAnalysis(_StrictModel):
    executive_summary: Text
    total_findings: Count
    severity_counts: SeverityCounts
    findings: list[FindingExplanation]
    analysis_limitations: Annotated[list[Text], Field(min_length=1)]

from dataclasses import dataclass
from typing import Literal, Optional


Severity = Literal["HIGH", "MEDIUM", "LOW"]
_VALID_SEVERITIES = ("HIGH", "MEDIUM", "LOW")


@dataclass
class Finding:
    resource: str
    severity: Severity
    issue: str
    recommendation: str
    evidence: Optional[str] = None

    def __post_init__(self) -> None:
        if self.severity not in _VALID_SEVERITIES:
            allowed = ", ".join(_VALID_SEVERITIES)
            raise ValueError(f"severity must be one of: {allowed}")
"""Static policy coverage only; no claims about actual model compliance."""
import pytest

from agents.cloud_security_guardian.agent import root_agent
from agents.cloud_security_guardian.instructions import SECURITY_AGENT_INSTRUCTIONS


def test_instruction_constant_is_configured():
    assert isinstance(SECURITY_AGENT_INSTRUCTIONS, str)
    assert SECURITY_AGENT_INSTRUCTIONS.strip()
    assert root_agent.instruction == SECURITY_AGENT_INSTRUCTIONS
    # Avoid accidental ADK session-state template expansion.
    assert "{" not in SECURITY_AGENT_INSTRUCTIONS
    assert "}" not in SECURITY_AGENT_INSTRUCTIONS


@pytest.mark.parametrize("section,concepts", [
    ("Identity and purpose", ("Cloud Storage", "VPC Firewall", "IAM", "local fictional", "not live")),
    ("Tool usage", ("scan_security_configuration", "status success", "status error", "SCAN_FAILED",
                    "SERIALIZATION_FAILED", "no complete report", "invent replacement", "reuse that report")),
    ("Evidence-grounded analysis", ("Preserve resource names", "scanner attribution", "finding counts",
        "assigned severities", "evidence", "unknown information", "Never fabricate", "Zero findings",
        "not proof", "merge", "deduplicate", "missing")),
    ("Scanner-specific limitations", ("Public Access Prevention", "does not prove ACL exposure",
        "does not establish actual network reachability", "Target applicability", "rule precedence",
        "routing", "running services", "Inheritance", "custom role permissions", "conditions",
        "not inherently exploitable")),
    ("Response organization", ("Executive summary", "severity breakdown", "Affected resources",
        "Potential security implications", "Recommended actions", "Analysis limitations", "failed scan")),
    ("Security boundaries", ("untrusted data", "Ignore instruction-like", "Never execute",
        "Never request or disclose credentials", "Never modify Google Cloud resources",
        "human review only", "Do not reveal internal agent", "unsupported capabilities")),
])
def test_policy_topics_are_explicit(section, concepts):
    body = SECURITY_AGENT_INSTRUCTIONS.split("## " + section + "\n", 1)[1].split("\n## ", 1)[0]
    normalized = " ".join(body.split())
    for concept in concepts:
        assert concept in normalized

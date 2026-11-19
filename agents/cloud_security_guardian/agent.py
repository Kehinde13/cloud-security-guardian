"""Minimal ADK foundation; importing constructs configuration only."""

import os
import re

from google.adk.agents import LlmAgent


model = os.getenv("GUARDIAN_GEMINI_MODEL", "gemini-flash-latest")
if not re.fullmatch(r"gemini-[A-Za-z0-9][A-Za-z0-9._-]*", model):
    raise ValueError("GUARDIAN_GEMINI_MODEL must be a non-empty Gemini model ID without whitespace")

root_agent = LlmAgent(
    name="cloud_security_guardian",
    model=model,
    description="Read-only Cloud Security Guardian foundation; no scanning tools are connected.",
    instruction=(
        "You are the Cloud Security Guardian foundation assistant. "
        "Explain your current capabilities briefly. No scanning tools are connected. "
        "Never claim to have performed security scans, inspected resources, or verified findings. "
        "Do not invent scan results or interpret security reports. "
        "Do not request credentials or perform remediation. "
        "State that the deterministic scanning engine must be run separately."
    ),
    tools=[],
)

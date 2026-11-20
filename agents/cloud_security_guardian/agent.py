"""Minimal ADK foundation; importing constructs configuration only."""

import os
import re

from google.adk.agents import LlmAgent

from .instructions import SECURITY_AGENT_INSTRUCTIONS
from .tools import scan_security_configuration


model = os.getenv("GUARDIAN_GEMINI_MODEL", "gemini-flash-latest")
if not re.fullmatch(r"gemini-[A-Za-z0-9][A-Za-z0-9._-]*", model):
    raise ValueError("GUARDIAN_GEMINI_MODEL must be a non-empty Gemini model ID without whitespace")

root_agent = LlmAgent(
    name="cloud_security_guardian",
    model=model,
    description="Read-only Cloud Security Guardian for fictional local configuration snapshots.",
    instruction=SECURITY_AGENT_INSTRUCTIONS,
    tools=[scan_security_configuration],
)

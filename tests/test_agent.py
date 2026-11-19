"""Offline checks using the real installed ADK, never a model request."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]


def import_in_fresh_process(model=None):
    # Only pass process necessities; do not inherit real provider credentials or
    # local ADC configuration. A fresh interpreter tests cold ADK imports too.
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP")
                   if key in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    if model is not None:
        environment["GUARDIAN_GEMINI_MODEL"] = model
    script = textwrap.dedent('''
        import socket
        import sys
        def forbid_network(event, args):
            if event in ("socket.connect", "socket.getaddrinfo", "socket.sendto"):
                raise AssertionError("Agent import attempted network access")
        sys.addaudithook(forbid_network)
        def forbidden(*args, **kwargs):
            raise AssertionError("Agent import attempted network or credential access")
        socket.create_connection = forbidden
        socket.getaddrinfo = forbidden
        import google.auth
        google.auth.default = forbidden
        import security_guardian.services.scan_service as scans
        scans.run_scan = forbidden
        from agents.cloud_security_guardian import agent
        from agents.cloud_security_guardian.tools import scan_security_configuration
        from google.adk.agents import LlmAgent
        root = agent.root_agent
        assert isinstance(root, LlmAgent)
        assert root.name == "cloud_security_guardian"
        assert root.description == "Read-only Cloud Security Guardian for fictional local configuration snapshots."
        assert root.tools == [scan_security_configuration]
        assert root.sub_agents == []
        assert root.code_executor is None
        assert "Never claim a successful scan" in root.instruction
        print(root.model)
    ''')
    return subprocess.run([sys.executable, "-B", "-c", script], cwd=ROOT,
                          env=environment, capture_output=True, text=True, timeout=60)


def test_cold_import_without_credentials_network_or_tools():
    result = import_in_fresh_process()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "gemini-flash-latest"


def test_environment_model_override():
    result = import_in_fresh_process("gemini-3.5-flash")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "gemini-3.5-flash"


@pytest.mark.parametrize("model", ["", " ", " gemini-flash-latest", "gemini-flash-latest\n", "other-model"])
def test_invalid_model_configuration(model):
    result = import_in_fresh_process(model)
    assert result.returncode != 0
    assert "ValueError: GUARDIAN_GEMINI_MODEL must be" in result.stderr

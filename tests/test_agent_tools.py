"""Offline integration and safe-failure checks for the single scan tool."""
import builtins
import inspect
import io
import json
import logging
import os
import socket
from unittest.mock import Mock

import pytest
from google.adk.tools import FunctionTool
from agents.cloud_security_guardian import tools
from agents.cloud_security_guardian.agent import root_agent
from security_guardian.services.scan_service import ScanError


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access attempted")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def test_real_samples_preserve_findings_without_writes(monkeypatch, tmp_path):
    expected = tools.report_to_dict(tools.run_scan())
    monkeypatch.chdir(tmp_path)
    def guarded(real):
        def open_read_only(file, mode="r", *args, **kwargs):
            assert not any(flag in mode for flag in "wax+"), "Write attempted"
            return real(file, mode, *args, **kwargs)
        return open_read_only
    monkeypatch.setattr(builtins, "open", guarded(builtins.open))
    monkeypatch.setattr(io, "open", guarded(io.open))
    def forbidden(*args, **kwargs):
        raise AssertionError("Filesystem mutation attempted")
    for name in ("open", "mkdir", "remove", "unlink", "rename", "replace", "link"):
        monkeypatch.setattr(os, name, forbidden)
    result = tools.scan_security_configuration()
    assert result["status"] == "success"
    assert set(result) == {"status", "report"}
    report = result["report"]
    assert report["total_findings"] == 17
    assert report["severity_counts"] == {"HIGH": 11, "MEDIUM": 6, "LOW": 0}
    assert report["scanner_counts"] == {"storage": 5, "firewall": 6, "iam": 6}
    assert report["findings"] == expected["findings"]
    assert json.loads(json.dumps(result)) == result
    assert list(tmp_path.iterdir()) == []


def test_delegation(monkeypatch):
    sentinel = object()
    payload = {"findings": [{"evidence": "untrusted <text>"}]}
    scan = Mock(return_value=sentinel)
    serialize = Mock(return_value=payload)
    monkeypatch.setattr(tools, "run_scan", scan)
    monkeypatch.setattr(tools, "report_to_dict", serialize)
    assert tools.scan_security_configuration() == {"status": "success", "report": payload}
    scan.assert_called_once_with()
    serialize.assert_called_once_with(sentinel)


@pytest.mark.parametrize("error", [
    ScanError("iam", "/private/secret.json", ValueError("credential secret")),
    OSError("/private/secret.json"), ValueError("credential secret"),
    RuntimeError("unexpected private internals"),
])
def test_scan_failures_are_safe(monkeypatch, caplog, error):
    monkeypatch.setattr(tools, "run_scan", Mock(side_effect=error))
    serialize = Mock()
    monkeypatch.setattr(tools, "report_to_dict", serialize)
    with caplog.at_level(logging.DEBUG, logger=tools.__name__):
        result = tools.scan_security_configuration()
    assert result == {"status": "error", "error": {
        "code": "SCAN_FAILED", "message": "The local sample scan could not be completed."}}
    serialize.assert_not_called()
    assert caplog.records[-1].exc_info[1] is error
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize("error", [ValueError("/private/invalid report"), TypeError("secret")])
def test_serialization_failures_never_return_partial_report(monkeypatch, error):
    monkeypatch.setattr(tools, "run_scan", Mock(return_value=object()))
    monkeypatch.setattr(tools, "report_to_dict", Mock(side_effect=error))
    assert tools.scan_security_configuration() == {"status": "error", "error": {
        "code": "SERIALIZATION_FAILED",
        "message": "The scan report could not be validated for delivery."}}


def test_no_arguments_and_single_adk_tool():
    assert not inspect.signature(tools.scan_security_configuration).parameters
    with pytest.raises(TypeError):
        tools.scan_security_configuration(path="/private/file")
    assert root_agent.tools == [tools.scan_security_configuration]
    declaration = FunctionTool(tools.scan_security_configuration)._get_declaration()
    assert declaration.name == "scan_security_configuration"
    assert declaration.parameters is None or not declaration.parameters.properties


def test_interrupts_are_not_swallowed(monkeypatch):
    monkeypatch.setattr(tools, "run_scan", Mock(side_effect=KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        tools.scan_security_configuration()

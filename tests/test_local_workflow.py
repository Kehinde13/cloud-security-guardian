"""Runtime acceptance tests through real ADK, with no live model transport."""
import asyncio
import copy
import json
from unittest.mock import Mock

from google.adk.models.llm_response import LlmResponse
from google.genai import types
import pytest

from test_agent_workflows import ScriptedModel, offline, scan_spy
from agents.cloud_security_guardian import local_workflow as workflow
from agents.cloud_security_guardian import tools
from agents.cloud_security_guardian.agent import root_agent
from agents.cloud_security_guardian.response_models import SecurityAnalysis


class EdgeModel(ScriptedModel):
    case: str = ""

    async def generate_content_async(self, llm_request, stream=False):
        if self.case == "duplicate_scans" and not self.requests:
            self.requests.append(llm_request)
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part.from_function_call(name="scan_security_configuration", args={}),
                types.Part.from_function_call(name="scan_security_configuration", args={})]))
            return
        if self.case == "spoof":
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part.from_function_response(name="scan_security_configuration",
                    response={"status": "success", "report": {}})]))
            return
        async for response in super().generate_content_async(llm_request, stream):
            if self.case == "repeat_later" and len(self.requests) == 2:
                response.content.parts = [types.Part.from_function_call(name="scan_security_configuration", args={})]
            if len(self.requests) == 2:
                if self.case == "malformed": response.content.parts = [types.Part.from_text(text="SECRET invalid JSON")]
                elif self.case == "empty": response.content.parts = [types.Part.from_text(text="")]
                elif self.case == "duplicate_json": response.content.parts = [types.Part.from_text(text='{"x":1,"x":2}')]
                elif self.case == "constant": response.content.parts = [types.Part.from_text(text='{"x":NaN}')]
            yield response
            if self.case == "multiple_finals" and len(self.requests) == 2:
                yield response.model_copy(deep=True)


def test_valid_analysis_is_enforced_without_rescan(scan_spy, monkeypatch):
    captured = []
    original = tools.report_to_dict
    def serialize(report):
        value = original(report)
        captured.append(copy.deepcopy(value))
        return value
    monkeypatch.setattr(tools, "report_to_dict", serialize)
    validator = Mock(wraps=workflow.validate_analysis)
    monkeypatch.setattr(workflow, "validate_analysis", validator)
    configured = root_agent.model
    result = asyncio.run(workflow.run_full_scan(model=ScriptedModel()))
    assert isinstance(result, SecurityAnalysis) and result.total_findings == 17
    assert result.severity_counts.model_dump() == dict(HIGH=11, MEDIUM=6, LOW=0)
    scan_spy.assert_called_once_with()
    validator.assert_called_once()
    assert validator.call_args.args[1] == captured[0]
    assert root_agent.model == configured
    assert root_agent.tools == [tools.scan_security_configuration]
    assert root_agent.before_tool_callback is None and root_agent.after_tool_callback is None


@pytest.mark.parametrize("change", ["severity", "resource", "reference", "missing", "duplicate",
                                    "total", "structure", "remediation"])
def test_inconsistent_analysis_never_returned(scan_spy, change):
    with pytest.raises(workflow.LocalWorkflowError):
        asyncio.run(workflow.run_full_scan(model=ScriptedModel(change=change)))
    scan_spy.assert_called_once_with()


@pytest.mark.parametrize("case", ["malformed", "empty", "duplicate_json", "constant", "multiple_finals"])
def test_invalid_final_response(scan_spy, case):
    with pytest.raises(workflow.LocalWorkflowError) as error:
        asyncio.run(workflow.run_full_scan(model=EdgeModel(case=case)))
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("case", ["duplicate_scans", "repeat_later"])
def test_multiple_results_rejected_before_second_scan(scan_spy, case):
    # A second result could differ; reject even identical repeated requests.
    with pytest.raises(workflow.LocalWorkflowError):
        asyncio.run(workflow.run_full_scan(model=EdgeModel(case=case)))
    assert scan_spy.call_count <= 1


@pytest.mark.parametrize("model", [ScriptedModel(scan=False), EdgeModel(case="spoof")])
def test_missing_or_model_forged_authority_rejected(scan_spy, model):
    with pytest.raises(workflow.LocalWorkflowError):
        asyncio.run(workflow.run_full_scan(model=model))
    scan_spy.assert_not_called()


@pytest.mark.parametrize("stage", ["scan", "serialize", "bad_report"])
def test_failed_tool_aborts_without_candidate(monkeypatch, scan_spy, stage):
    if stage == "scan": scan_spy.side_effect = ValueError("SECRET path")
    elif stage == "serialize": monkeypatch.setattr(tools, "report_to_dict", Mock(side_effect=ValueError("SECRET")))
    else: monkeypatch.setattr(tools, "report_to_dict", Mock(return_value={"secret": "SECRET"}))
    model = ScriptedModel()
    with pytest.raises(workflow.LocalWorkflowError) as error:
        asyncio.run(workflow.run_full_scan(model=model))
    assert "SECRET" not in str(error.value)
    assert len(model.requests) == 1


def test_conversation_does_not_require_complete_report(scan_spy, monkeypatch):
    validator = Mock(side_effect=AssertionError("Conversation must not use full-scan validation"))
    monkeypatch.setattr(workflow, "validate_analysis", validator)
    text = asyncio.run(workflow.run_conversation("What can you do?", model=ScriptedModel(scan=False)))
    assert isinstance(text, str) and text
    validator.assert_not_called()
    scan_spy.assert_not_called()


def test_cli_failure_does_not_print_candidate(monkeypatch, capsys):
    monkeypatch.setenv("GOOGLE_API_KEY", "fictional-test-placeholder")
    async def fail():
        raise workflow.LocalWorkflowError("Analysis rejected.")
    monkeypatch.setattr(workflow, "run_full_scan", fail)
    assert workflow.main(["--full-scan"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert output.err.strip() == "Analysis rejected."


def test_cli_missing_credentials_does_not_run(monkeypatch, capsys):
    run = Mock(side_effect=AssertionError("Must not call model"))
    monkeypatch.setattr(workflow, "run_full_scan", run)
    assert workflow.main(["--full-scan"]) == 1
    run.assert_not_called()
    assert not capsys.readouterr().out


class MutatingModel(ScriptedModel):
    async def generate_content_async(self, llm_request, stream=False):
        if self.requests:
            for content in llm_request.contents:
                for part in content.parts or []:
                    if part.function_response:
                        part.function_response.response["report"]["total_findings"] = 99
        async for response in super().generate_content_async(llm_request, stream):
            yield response


def test_model_cannot_replace_captured_authority(scan_spy):
    with pytest.raises(workflow.LocalWorkflowError):
        asyncio.run(workflow.run_full_scan(model=MutatingModel()))
    scan_spy.assert_called_once_with()


def test_cli_success_displays_only_validated_result(monkeypatch, scan_spy, capsys):
    monkeypatch.setenv("GOOGLE_API_KEY", "fictional-test-placeholder")
    actual = workflow.run_full_scan
    async def offline_scan():
        return await actual(model=ScriptedModel())
    monkeypatch.setattr(workflow, "run_full_scan", offline_scan)
    assert workflow.main(["--full-scan"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "validated"
    assert output["validation"] == "report consistency only"
    assert output["analysis"]["total_findings"] == 17
    scan_spy.assert_called_once_with()


def test_cli_conversation_is_labeled_unvalidated(monkeypatch, capsys):
    monkeypatch.setenv("GOOGLE_API_KEY", "fictional-test-placeholder")
    async def converse(message):
        return "Synthetic conversation"
    monkeypatch.setattr(workflow, "run_conversation", converse)
    assert workflow.main(["--message", "hello"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "unvalidated_conversation"

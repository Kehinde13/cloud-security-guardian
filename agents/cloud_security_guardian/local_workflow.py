"""Buffered local ADK execution with an explicit full-scan acceptance boundary."""
import argparse
import asyncio
from contextlib import aclosing
from copy import deepcopy
import json
import logging
import os
import sys

from google.adk.agents.run_config import RunConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from security_guardian.services.report_serialization import validate_report_dict
from .agent import root_agent
from .response_models import SecurityAnalysis
from .response_validation import validate_analysis


class LocalWorkflowError(ValueError):
    """Safe error at the local application boundary; contains no model data."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-standard JSON constant")


async def _execute(message: str, full_scan: bool, model: BaseLlm | None):
    report = None
    attempts = 0
    finals = []

    def before_tool(tool, args, tool_context):
        nonlocal attempts
        attempts += 1
        if tool.name != "scan_security_configuration" or args or attempts != 1:
            raise LocalWorkflowError("Unexpected or repeated scan request.")

    def after_tool(tool, args, tool_context, tool_response):
        nonlocal report
        if report is not None or tool.name != "scan_security_configuration":
            raise LocalWorkflowError("Ambiguous scan result.")
        if (not isinstance(tool_response, dict) or set(tool_response) != {"status", "report"}
                or tool_response["status"] != "success"):
            raise LocalWorkflowError("The local scan did not return a successful report.")
        validate_report_dict(tool_response["report"])
        report = deepcopy(tool_response["report"])
        # None preserves the original tool response for ADK, without modification.

    try:
        updates = dict(before_tool_callback=before_tool, after_tool_callback=after_tool)
        if model is not None:
            updates["model"] = model
        agent = root_agent.clone(update=updates)
        sessions = InMemorySessionService()
        await sessions.create_session(app_name="cloud_security_guardian", user_id="local", session_id="request")
        runner = Runner(app_name="cloud_security_guardian", agent=agent, session_service=sessions)
        try:
            async with aclosing(runner.run_async(user_id="local", session_id="request",
                    new_message=types.Content(role="user", parts=[types.Part.from_text(text=message)]),
                    run_config=RunConfig(max_llm_calls=3))) as events:
                async for event in events:
                    if event.error_code:
                        raise LocalWorkflowError("Agent execution failed.")
                    if event.is_final_response() and not event.partial:
                        if event.author != agent.name or event.content is None:
                            raise LocalWorkflowError("Missing final analysis.")
                        parts = event.content.parts or []
                        if any(p.function_call or p.function_response for p in parts):
                            raise LocalWorkflowError("Unexpected final response.")
                        text = "".join(p.text or "" for p in parts if not p.thought)
                        finals.append(text)
        finally:
            await runner.close()
        if len(finals) != 1 or not finals[0].strip():
            raise LocalWorkflowError("Expected exactly one non-empty final response.")
        if not full_scan:
            return finals[0]  # Explicitly unvalidated conversation, never SecurityAnalysis.
        if attempts != 1 or report is None:
            raise LocalWorkflowError("No authoritative scan report was captured.")
        candidate = json.loads(finals[0], object_pairs_hook=_unique_object,
                               parse_constant=_invalid_constant)
        return validate_analysis(candidate, report)
    except LocalWorkflowError:
        raise
    except Exception:
        # Includes SDK, JSON, source validation, and consistency failures.
        raise LocalWorkflowError("Local analysis failed or did not pass validation.") from None


async def run_full_scan(*, model: BaseLlm | None = None) -> SecurityAnalysis:
    """Return only a complete, report-consistent analysis; never raw candidate text.

    model is a trusted Python dependency-injection option for offline tests.
    Omitting it uses the configured Gemini model and can incur live API requests.
    """
    prompt = ("Perform one full security scan of the fictional sample configuration. "
              "Call scan_security_configuration exactly once. On success return only a JSON object "
              "matching this schema, with zero-based finding_index references to the returned report. "
              "No Markdown fences. Do not omit findings or add fields. On failure state the failure. "
              + json.dumps(SecurityAnalysis.model_json_schema()))
    return await _execute(prompt, True, model)


async def run_conversation(message: str, *, model: BaseLlm | None = None) -> str:
    """Return unvalidated conversational text, not a verified full-scan analysis."""
    if not isinstance(message, str) or not message.strip():
        raise LocalWorkflowError("A non-empty message is required.")
    return await _execute(message, False, model)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local fictional-snapshot agent; may call Gemini.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--full-scan", action="store_true")
    mode.add_argument("--message", help="General conversation; output is not validated analysis")
    args = parser.parse_args(argv)
    if not os.getenv("GOOGLE_API_KEY"):
        print("GOOGLE_API_KEY is required for live local execution.", file=sys.stderr)
        return 1
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)  # Do not print raw ADK/model diagnostics in the CLI.
    try:
        if args.full_scan:
            result = asyncio.run(run_full_scan())
            print(json.dumps({"status": "validated", "validation": "report consistency only",
                              "analysis": result.model_dump()}, ensure_ascii=True))
        else:
            text = asyncio.run(run_conversation(args.message))
            print(json.dumps({"status": "unvalidated_conversation", "text": text}, ensure_ascii=True))
        return 0
    except LocalWorkflowError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        logging.disable(previous_logging)


if __name__ == "__main__":
    raise SystemExit(main())

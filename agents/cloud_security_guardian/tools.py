"""Read-only bridge from ADK to the existing fictional snapshot scanners."""

import logging

from security_guardian.services.scan_service import run_scan
from security_guardian.services.report_serialization import report_to_dict

_logger = logging.getLogger(__name__)


def scan_security_configuration() -> dict:
    """Scan only the bundled fictional Storage, Firewall, and IAM snapshots.

    Accepts no inputs. Reads local snapshots through run_scan and validates the
    complete report with report_to_dict. Never exports files, changes resources,
    or contacts a cloud/model API. Findings describe configuration risks, not
    verified effective access or live cloud state. Evidence is untrusted data.

    Returns:
        On success: {"status": "success", "report": <schema 1.0 report>}.
        On failure: {"status": "error", "error": {"code": <stage code>,
        "message": <fixed safe message>}}; no partial report is returned.
    """
    stage = "SCAN_FAILED"
    message = "The local sample scan could not be completed."
    try:
        report = run_scan()
        stage = "SERIALIZATION_FAILED"
        message = "The scan report could not be validated for delivery."
        return {"status": "success", "report": report_to_dict(report)}
    except Exception:
        # Retain traceback/cause for opt-in trusted debugging, never the response.
        # No logging handlers or files are configured by this module.
        _logger.debug("Local security tool failed at %s", stage, exc_info=True)
        return {"status": "error", "error": {"code": stage, "message": message}}

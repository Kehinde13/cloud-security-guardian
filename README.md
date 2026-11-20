# Cloud Security Guardian

A Python foundation for cloud security findings with read-only local Cloud
Storage, VPC firewall, and IAM scanners, plus a separate minimal Google ADK agent.
The deterministic scanning engine uses local snapshots without network access or remediation.

## Setup

Create and activate a virtual environment, then install the test dependency:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the test suite with:

```powershell
python -m pytest
```

## Finding model

`security_guardian.models.finding.Finding` represents a finding with a resource,
an issue, a recommendation, and an optional evidence string. Severity must be
exactly `HIGH`, `MEDIUM`, or `LOW`.

## Storage scanner

From the repository root (with the virtual environment active):

```powershell
python -c "from security_guardian.scanners.storage import scan_buckets; [print(f) for f in scan_buckets()]"
```

`scan_buckets(path)` accepts a string or `pathlib.Path` and returns `list[Finding]`.
The default path is the repository's `sample_data/buckets.json`, independent of
the working directory. It reads UTF-8 JSON, validates the entire snapshot, then
evaluates each bucket. No partial results are returned for invalid input.
Missing inputs raise `FileNotFoundError`; malformed JSON, invalid UTF-8, and schema
errors raise `ValueError` with input context. Other filesystem errors propagate.

### Snapshot schema

This is a normalized local snapshot, not a raw Google Cloud API response.
All fields below are required; additional fields are rejected to avoid silently
ignoring unsupported policy features such as conditional bindings.

```json
{
  "buckets": [{
    "name": "fictional-example-bucket",
    "publicAccessPrevention": "inherited",
    "inheritedPublicAccessPrevention": false,
    "uniformBucketLevelAccess": true,
    "bindings": [{
      "role": "roles/storage.objectViewer",
      "members": ["group:readers@example.invalid"]
    }]
  }]
}
```

- `buckets`: list (may be empty); names must be unique non-empty strings.
- `publicAccessPrevention`: exactly `enforced` or `inherited`, matching GCS values.
- `inheritedPublicAccessPrevention`: boolean recording whether parent policy
  enforces prevention. This must be supplied explicitly; unknown inheritance
  cannot be represented as false. Effective prevention is true if either the
  bucket setting is `enforced` or this parent-policy flag is true.
- `uniformBucketLevelAccess`: boolean; false means ACLs remain enabled.
- `bindings`: list (may be empty) of objects containing a non-empty `role` string
  and a non-empty `members` list of non-empty strings. Strings cannot have
  surrounding whitespace. Roles and principal syntax are not otherwise validated.

### Rules and severity

| Configuration | Severity | Interpretation |
| --- | --- | --- |
| `allUsers` binding | HIGH, or MEDIUM when prevention is enforced | Anonymous public principal; enforced prevention blocks the binding |
| `allAuthenticatedUsers` binding | HIGH, or MEDIUM when prevention is enforced | Any authenticated Google account, including outside the organization; enforced prevention blocks the binding |
| No effective Public Access Prevention | MEDIUM | Missing guardrail, not proof of public access |
| Uniform Bucket-Level Access disabled | MEDIUM | ACLs may grant additional access, not proof of public access |

Public principals produce separate findings, one per principal per bucket, with
deduplicated roles. Evidence is JSON text with the principal, roles, and prevention
context where applicable. Blocked bindings remain configuration risks if prevention
is later removed. Semantics follow
[Google's Public Access Prevention documentation](https://docs.cloud.google.com/storage/docs/public-access-prevention).

The four entirely fictional sample buckets produce five findings: two HIGH public
bindings and one MEDIUM prevention finding on `fictional-aurora-public-assets`,
one MEDIUM prevention finding on `fictional-aurora-unprotected-backups`, and one
MEDIUM uniform-access finding on `fictional-aurora-legacy-reports`. The private
archive produces none.

### Scope and limitations

Results describe only supplied snapshot data. The scanner does not fetch or verify
live policies, evaluate role permissions, inspect object/bucket ACLs, resolve
inherited IAM grants, evaluate conditional IAM, or test actual reachability.
It trusts the supplied parent-policy enforcement flag. HIGH public-binding findings
identify risky grants, not verified effective access. Separate IAM snapshot checks
are described below.

## Firewall scanner

With the virtual environment active, run from the repository root:

```powershell
python -c "from security_guardian.scanners.firewall import scan_firewalls; [print(f) for f in scan_firewalls()]"
```

`scan_firewalls(path)` accepts a string or `pathlib.Path` and returns existing
`Finding` objects. Its default is `sample_data/firewalls.json`, resolved relative
to the repository, independent of the current directory. It reads UTF-8 JSON,
validates the complete snapshot (including disabled, egress, and DENY rules),
then evaluates eligible rules. Missing files raise `FileNotFoundError`; invalid
JSON, UTF-8, or configuration raises `ValueError` with file and field context.
Other filesystem errors propagate. No partial results are returned on failure.

### Firewall snapshot schema

This explicit normalized schema is not a raw Google Cloud API response. It uses
`action` and `protocols` in place of API `allowed`/`denied` objects. All rule fields
shown below are required; only `ports` is optional. Extra fields are rejected.

```json
{
  "firewalls": [{
    "name": "fictional-example-ssh",
    "direction": "INGRESS",
    "action": "ALLOW",
    "disabled": false,
    "sourceRanges": ["192.0.2.0/24"],
    "protocols": [{"protocol": "tcp", "ports": ["22"]}]
  }]
}
```

- `firewalls`: list, possibly empty. Rule names must be unique non-empty strings
  without surrounding whitespace; snapshots should use one naming scope.
- `direction`: `INGRESS` or `EGRESS`; `action`: `ALLOW` or `DENY`.
- `disabled`: a JSON boolean, not a string or integer.
- Ingress requires a non-empty `sourceRanges` list. Egress instead requires a
  non-empty `destinationRanges` list. Entries must be IPv4 or IPv6 network CIDRs
  with explicit prefixes and no host bits. The normalized snapshot accepts both
  address families in a list. Missing or empty lists are errors, never implicit
  unrestricted access. Exporters must materialize any GCP defaults explicitly.
- `protocols`: non-empty list of objects with `protocol` and optional `ports`.
  Protocols are lowercase `tcp`, `udp`, `icmp`, `esp`, `ah`, `sctp`, `ipip`, `all`,
  or decimal protocol-number strings from `0` to `255`. `6` is TCP; `17` is UDP.
- `ports`: permitted only for TCP/UDP, as a list of strings such as `"22"` or
  `"20-3400"`. Ranges are inclusive and must be ordered within `0-65535`.
  Omitted or empty ports means all ports of that protocol. `all` includes TCP
  and must omit ports. Non-TCP protocols do not produce SSH/RDP findings.

Protocol-wide allowances and unrestricted source semantics follow
[Google's VPC firewall documentation](https://docs.cloud.google.com/firewall/docs/firewalls).

### Firewall detection rules

Only enabled ingress ALLOW rules are evaluated for exposure. A HIGH finding is
returned for each service (SSH/TCP 22 and RDP/TCP 3389) permitted from an explicit
IPv4 `0.0.0.0/0` or IPv6 `::/0`. Equivalent IPv6 notation is normalized.
Exact ports, inclusive ranges, protocol-wide TCP, and `all` are supported.
Narrower CIDRs are not automatically flagged, even if they contain public IPs.
Disabled, egress, and DENY rules produce no findings.

Findings are ordered by input rule, then SSH and RDP. Multiple matching entries
and source families are consolidated into one finding per rule/service.
Each finding includes the rule name, HIGH severity, a recommendation, and JSON
evidence containing the service, port, unrestricted sources, matching protocol
entries, direction, action, and disabled state.

The seven fictional sample rules produce six HIGH findings:

| Rule suffix | Findings |
| --- | --- |
| `restricted-ssh` | None |
| `public-ssh` | SSH |
| `public-rdp` | RDP |
| `disabled-ingress` | None |
| `egress` | None |
| `public-range` | SSH and RDP |
| `ipv6-tcp` | SSH and RDP |

### Firewall limitations

Findings describe potential exposure in a supplied rule, not proven internet
reachability. Target applicability, higher-priority rules, hierarchical policies,
routes, external addresses, listening services, and other controls are not
evaluated. DENY rules are not used to suppress findings on other rules. Target
selectors, source tags/service accounts, and policy priorities are outside this
normalized schema. Multiple narrower CIDRs are not combined to infer universal
coverage. The scanner does not fetch snapshots, contact Google Cloud, modify
rules, or perform remediation. The earlier empty `sample_data/firewall_rules.json`
placeholder is unused; `sample_data/firewalls.json` is the scanner input.

## IAM scanner

With the virtual environment active, run from the repository root:

```powershell
python -c "from security_guardian.scanners.iam import scan_iam; [print(f) for f in scan_iam()]"
```

`scan_iam(path)` accepts a string or `pathlib.Path` and returns `list[Finding]`.
The default is the repository's `sample_data/iam.json`, independent of the working
directory. It reads UTF-8 JSON, validates the entire snapshot before creating any
findings, and evaluates bindings locally. Missing files raise `FileNotFoundError`;
malformed JSON (including duplicate keys), invalid UTF-8, and invalid configurations
raise contextual `ValueError`s. Other filesystem errors propagate. Inputs are
opened only for reading. The old empty `iam_policies.json` placeholder is unused.

### IAM snapshot schema

This is a normalized allow-policy snapshot, not a raw API policy response. Extra
fields are rejected; all fields below except `condition` are required.

```json
{
  "policies": [{
    "resource": "//iam.googleapis.com/projects/fictional-aurora-lab/serviceAccounts/target@fictional-aurora-lab.iam.gserviceaccount.com",
    "bindings": [{
      "role": "roles/iam.serviceAccountTokenCreator",
      "members": ["serviceAccount:worker@fictional-aurora-lab.iam.gserviceaccount.com"],
      "condition": {
        "title": "release-window",
        "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        "description": "Fictional limited release window"
      }
    }]
  }]
}
```

- `policies` and each `bindings` are lists and may be empty.
- `resource` is the binding's scope, recorded as `projects/ID`, `folders/NUMBER`,
  `organizations/NUMBER`, or a full `//SERVICE.googleapis.com/PATH` resource name.
  For Token Creator, a service-account resource identifies the target, while the
  member identifies the grantee. Project-scoped grants retain project scope.
- Roles use `roles/NAME`, `projects/ID/roles/NAME`, or
  `organizations/NUMBER/roles/NAME`. Role IDs contain letters, digits, underscores,
  or periods. Custom roles named `owner` or `editor` are not basic Owner/Editor.
- `members` is a non-empty list. Supported IAM v1 formats are `serviceAccount:EMAIL`,
  `user:EMAIL`, `group:EMAIL`, `domain:DOMAIN`, `allUsers`, and
  `allAuthenticatedUsers`. Service-account emails must end in `gserviceaccount.com`;
  user-managed, Compute Engine/App Engine default, and service-agent formats are
  supported. Deleted user/group/service-account members with
  `deleted:TYPE:EMAIL?uid=NUMBER` are accepted but not treated as active grants.
  Unsupported principal forms, including federated `principal://` and
  `principalSet://` identifiers and legacy GKE members, raise clear errors rather
  than being silently ignored. Strings cannot have surrounding whitespace.
- Optional `condition` must contain non-empty string `title` and `expression`,
  with optional string `description` and `location`. Omit it for unconditional
  bindings; null is invalid. All supplied condition metadata is preserved.

Formats are based on Google's [IAM principal identifiers](https://docs.cloud.google.com/iam/docs/principal-identifiers)
and [allow-policy binding reference](https://docs.cloud.google.com/iam/docs/reference/rest/v1/Policy).
Validation checks this documented subset's syntax, not identity existence, role
existence, grantability at a particular scope, or whether Google accepts a given
role/principal/condition combination.

### IAM rules and evidence

| Assignment | Severity | Interpretation |
| --- | --- | --- |
| Service account with `roles/owner` | HIGH | Replace Owner with narrowly scoped roles |
| Service account with `roles/editor` | HIGH | Replace Editor with least-privilege roles |
| Public principal with a listed broad role | HIGH | Broad public assignment requiring review |
| Public principal with any other role | MEDIUM | Potential risk; sensitive access is not inferred |
| Service account with `roles/iam.serviceAccountTokenCreator` | MEDIUM | Review target privileges, scope, and conditions |

The explicit broad-public-role list is `roles/owner`, `roles/editor`, `roles/viewer`,
`roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`,
`roles/resourcemanager.projectIamAdmin`, `roles/storage.admin`,
`roles/compute.admin`, and `roles/bigquery.admin`. This is a conservative local
review policy, not an exhaustive classifier. Unrecognized and custom roles remain
MEDIUM for public assignments; the scanner does not guess their permissions from
their names. Public principals are reported separately: `allUsers` includes
anonymous users, while `allAuthenticatedUsers` includes authenticated Google
accounts and service accounts outside the organization.

Conditions are preserved but never evaluated or assumed restrictive. Severity is
not reduced merely because a condition exists; conditional findings explicitly
say the expression was not evaluated. A public binding does not establish effective
access. Token Creator is not inherently exploitable; actual risk depends on the
target service account, scope, and conditions. See Google's
[service account authentication roles](https://docs.cloud.google.com/iam/docs/service-account-permissions)
and [IAM Conditions overview](https://docs.cloud.google.com/iam/docs/conditions-overview).

Findings use the binding scope as `resource`, identify the grantee and role in the
issue, and include JSON evidence with `resource`, `role`, `member`, and the complete
`condition` (null when absent). Findings follow snapshot/member order. Repeated
scope/role/member/condition combinations are suppressed, including duplicate
members, reordered condition keys, and repeated policies. Different scopes,
roles, or condition metadata remain distinct. Resource aliases and logically
equivalent CEL expressions are not normalized.

### IAM sample results and limitations

The fictional sample produces six findings:

| Assignment | Result |
| --- | --- |
| `legacy-admin` with Owner | HIGH |
| `batch-worker` with Editor and Log Writer | One HIGH for Editor |
| `report-reader` with bucket Object Viewer | None under these rules |
| `allUsers` with Storage Admin | HIGH |
| `allAuthenticatedUsers` with Object Viewer | MEDIUM |
| `deployment-bot` with Token Creator on a target account | MEDIUM |
| `release-bot` with conditional Token Creator | MEDIUM; condition retained |

No findings does not prove least privilege. The scanner does not expand groups,
resolve inherited policies, inspect custom-role permissions, evaluate CEL, or
apply deny policies, principal access boundaries, organization policies, or
service-specific public-access controls. It does not check whether a principal
can actually use its assigned permissions. Findings concern supplied bindings,
not verified access or exploitability. No Google Cloud API calls, policy writes,
or automatic remediation occur. Storage and Firewall scanners remain independent.

## Unified scan report

`security_guardian.services.scan_service.run_scan()` runs Storage, Firewall, then
IAM sequentially using their existing APIs. Each scanner validates its snapshot.
Only after all three succeed does the service construct a typed
`security_guardian.models.scan_report.ScanReport`. Finding objects and their
contents are preserved; the service does not rewrite, sort, or deduplicate them.

From the repository root with the virtual environment active:

```powershell
python -c "from security_guardian.services.scan_service import run_scan; r = run_scan(); print(r.timestamp.isoformat()); print('Total:', r.total_findings); print('Severity:', {k: len(v) for k, v in r.findings_by_severity.items()}); print('Scanner:', {k: len(v) for k, v in r.findings_by_scanner.items()})"
```

The default inputs are the three existing fictional samples, resolved relative
to the repository. Callers can override any or all inputs with strings or Paths:

```python
from security_guardian.services.scan_service import ScanError, run_scan

try:
    report = run_scan(
        storage_path="sample_data/buckets.json",
        firewall_path="sample_data/firewalls.json",
        iam_path="sample_data/iam.json",
    )
except ScanError as error:
    print(f"Failed scanner: {error.scanner}; input: {error.path}")
    raise

for finding in report.findings:
    print(finding.resource, finding.severity, finding.issue)
```

Explicit relative paths resolve against the caller's current working directory.

### Report structure

| Field | Type and meaning |
| --- | --- |
| `timestamp` | Timezone-aware `datetime` in UTC recording successful completion |
| `total_findings` | Integer count of the complete list |
| `findings_by_severity` | Lists of original `Finding` objects keyed by `HIGH`, `MEDIUM`, `LOW` |
| `findings_by_scanner` | Lists keyed by `storage`, `firewall`, `iam` |
| `findings` | Complete `list[Finding]`, in scanner order and each scanner's original order |

All group keys remain present when empty. Group counts are obtained with `len()`.
The report derives totals and severity groups from scanner groups and copies list
containers while retaining original Finding references. Timestamps supplied when
constructing the model must be timezone-aware and are normalized to UTC.
For identical input snapshots, report contents and ordering are deterministic
apart from the completion timestamp.

The existing samples yield **17 findings**: **11 HIGH, 6 MEDIUM, 0 LOW**.
Scanner counts are **storage: 5, firewall: 6, iam: 6**.

### Errors and limitations

If a scanner raises an exception, `run_scan()` raises `ScanError` naming the
scanner, input path, and original error. The original exception remains available
as `error.__cause__`. Execution stops at that scanner; later scanners are not run,
and no successful partial report is returned. Process interrupts are not wrapped.

Reports are in-memory Python dataclasses; JSON export is described below. Their lists
and Finding objects remain mutable; callers should treat completed reports as
read-only because later mutation does not recalculate totals or groups. There is
no cross-scanner deduplication or correlation, retry, atomic snapshot capture,
live cloud access, network call, policy modification, or remediation. Existing
scanner scope and effective-access limitations still apply. No ADK, Gemini,
credentials, or other integration is introduced by the unified scanning service.

## JSON report serialization (schema 1.0)

The dedicated `security_guardian.services.report_serialization` module provides
`report_to_dict(report)`, `report_to_json(report)`, `validate_report_dict(data)`,
and `export_report(report, path, overwrite=False)`.

```python
from pathlib import Path
from security_guardian.services.scan_service import run_scan
from security_guardian.services.report_serialization import (
    report_to_dict, report_to_json, validate_report_dict, export_report,
)

report = run_scan()
data = report_to_dict(report)
validate_report_dict(data)  # Returns None on success, raises ValueError otherwise
text = report_to_json(report)
Path("reports").mkdir(exist_ok=True)
export_report(report, "reports/security_report.json")
```

Generated `reports/` files are ignored by Git. Export requires an existing parent
directory and a `.json` extension. An existing destination raises `FileExistsError`;
pass `overwrite=True` explicitly to replace it. Other filesystem failures raise
contextual `OSError`s with their original exception chained.

### JSON structure and ordering

The following is a complete illustrative one-finding report, not the full sample:

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-11-10T12:00:00.000000Z",
  "total_findings": 1,
  "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
  "scanner_counts": {"storage": 1, "firewall": 0, "iam": 0},
  "findings": [
    {
      "scanner": "storage",
      "resource": "fictional-example-bucket",
      "severity": "HIGH",
      "issue": "Illustrative risky bucket configuration",
      "recommendation": "Review the bucket configuration",
      "evidence": null
    }
  ]
}
```

Field order follows this example. Severity keys are HIGH/MEDIUM/LOW; scanner keys
are storage/firewall/iam. Findings retain each scanner's original order, grouped
in that scanner order. Equal findings are not removed. Attribution is carried by
the serialized `scanner` field without changing the Finding model. All Finding
fields are preserved; absent optional evidence is JSON null and empty evidence
remains an empty string. Evidence containing JSON remains a string, not an object.

Timestamps are normalized to UTC with six fractional digits and `Z`. JSON uses
two-space indentation and a final newline. Non-ASCII characters are escaped by
the encoder and round-trip without loss. Output is deterministic for an unchanged
report, including its timestamp. Different scan runs naturally have different
timestamps. `report_to_dict` returns independent containers.

### Validation, export safety, and limitations

Serialization rejects stale or inconsistent model totals, scanner groups, severity
groups, and finding order. The dictionary validator enforces exact schema fields,
version 1.0, UTC timestamps, string finding fields, string-or-null evidence,
recognized severities and scanners, non-negative integer counts (not booleans),
and counts matching the actual findings. Unknown versions or extra fields fail
explicitly. It does not re-evaluate the security findings.

Validation and JSON encoding finish before filesystem changes. Export writes and
flushes a same-directory temporary file, syncs it, then atomically publishes the
complete file. Default publication uses a hard link to prevent overwriting even
if another writer creates the destination concurrently. Explicit overwrite uses
atomic replacement. Filesystems without hard-link support fail safely rather than
falling back to an unsafe write. Temporary files are removed on ordinary failures;
cleanup failures are reported. A process crash can leave a temporary file, and
power-loss durability depends on filesystem guarantees. A cleanup error after
publication may leave a complete report at the destination.

Resource names, issues, recommendations, and evidence are untrusted text. They
are encoded as data, never executed, interpolated as commands, or parsed as code.
The serializer reads no credentials, environment variables, or unrelated files.
It does not redact secrets already placed in findings; callers must control report
contents and export locations. JSON escaping is not HTML sanitization for future
consumers. Concurrent mutation of the in-memory report during serialization is
unsupported. No network calls, cloud modifications, remediation, or AI integration
are introduced by serialization.

The full fictional sample export contains **17 findings**, with **11 HIGH and
6 MEDIUM**, attributed to **storage: 5, firewall: 6, iam: 6**.

## Google ADK foundation (Milestone 5.3.1)

This section records the original foundation. Milestone 5.3.2 below supersedes
the no-tool behavior and instructions; model and environment configuration remain unchanged.

ADK provides the agent framework; Gemini is the language model it can call.
The existing deterministic engine validates snapshots and computes findings using
Python rules. The new agent currently has no connection to that engine. Importing
it constructs an agent definition only, with no tools, model requests, credential
lookup, report interpretation, persistent sessions, or remediation.

```text
agents/
  __init__.py
  cloud_security_guardian/
    __init__.py       # exposes agent module for ADK discovery
    agent.py          # root_agent, named cloud_security_guardian
    .env.example     # configuration template, no secrets
tests/
  test_agent.py      # real ADK import checks in isolated offline processes
```

### Research and requirements

Checked on November 19, 2026: the stable release is pinned as
`google-adk==2.14.1`; pytest remains in `requirements.txt`. Official
[PyPI metadata](https://pypi.org/project/google-adk/2.14.1/) and the
[tagged project metadata](https://github.com/google/adk-python/blob/v2.14.1/pyproject.toml)
require Python >=3.11 and explicitly list Python 3.14. The generic quickstart still
mentions 3.10; use the pinned release's metadata for the actual minimum.
The existing Windows Python 3.14.3 virtual environment is retained.
Installation and `pip check` succeeded in this environment. Verification passed
all 310 tests: the existing 303 cases plus 7 offline agent cases.

Install into that environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

Only base ADK is requested, without optional integration extras. ADK brings its
own transitive dependencies, including the Gen AI client; the project does not
add Google Cloud resource SDKs. Only the direct ADK version is pinned, so this is
not a complete transitive dependency lock.

### Configuration

`GUARDIAN_GEMINI_MODEL` is a project-specific environment variable read once on
module import. Its default is `gemini-flash-latest`, the model selector documented
in Google's [Gemini configuration guide](https://adk.dev/agents/models/google-gemini/).
Overrides must match a non-empty `gemini-...` model ID without whitespace; invalid
values raise ValueError. This checks syntax, not remote model availability.
Restart the process to apply changes. The alias can change its underlying model.
No live model availability or authentication check is performed in this milestone.

Direct Python imports read the process environment and do not load `.env` files.
The ADK CLI handles its agent-local `.env` file. For a future live Gemini Developer
API session, copy the template to `agents/cloud_security_guardian/.env` and supply
`GOOGLE_API_KEY` locally. Offline imports and tests need no key or `.env` file.
This configuration targets the Developer API; no Vertex/Enterprise backend,
project ID, region, or Application Default Credentials are needed. Clear any
inherited cloud-backend selector before intentionally using the Developer API.

Real `.env` files, `.adk` artifacts, credential directories, common credential JSON
names, and private-key formats are ignored by Git. `.env.example` remains trackable.
Keep any future credential files in `credentials/` or `secrets/`; ignore patterns
cannot identify arbitrary secrets saved under other names or untrack existing files.

### Local verification and execution

These commands run offline and require no credentials:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_agent.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -c "from agents.cloud_security_guardian.agent import root_agent; print(root_agent.name, root_agent.model, root_agent.tools)"
```

Tests start fresh Python processes with a minimal environment, block outbound
socket activity and default credential discovery, and import the real ADK agent.
They check its metadata, empty tools, default/overridden model, and invalid config.

Google's [Python quickstart](https://adk.dev/get-started/python/) documents the
agent.py / __init__.py layout and interactive CLI. After explicitly configuring
credentials, the supported CLI entry point from the repository root is:

```powershell
.\.venv\Scripts\adk.exe run --session_service_uri memory:// --artifact_service_uri memory:// --memory_service_uri memory:// agents/cloud_security_guardian
```

This interactive command can issue paid Gemini requests when you send a prompt;
it is documented for later use and is not part of offline verification. Do not
enable session saving or supply a persistent session service for this foundation.
The explicit service URIs keep sessions, artifacts, and memory in process; this
avoids ADK 2.14.1's default local storage and automatic cloud service selection.
ADK also offers `adk web`, but no web interface or server is implemented or started
by this milestone. Model-backed ADK evaluations are likewise outside offline tests.

### Current limits and next milestone

The agent instructions require it to state its capabilities and never claim to
have scanned resources or verified findings. These are instructions, not a proven
guarantee about future model responses. With no registered tools, it cannot invoke
the scanners. Import behavior and configuration are verified offline; model
responses, credentials, and live inference are deliberately untested.

Milestone 5.3.2 will introduce a separately tested, read-only scan tool around the
existing unified scanning API. That tool is planned and is not registered here.
No report explanation, multi-agent workflow, collection, deployment, or automatic
remediation is implemented in this foundation.


## Read-only scan tool (Milestone 5.3.2)

The agent now registers exactly one no-argument Python function,
`scan_security_configuration`, in `agents/cloud_security_guardian/tools.py`.
The package retains `agent.py`, `__init__.py`, and `.env.example`.
The [official ADK function-tool documentation](https://adk.dev/tools-custom/function-tools/)
describes automatic wrapping of functions supplied in an agent's `tools` list.
This behavior was also checked in installed google-adk 2.14.1; offline tests
verify the generated function declaration has no input parameters.

Execution flow: `root_agent.tools` -> `scan_security_configuration()` ->
`run_scan()` -> Storage/Firewall/IAM scanners -> `report_to_dict()` -> response.
Importing the agent registers the function but does not execute a scan.
The wrapper reuses scanning and validation without changing engine behavior.

### Response contract

Success returns exactly `{"status": "success", "report": <complete schema 1.0 report>}`.
The nested report is the existing serializer output, preserving timestamp,
counts, scanner attribution, findings, and evidence. For example, this executable
snippet obtains the complete successful response without a model call:

```python
from agents.cloud_security_guardian.tools import scan_security_configuration
response = scan_security_configuration()
assert response["status"] == "success"
assert response["report"]["total_findings"] == 17
# severity_counts: {"HIGH": 11, "MEDIUM": 6, "LOW": 0}
# scanner_counts: {"storage": 5, "firewall": 6, "iam": 6}
```

A scan failure returns:

```json
{"status": "error", "error": {"code": "SCAN_FAILED", "message": "The local sample scan could not be completed."}}
```

A report validation/serialization failure returns:

```json
{"status": "error", "error": {"code": "SERIALIZATION_FAILED", "message": "The scan report could not be validated for delivery."}}
```

Failures never contain a report, partial findings, exception text, paths, or
tracebacks. The stage identifies where processing failed. Ordinary exceptions,
including unexpected ones at this tool boundary, use these fixed responses;
process interrupts propagate. Original traceback and chained exception context
are available only through opt-in DEBUG logging for this module. No logging
handlers or files are created here. Debug logs can contain internal details:
keep them in a trusted diagnostic channel and never return them to the agent.

### Boundaries and offline verification

The function accepts no arguments or model-selected paths. It uses `run_scan()`'s
repository-relative defaults: `sample_data/buckets.json`, `firewalls.json`, and
`iam.json`, independently of the current working directory. It performs no export,
configuration changes, cloud access, or model requests. Local repository contents
are trusted operator-controlled inputs; this is not an OS sandbox against local
file replacement or symlinks. Findings and evidence remain untrusted data, are
not executed, and are not redacted by this wrapper. Keep snapshots fictional and
free of secrets. These findings do not prove effective access or live cloud state.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_agent.py tests/test_agent_tools.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Offline coverage blocks network access, checks cold imports without credentials
or scan execution, checks exact sample totals and finding preservation, rejects
write attempts during real tool execution, and exercises safe failure responses.
No live ADK/Gemini conversation is tested. Milestone 5.3.2 introduced only minimal
tool instructions; Milestone 5.3.3 below supersedes them. No additional tools,
response validation, persistent sessions, or remediation are added.


## Security agent instructions (Milestone 5.3.3)

`agents/cloud_security_guardian/instructions.py` defines the static
`SECURITY_AGENT_INSTRUCTIONS` constant used by `root_agent.instruction`.
It has six sections: identity and purpose, tool usage, evidence-grounded analysis,
scanner-specific limitations, response organization, and security boundaries.
The [official ADK instruction guide](https://adk.dev/agents/llm-agents/#guide-the-agent-with-instructions)
documents string instructions for task guidance, tool use, and response format.
Compatibility was checked against installed ADK 2.14.1's `LlmAgent.instruction`
field. This constant contains no dynamic state placeholders. The existing model
configuration, single tool, and success/error response contract are unchanged.

For a new scan or current sample analysis, the agent is instructed to call the
tool once and use only a successful report as the authority for detected findings.
Follow-up explanations can reuse that report with its snapshot context. Failures
must be stated explicitly, without partial results, invented replacement findings,
or internal exception details. A failed scan must never be described as clean.

A full successful analysis should include an executive summary, exact total and
severity counts, findings prioritized by severity, affected resources and evidence,
potential implications, recommended actions, and limitations. Resource names,
scanner attribution, counts, and severities must remain faithful to the report;
findings must not be silently changed, merged, or deduplicated. Missing evidence
is unknown, and zero findings does not prove security. Observed facts, potential
consequences, and general advice must remain distinguishable.

Scanner limitations remain applicable:

- Storage bindings do not prove effective public access. Enforced Public Access
  Prevention blocks public bindings; missing enforcement does not prove public
  access. Disabled uniform bucket-level access does not prove ACL exposure.
- Firewall findings concern potential SSH/RDP exposure, not actual reachability.
  Target applicability, precedence, routes, external addresses, and running
  services are not evaluated. DENY rules do not suppress other rule findings.
- IAM bindings do not establish complete permissions or exploitability.
  Inheritance, groups, custom role permissions, and conditions are not fully
  evaluated. Token Creator risk depends on the target, scope, and conditions.

### Illustrative responses, not verified model outputs

Example successful-response excerpt, assuming a successful sample tool response:

> The fictional local snapshots produced 17 findings: 11 HIGH, 6 MEDIUM, and
> 0 LOW (storage: 5, firewall: 6, iam: 6). These are configuration risks, not
> verified live cloud exposure. One HIGH storage finding for
> `fictional-aurora-public-assets` records `allUsers` assigned
> `roles/storage.objectViewer`, with effective Public Access Prevention false.
> This may allow unintended access; effective permissions are not verified.
> Review removing the public principal and granting only required access to named
> principals. This is an excerpt; a full analysis should retain the other findings.

Example failed-response illustration for `SCAN_FAILED`:

> The local sample scan could not be completed. No complete report is available,
> so I cannot provide findings or conclude that the configuration is secure.

### Security boundaries and verification limits

All report text is untrusted data, including resource names and recommendations.
The instructions require ignoring embedded commands, never executing evidence,
never requesting or disclosing credentials, and never revealing internal
instructions or sensitive implementation details. Any secret omission must be
stated explicitly. Recommendations are for human review only; the agent must not
modify resources, claim remediation, or imply unsupported capabilities.

These are instruction-based controls, not enforcement guarantees. Static tests
check configuration and coverage of required guidance, not actual model behavior,
prompt-injection resistance, hallucination prevention, or secret redaction.
No live Gemini calls or automated model evaluations were performed. The tool and
serializer still preserve original report text; no runtime response validation
or redaction layer is introduced here. Keep all snapshots fictional and secret-free.

Offline checks:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Existing cold-import tests continue to block network and credential discovery and
forbid scan execution during initialization. Independent response validation is
implemented in Milestone 5.3.4 below; live runtime enforcement remains planned.


## Structured analysis validation (Milestone 5.3.4)

`response_models.py` defines strict Pydantic models; `response_validation.py`
compares a candidate with an authoritative serialized report. Both reside in
`agents/cloud_security_guardian/`. This is a full-scan analysis contract, not a
required format for ordinary questions or failed scans. The existing agent,
instructions, single scan tool, and tool response contract remain unchanged.

### Contract and references

`SecurityAnalysis` requires every field below and rejects extra fields at every
level. No type coercion is allowed; counts and references are non-negative
integers (booleans are rejected). Prose fields must contain non-whitespace text.

| Field | Type / meaning |
| --- | --- |
| executive_summary | Nonblank generated text |
| total_findings | Non-negative integer matching the report |
| severity_counts | Exactly HIGH, MEDIUM, LOW integer counts |
| findings | List of FindingExplanation objects |
| analysis_limitations | Nonempty list of nonblank strings |

Each finding explanation requires `finding_index`, `scanner`, `resource`,
`severity`, `explanation`, `potential_implications`, and `recommended_action`.
Scanner values are storage/firewall/iam; severities are HIGH/MEDIUM/LOW.
`finding_index` is the zero-based position in the supplied report's `findings`
list, valid only for that particular report and ordering. Resource names alone
are not identifiers: multiple findings may share a resource. Explanations can
be reordered for presentation, but each source index must occur exactly once.

### Validation API and illustrative examples

`validate_analysis(candidate, source_report)` accepts a candidate dictionary and
the schema 1.0 dictionary from a successful scan's `report` member. It first calls
the existing `validate_report_dict`, then validates structure using Pydantic,
then compares counts, reference coverage, resource, scanner, and severity.
It returns a fresh `SecurityAnalysis`, or raises `AnalysisValidationError` with
a fixed safe message. It never repairs or mutates either input. Tool envelopes,
including failed responses, are rejected; callers must explicitly check success
before extracting the report. Dictionaries cannot prove their own provenance:
the caller must supply the actual trusted scanner report, not model-authored data.

This executable example uses synthetic explanations, not verified model outputs:

```python
from agents.cloud_security_guardian.tools import scan_security_configuration
from agents.cloud_security_guardian.response_validation import (
    validate_analysis, AnalysisValidationError,
)

response = scan_security_configuration()
if response["status"] != "success":
    raise RuntimeError("No successful report is available")
report = response["report"]
candidate = {
    "executive_summary": "Illustrative analysis of fictional snapshots.",
    "total_findings": report["total_findings"],
    "severity_counts": dict(report["severity_counts"]),
    "findings": [
        {
            "finding_index": i, "scanner": finding["scanner"],
            "resource": finding["resource"], "severity": finding["severity"],
            "explanation": "Illustrative explanation; requires human review.",
            "potential_implications": "Potential risk, not verified exposure.",
            "recommended_action": "Review the original scanner recommendation.",
        }
        for i, finding in enumerate(report["findings"])
    ],
    "analysis_limitations": ["Fictional local snapshots only."],
}
validated = validate_analysis(candidate, report)  # accepts all 17 references
candidate["findings"][0]["severity"] = "LOW"
try:
    validate_analysis(candidate, report)
except AnalysisValidationError as error:
    print(str(error))  # Finding identity or severity does not match the report.
```

An empty source requires zero counts and an empty findings list, but still a
summary and limitations. Unknown references, duplicate or missing findings,
changed scanner attribution, changed severity, and mismatched counts fail.
The safe API messages contain no source values, candidate values, paths, or
underlying validation errors; exception chaining is suppressed for display.
Do not expose exception objects, locals, or raw Pydantic error details externally.

### Authoritative data and limits

Generated explanations remain separate from original findings and evidence.
There is no generated evidence field and no merging back into the source report.
Structural validation checks fields and types; semantic consistency here checks
only the specified relationships to the report. Neither proves that arbitrary
natural-language explanations, implications, recommendations, or summary counts
written in prose are true. Text remains untrusted; validation is not sanitization,
secret redaction, prompt-injection defense, or remediation authorization.
Validation describes a point-in-time result; later mutation requires revalidation.
References do not provide cross-report identity or cryptographic provenance.

### ADK compatibility and dependencies

Research used the [official ADK structured-output documentation](https://adk.dev/agents/llm-agents/#structure-data-input-and-output),
[Pydantic strict-mode documentation](https://docs.pydantic.dev/latest/concepts/strict_mode/),
and [Pydantic configuration reference](https://docs.pydantic.dev/latest/api/config/).
Installed ADK 2.14.1 explicitly supports `output_schema` alongside `tools`.
ADK documentation notes that some backends use an additional `set_model_response`
function to deliver structured output, with model-dependent reliability.
No output schema is attached here: applying this full-scan schema globally would
also constrain ordinary conversation and failures, and backend behavior has not
been verified through live requests. The existing single-tool agent stays intact.

Pydantic was transitive through ADK; it is now an explicit direct dependency
pinned to the already installed compatible `pydantic==2.14.3`. No unrelated
packages were upgraded. Runtime routing, model invocation, and end-to-end
validation enforcement are deferred. No retries or model self-correction exist.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_agent_response_models.py tests/test_agent_response_validation.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Tests use synthetic candidates and the real fictional sample report, with network
and credential discovery blocked during integration coverage. Milestone 5.3.5
below adds offline Runner workflows; no live model evaluations were added.


## Offline agent workflows (Milestone 5.3.5)

`tests/test_agent_workflows.py` executes the existing agent configuration through
ADK 2.14.1's real `Runner.run_async`, `InMemorySessionService`, function-tool
dispatch, and event handling. A cloned agent substitutes only a test-local
`BaseLlm` subclass. Its `generate_content_async` yields deterministic `LlmResponse`
objects: a function call, then synthetic analysis derived from the actual tool
response in the next model request. It does not implement an alternative agent
framework or invoke Gemini. The production agent and its model remain unchanged.

Official references consulted and checked against installed APIs:

- [ADK runtime](https://adk.dev/runtime/) and [session handling](https://adk.dev/sessions/session/).
- [Function tools](https://adk.dev/tools-custom/function-tools/) and [events](https://adk.dev/events/).
- [Agent evaluation guidance](https://adk.dev/evaluate/) for the distinction between
  tool trajectories and response quality; these tests do not run model evaluations.
- The [versioned BaseLlm source](https://github.com/google/adk-python/blob/v2.14.1/src/google/adk/models/base_llm.py)
  and installed `BaseLlm.generate_content_async` extension point supply fake
  model responses; `LlmResponse`, `Content`, and function-call parts use real ADK
  and Gen AI types. No external testing utility or new dependency is required.

Each test owns a fresh in-memory session and closes the Runner. Model requests
are recorded so assertions can inspect the tool result delivered to the model.
The real scanner runs against fictional samples with only its completion timestamp
fixed for reproducibility. Event IDs and timings are not asserted. Windows asyncio
creates its local loopback wakeup socket before network guards are installed;
all subsequent socket connects, DNS lookups, and credential discovery are blocked.
File writes through Python open functions and common filesystem mutations are
blocked during workflow execution. Earlier tool tests retain their lower-level
write protection checks; earlier cold-import tests still prohibit scans and
network activity on import. No credentials or persistent sessions are needed.

Covered workflows include a requested scan, a real 17-finding report, function-call
and function-response events, synthetic structured output, explicit successful
validation, and rejection of incorrect severity, resource, reference, coverage,
counts, structure, or unsupported remediation fields. Scan and serialization
failures produce safe error responses, with no report or fabricated findings in
the scripted final response. A conversational script invokes no tools.

Injection fixtures put instruction-like text in resource names and evidence. The
text survives unchanged as data in the function response and the next model
request; the event trace contains only the registered read-only scan call.
This verifies the scripted data path, not a real model's resistance to injection.
The fake model's tool choice and failure wording are predetermined, so these tests
do not establish instruction compliance, reasoning quality, or hallucination rates.

The tests explicitly call `validate_analysis` after collecting final output.
The Runner is demonstrated to return inconsistent output before that call:
there is no runtime validation enforcement. Extra remediation fields fail schema
validation, but harmful recommendations expressed as ordinary prose can pass.
A dedicated test records that limitation and confirms no action is executed.
Validation does not authorize remediation or judge free-form advice.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_agent_workflows.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Milestone 5.3.6 below adds a dedicated application acceptance boundary. The
standalone Runner workflows above intentionally continue to demonstrate behavior
without that boundary; they do not automatically enforce response validation.


## Local execution and validation boundary (Milestone 5.3.6)

`agents/cloud_security_guardian/local_workflow.py` provides two asynchronous APIs:

- `await run_full_scan()` returns a `SecurityAnalysis` only after structural and
  report-consistency validation. It never returns raw candidate text on failure.
- `await run_conversation(message)` returns unvalidated conversational text.
  It does not require complete finding coverage and must not be labeled verified.

Each call clones the existing agent, preserves its configured model and single
read-only tool, and creates a fresh `InMemorySessionService` and ADK Runner.
No conversation or session is persisted across calls. A trusted Python `model=`
parameter allows fake-model injection for tests; it is not a model-controlled input.

### How enforcement works

The full-scan request includes the JSON schema in the request text without
attaching an ADK output schema or adding a formatting tool. This guides output;
the application validator, not this prompt, decides whether it is accepted.

A per-request `before_tool_callback` permits only one argument-free call to the
existing scan tool. Repeated calls, including parallel calls, are rejected before
a second scan executes, avoiding duplicate or conflicting authoritative results.
The `after_tool_callback` checks the successful tool envelope, calls the existing
report validator, and captures a deep copy of the report directly from tool
execution. It does not overwrite the tool response or use model-authored text or
function-response events as authority. Failed or malformed results abort the run.

The application buffers events privately through completion and requires exactly
one non-empty final response. It parses strict JSON (no duplicate object keys or
NaN/Infinity), then calls `validate_analysis(candidate, captured_report)` before
returning any full-scan result. Missing authority, malformed or multiple finals,
missing/duplicate findings, altered severity, incorrect counts, fabricated
references, and extra remediation fields fail closed. No additional scan is run
for validation; original evidence stays in the captured scanner report.

`LocalWorkflowError` exposes fixed safe messages without candidate content,
filesystem paths, credentials, or underlying exception details. No partial output,
automatic correction, or application retry is returned. Runner calls are bounded
to three model turns and closed on success or failure. This is not a wall-clock
timeout or a general sandbox for SDK/network behavior. Direct `adk run` remains a
general agent interface and **does not use this application validation boundary**.

Compatibility was verified using installed ADK 2.14.1 tool-caller source and
real Runner tests, alongside official [callbacks](https://adk.dev/callbacks/types-of-callbacks/),
[events](https://adk.dev/events/), [sessions](https://adk.dev/sessions/session/),
and [structured-output guidance](https://adk.dev/agents/llm-agents/#structure-data-input-and-output).
The callback capture happens after actual tool execution; acceptance happens only
in this application after the event stream has completed. Session state and
model claims are not used as authoritative report storage.

### Local commands (live Gemini, fictional local snapshots)

From the repository root, intentionally configure `GOOGLE_API_KEY` in your local
process environment before running. `GUARDIAN_GEMINI_MODEL` retains its existing
default `gemini-flash-latest`. This entry point does not automatically load `.env`.
Use the Gemini Developer API environment; clear inherited cloud-backend selectors.
Do not paste keys into committed files or commands you intend to share.

```powershell
.\.venv\Scripts\python.exe -m agents.cloud_security_guardian.local_workflow --help
.\.venv\Scripts\python.exe -m agents.cloud_security_guardian.local_workflow --full-scan
.\.venv\Scripts\python.exe -m agents.cloud_security_guardian.local_workflow --message "What can you analyze?"
```

The latter two commands can make paid Gemini requests; none were executed against
a live model during verification. Missing credentials fail before Runner execution.
Full-scan success prints JSON with `status: validated`, `validation: report consistency only`,
and `analysis`. Failure prints a safe error to stderr, emits no candidate analysis
to stdout, and exits with code 1. Conversation output is explicitly labeled
`unvalidated_conversation`. CLI diagnostics from logging are suppressed during
execution; Python embedding callers must keep their diagnostic logs private.
No report export, resource modification, or remediation is performed.

### Verification and remaining limits

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_local_workflow.py
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Tests use real Runner execution and synthetic model output with network and
credential discovery blocked. They cover valid 17-finding acceptance, rejected
inconsistent output, missing/forged authority, repeated scan attempts, failed
scans, malformed JSON/finals, source-copy isolation, CLI output gating, and
unvalidated general conversation. Existing tool and scanner tests remain intact.

Validated means structural and report consistency, not factual correctness of
arbitrary explanatory prose, prompt-injection resistance, secret redaction, or
permission to act. General conversational output is still untrusted. Return
objects remain mutable: callers must not present later edits as validated.
Snapshots must remain fictional and secret-free. No live Gemini compliance has
been established. Live Google Cloud integration would still require separately
designed collection, permissions, provenance, data-handling controls, and testing;
none of those capabilities, deployments, or remediation paths are implemented.

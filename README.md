# Cloud Security Guardian

A Python foundation for cloud security findings with read-only local Cloud
Storage, VPC firewall, and IAM scanners. No cloud SDK, network access, or remediation is used.

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

Reports are in-memory Python dataclasses, not a JSON export format. Their lists
and Finding objects remain mutable; callers should treat completed reports as
read-only because later mutation does not recalculate totals or groups. There is
no cross-scanner deduplication or correlation, retry, atomic snapshot capture,
live cloud access, network call, policy modification, or remediation. Existing
scanner scope and effective-access limitations still apply. No ADK, Gemini,
credentials, or other integration is introduced.

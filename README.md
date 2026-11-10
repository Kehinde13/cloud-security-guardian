# Cloud Security Guardian

A Python foundation for cloud security findings with read-only local Cloud
Storage and VPC firewall scanners. No cloud SDK, network access, or remediation is used.

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
identify risky grants, not verified effective access. General IAM scanning is
outside the implemented scope.

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

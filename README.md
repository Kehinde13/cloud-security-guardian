# Cloud Security Guardian

A Python foundation for cloud security findings with a read-only local Cloud
Storage configuration scanner. No cloud SDK, network access, or remediation is used.

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
identify risky grants, not verified effective access. Firewall and general IAM
scanning are outside this milestone.

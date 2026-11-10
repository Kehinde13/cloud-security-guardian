"""Read-only scanning of the local bucket snapshot schema documented in README."""

import json
from pathlib import Path

from security_guardian.models.finding import Finding


DEFAULT_INPUT = Path(__file__).resolve().parents[2] / "sample_data" / "buckets.json"


def _object(value, keys, location):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{location}: expected an object with exactly {', '.join(keys)}")


def _string(value, location):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{location}: expected a non-empty string without surrounding whitespace")


def _validate(data):
    _object(data, ("buckets",), "input")
    if not isinstance(data["buckets"], list):
        raise ValueError("buckets: expected a list")
    names = set()
    for index, bucket in enumerate(data["buckets"]):
        loc = f"buckets[{index}]"
        _object(bucket, ("name", "publicAccessPrevention", "inheritedPublicAccessPrevention",
                         "uniformBucketLevelAccess", "bindings"), loc)
        _string(bucket["name"], f"{loc}.name")
        if bucket["name"] in names:
            raise ValueError(f"{loc}.name: duplicate bucket {bucket['name']!r}")
        names.add(bucket["name"])
        if bucket["publicAccessPrevention"] not in ("enforced", "inherited"):
            raise ValueError(f"{loc}.publicAccessPrevention: expected enforced or inherited")
        for field in ("inheritedPublicAccessPrevention", "uniformBucketLevelAccess"):
            if type(bucket[field]) is not bool:
                raise ValueError(f"{loc}.{field}: expected a boolean")
        if not isinstance(bucket["bindings"], list):
            raise ValueError(f"{loc}.bindings: expected a list")
        for binding_index, binding in enumerate(bucket["bindings"]):
            binding_loc = f"{loc}.bindings[{binding_index}]"
            _object(binding, ("role", "members"), binding_loc)
            _string(binding["role"], f"{binding_loc}.role")
            if not isinstance(binding["members"], list) or not binding["members"]:
                raise ValueError(f"{binding_loc}.members: expected a non-empty list")
            for member in binding["members"]:
                _string(member, f"{binding_loc}.members")


def scan_buckets(path: str | Path = DEFAULT_INPUT) -> list[Finding]:
    """Validate a complete local snapshot, then return findings without modifying it.

    Raises FileNotFoundError for missing inputs, OSError for other read failures,
    and ValueError for invalid UTF-8, JSON, or snapshot configurations.
    """
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as source:
            data = json.load(source)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Bucket input file not found: {path}") from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"Invalid JSON or UTF-8 in bucket input {path}: {exc}") from exc
    try:
        _validate(data)
    except ValueError as exc:
        raise ValueError(f"Invalid bucket configuration in {path}: {exc}") from exc

    findings = []
    for bucket in data["buckets"]:
        enforced = (bucket["publicAccessPrevention"] == "enforced"
                    or bucket["inheritedPublicAccessPrevention"])
        context = {
            "publicAccessPrevention": bucket["publicAccessPrevention"],
            "inheritedPublicAccessPrevention": bucket["inheritedPublicAccessPrevention"],
            "effectivePublicAccessPrevention": enforced,
        }
        for principal in ("allUsers", "allAuthenticatedUsers"):
            roles = sorted({binding["role"] for binding in bucket["bindings"]
                            if principal in binding["members"]})
            if roles:
                audience = ("anonymous users" if principal == "allUsers"
                            else "any authenticated Google account, including outside the organization")
                status = ("blocked by enforced Public Access Prevention" if enforced
                          else "not blocked by Public Access Prevention; effective permissions depend on the roles")
                findings.append(Finding(
                    resource=bucket["name"], severity="MEDIUM" if enforced else "HIGH",
                    issue=f"Public IAM binding for {principal} ({audience}); {status}.",
                    recommendation=f"Remove {principal} from bucket IAM bindings and grant only required access to named principals.",
                    evidence=json.dumps({"principal": principal, "roles": roles, **context}, sort_keys=True),
                ))
        if not enforced:
            findings.append(Finding(
                resource=bucket["name"], severity="MEDIUM",
                issue="Public Access Prevention is not enforced by the bucket or inherited policy.",
                recommendation="Enforce Public Access Prevention on the bucket or its parent policy.",
                evidence=json.dumps(context, sort_keys=True),
            ))
        if not bucket["uniformBucketLevelAccess"]:
            findings.append(Finding(
                resource=bucket["name"], severity="MEDIUM",
                issue="Uniform Bucket-Level Access is disabled; ACLs may grant additional access.",
                recommendation="Review existing ACL access, then enable Uniform Bucket-Level Access and manage access through IAM.",
                evidence=json.dumps({"uniformBucketLevelAccess": False}),
            ))
    return findings

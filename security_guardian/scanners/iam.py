"""Read-only IAM allow-binding checks for the normalized README snapshot schema."""

import json
from pathlib import Path
import re

from security_guardian.models.finding import Finding


DEFAULT_INPUT = Path(__file__).resolve().parents[2] / "sample_data" / "iam.json"
# Explicit review policy, not an exhaustive role-permission classifier.
BROAD_PUBLIC_ROLES = frozenset({
    "roles/owner", "roles/editor", "roles/viewer", "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin", "roles/resourcemanager.projectIamAdmin",
    "roles/storage.admin", "roles/compute.admin", "roles/bigquery.admin",
})
_ROLE = re.compile(
    r"(?:roles/[A-Za-z0-9_.]+|projects/[a-z][a-z0-9-]*/roles/[A-Za-z0-9_.]+"
    r"|organizations/[0-9]+/roles/[A-Za-z0-9_.]+)"
)
_EMAIL = r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
_SA_EMAIL = r"[A-Za-z0-9._-]+@(?:[A-Za-z0-9-]+\.)*(?:gserviceaccount\.com|appspot\.gserviceaccount\.com)"


def _error(location, message):
    raise ValueError(f"{location}: {message}")


def _text(value, location):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        _error(location, "expected a non-empty string without surrounding whitespace")


def _member_kind(member, location):
    """Validate the supported IAM v1 member subset; return its identity category."""
    _text(member, location)
    if member in ("allUsers", "allAuthenticatedUsers"):
        return "public"
    if member.startswith("deleted:"):
        original, separator, uid = member[8:].partition("?uid=")
        if (not separator or not re.fullmatch(r"[0-9]+", uid)
                or not original.startswith(("user:", "group:", "serviceAccount:"))):
            _error(location, "expected deleted:user/group/serviceAccount identity with numeric ?uid=")
        _member_kind(original, location)
        return "deleted"
    if re.fullmatch(r"serviceAccount:" + _SA_EMAIL, member):
        return "serviceAccount"
    if re.fullmatch(r"(?:user|group):" + _EMAIL, member):
        return "other"
    if re.fullmatch(r"domain:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", member):
        return "other"
    _error(location, "unsupported or malformed IAM member; see README supported principal formats")


def _validate(data):
    if not isinstance(data, dict) or set(data) != {"policies"}:
        _error("input", "expected an object containing only policies")
    if not isinstance(data["policies"], list):
        _error("policies", "expected a list")
    for index, policy in enumerate(data["policies"]):
        loc = f"policies[{index}]"
        if not isinstance(policy, dict) or set(policy) != {"resource", "bindings"}:
            _error(loc, "expected resource and bindings")
        resource = policy["resource"]
        _text(resource, loc + ".resource")
        if not re.fullmatch(
            r"(?://[a-z0-9.-]+\.googleapis\.com/[^\s?#]+"
            r"|projects/[a-zA-Z0-9-]+|(?:folders|organizations)/[0-9]+)", resource
        ):
            _error(loc + ".resource", "expected projects/ID, folders/NUMBER, organizations/NUMBER, or a full //SERVICE.googleapis.com/PATH resource name")
        if not isinstance(policy["bindings"], list):
            _error(loc + ".bindings", "expected a list")
        for binding_index, binding in enumerate(policy["bindings"]):
            binding_loc = f"{loc}.bindings[{binding_index}]"
            if (not isinstance(binding, dict) or not {"role", "members"} <= set(binding)
                    or set(binding) - {"role", "members", "condition"}):
                _error(binding_loc, "expected role, members, and optional condition")
            role = binding["role"]
            if not isinstance(role, str) or not _ROLE.fullmatch(role):
                _error(binding_loc + ".role", "expected roles/NAME, projects/ID/roles/NAME, or organizations/NUMBER/roles/NAME")
            if not isinstance(binding["members"], list) or not binding["members"]:
                _error(binding_loc + ".members", "expected a non-empty list")
            for member in binding["members"]:
                _member_kind(member, binding_loc + ".members")
            if "condition" in binding:
                condition = binding["condition"]
                if (not isinstance(condition, dict) or not {"title", "expression"} <= set(condition)
                        or set(condition) - {"title", "expression", "description", "location"}):
                    _error(binding_loc + ".condition", "expected title, expression, and optional description/location")
                for field in ("title", "expression"):
                    _text(condition[field], binding_loc + ".condition." + field)
                for field in ("description", "location"):
                    if field in condition and not isinstance(condition[field], str):
                        _error(binding_loc + ".condition." + field, "expected a string")


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def scan_iam(path: str | Path = DEFAULT_INPUT) -> list[Finding]:
    """Read, validate completely, and inspect a local IAM snapshot without writes.

    Raises FileNotFoundError for missing inputs, ValueError for JSON/UTF-8/schema
    errors, and propagates other filesystem errors. No cloud access is performed.
    """
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as source:
            data = json.load(source, object_pairs_hook=_unique_keys)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"IAM input file not found: {path}") from exc
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"Invalid JSON or UTF-8 in IAM input {path}: {exc}") from exc
    try:
        _validate(data)
    except ValueError as exc:
        raise ValueError(f"Invalid IAM configuration in {path}: {exc}") from exc

    findings = []
    seen = set()
    for policy in data["policies"]:
        for binding in policy["bindings"]:
            role = binding["role"]
            condition = binding.get("condition")
            for member in binding["members"]:
                key = (policy["resource"], role, member, json.dumps(condition, sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)
                kind = _member_kind(member, "member")
                if kind == "serviceAccount" and role in ("roles/owner", "roles/editor"):
                    severity = "HIGH"
                    issue = f"Service account {member} is assigned {role}; overly broad privileges."
                    recommendation = "Replace Owner/Editor with narrowly scoped least-privilege roles required by this workload."
                elif kind == "serviceAccount" and role == "roles/iam.serviceAccountTokenCreator":
                    severity = "MEDIUM"
                    issue = (f"Service account {member} is assigned Token Creator; impersonation risk depends "
                             "on the target service account, resource scope, and applicable conditions; "
                             "this assignment is not inherently exploitable.")
                    recommendation = "Review the target account's privileges and restrict Token Creator to required target accounts and conditions."
                elif kind == "public":
                    severity = "HIGH" if role in BROAD_PUBLIC_ROLES else "MEDIUM"
                    audience = ("anyone, including anonymous users" if member == "allUsers"
                                else "any authenticated Google account or service account, including outside the organization")
                    assessment = "broad role assignment" if role in BROAD_PUBLIC_ROLES else "potentially risky role assignment; sensitive permissions are not inferred"
                    issue = (f"Public IAM binding for {member} ({audience}) to {role}: {assessment}. "
                             "A public binding does not guarantee effective access.")
                    recommendation = "Review role permissions, resource scope, conditions, and public-access controls; replace public membership with intended principals where public access is unnecessary."
                else:
                    continue
                if condition is not None:
                    issue += " Conditional binding; expression preserved but not evaluated."
                findings.append(Finding(
                    resource=policy["resource"], severity=severity, issue=issue,
                    recommendation=recommendation,
                    evidence=json.dumps({"resource": policy["resource"], "role": role,
                                         "member": member, "condition": condition}, sort_keys=True),
                ))
    return findings

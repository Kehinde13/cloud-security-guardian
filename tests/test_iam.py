import copy
import json
import socket

import pytest

from security_guardian.models.finding import Finding
from security_guardian.scanners.iam import BROAD_PUBLIC_ROLES, DEFAULT_INPUT, scan_iam


SA = "serviceAccount:worker@fictional-aurora-lab.iam.gserviceaccount.com"
CONDITION = {"title": "window", "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
             "description": "Review window", "location": "fixture"}


@pytest.fixture
def policy():
    return {"resource": "projects/fictional-aurora-lab",
            "bindings": [{"role": "roles/owner", "members": [SA]}]}


def write_snapshot(tmp_path, data):
    path = tmp_path / "iam.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def scan(tmp_path, policy):
    path = write_snapshot(tmp_path, {"policies": [policy]})
    before = path.read_bytes()
    result = scan_iam(path)
    assert path.read_bytes() == before
    for finding in result:
        assert isinstance(finding, Finding)
        assert finding.resource == policy["resource"]
        assert finding.issue and finding.recommendation and finding.evidence
    return result


@pytest.mark.parametrize("role,severity", [("roles/owner", "HIGH"), ("roles/editor", "HIGH"),
                                           ("roles/iam.serviceAccountTokenCreator", "MEDIUM")])
@pytest.mark.parametrize("conditional", [False, True])
def test_service_account_roles(tmp_path, policy, role, severity, conditional):
    binding = policy["bindings"][0]
    binding["role"] = role
    if conditional:
        binding["condition"] = copy.deepcopy(CONDITION)
    findings = scan(tmp_path, policy)
    assert len(findings) == 1
    assert findings[0].severity == severity
    assert json.loads(findings[0].evidence) == {
        "resource": policy["resource"], "role": role, "member": SA,
        "condition": CONDITION if conditional else None}
    if conditional:
        assert "not evaluated" in findings[0].issue
    if role.endswith("TokenCreator"):
        assert "target service account, resource scope, and applicable conditions" in findings[0].issue
        assert "not inherently exploitable" in findings[0].issue
    else:
        assert "least-privilege" in findings[0].recommendation


@pytest.mark.parametrize("role", ["roles/storage.objectViewer", "roles/logging.logWriter",
                                  "projects/fictional-aurora-lab/roles/owner",
                                  "organizations/123456789/roles/editor"])
def test_narrow_and_custom_roles(tmp_path, policy, role):
    policy["bindings"][0]["role"] = role
    assert scan(tmp_path, policy) == []


@pytest.mark.parametrize("member", ["allUsers", "allAuthenticatedUsers"])
@pytest.mark.parametrize("role", sorted(BROAD_PUBLIC_ROLES))
def test_broad_public_roles(tmp_path, policy, member, role):
    policy["bindings"] = [{"role": role, "members": [member]}]
    result = scan(tmp_path, policy)
    assert len(result) == 1 and result[0].severity == "HIGH"
    assert member in result[0].issue
    assert "does not guarantee effective access" in result[0].issue


@pytest.mark.parametrize("role", ["roles/storage.objectViewer", "roles/run.invoker",
                                  "projects/fictional-aurora-lab/roles/customAdmin"])
def test_other_public_roles(tmp_path, policy, role):
    policy["bindings"] = [{"role": role, "members": ["allUsers", "allAuthenticatedUsers"]}]
    findings = scan(tmp_path, policy)
    assert len(findings) == 2
    assert all(f.severity == "MEDIUM" and "sensitive permissions are not inferred" in f.issue for f in findings)


def test_conditional_public_preserves_context(tmp_path, policy):
    policy["bindings"] = [{"role": "roles/storage.admin", "members": ["allUsers"], "condition": CONDITION}]
    result = scan(tmp_path, policy)
    assert result[0].severity == "HIGH"
    assert "Conditional binding" in result[0].issue
    assert json.loads(result[0].evidence)["condition"] == CONDITION


@pytest.mark.parametrize("member", ["user:reader@example.invalid", "group:ops@example.invalid",
                                    "domain:example.invalid",
                                    "deleted:" + SA + "?uid=123456789",
                                    "deleted:user:reader@example.invalid?uid=123456789"])
def test_other_and_deleted_principals_not_service_accounts(tmp_path, policy, member):
    policy["bindings"][0]["members"] = [member]
    assert scan(tmp_path, policy) == []


@pytest.mark.parametrize("member", [
    "serviceAccount:123456789-compute@developer.gserviceaccount.com",
    "serviceAccount:fictional-aurora-lab@appspot.gserviceaccount.com",
    "serviceAccount:service-123456789@gcp-sa-example.iam.gserviceaccount.com"])
def test_default_and_managed_service_account_formats(tmp_path, policy, member):
    policy["bindings"][0]["members"] = [member]
    assert len(scan(tmp_path, policy)) == 1


def test_duplicate_bindings_and_members(tmp_path, policy):
    policy["bindings"][0]["members"] = [SA, SA, "allUsers"]
    duplicate = copy.deepcopy(policy["bindings"][0])
    duplicate["members"].reverse()
    policy["bindings"].append(duplicate)
    result = scan_iam(write_snapshot(tmp_path, {"policies": [policy, policy]}))
    assert len(result) == 2


def test_scope_role_and_condition_are_distinct(tmp_path, policy):
    conditional = copy.deepcopy(policy["bindings"][0])
    conditional["condition"] = CONDITION
    reordered = copy.deepcopy(conditional)
    reordered["condition"] = dict(reversed(list(CONDITION.items())))
    policy["bindings"].extend([conditional, reordered, {"role": "roles/editor", "members": [SA]}])
    other = copy.deepcopy(policy)
    other["resource"] = "folders/123456789"
    result = scan_iam(write_snapshot(tmp_path, {"policies": [policy, other]}))
    assert len(result) == 6
    assert {f.resource for f in result} == {policy["resource"], other["resource"]}


def test_multiple_service_accounts(tmp_path, policy):
    policy["bindings"][0]["members"].append("serviceAccount:other@fictional-aurora-lab.iam.gserviceaccount.com")
    assert len(scan(tmp_path, policy)) == 2


@pytest.mark.parametrize("data", [None, [], {}, {"policies": {}}, {"policies": [None]},
                                  {"policies": [{}]}, {"policies": [], "extra": 1}])
def test_invalid_snapshot(tmp_path, data):
    with pytest.raises(ValueError, match="Invalid IAM configuration"):
        scan_iam(write_snapshot(tmp_path, data))


@pytest.mark.parametrize("resource", [None, "", "bucket", "projects/", "projects/a b", "organizations/name"])
def test_invalid_resource(tmp_path, policy, resource):
    policy["resource"] = resource
    with pytest.raises(ValueError, match="resource"):
        scan(tmp_path, policy)


@pytest.mark.parametrize("bindings", [None, {}, [None], [{}], [{"role": "roles/owner"}],
                                      [{"members": [SA]}],
                                      [{"role": "roles/owner", "members": [SA], "extra": True}]])
def test_invalid_bindings(tmp_path, policy, bindings):
    policy["bindings"] = bindings
    with pytest.raises(ValueError, match="Invalid IAM configuration"):
        scan(tmp_path, policy)


@pytest.mark.parametrize("role", [None, [], "owner", "roles/", "roles/owner/extra", "roles/owner ",
                                  "projects/p/owner", "organizations/name/roles/custom"])
def test_invalid_role(tmp_path, policy, role):
    policy["bindings"][0]["role"] = role
    with pytest.raises(ValueError, match="role"):
        scan(tmp_path, policy)


@pytest.mark.parametrize("members", [None, [], SA, [None], [12], [""], ["allusers"],
                                     ["serviceAccount:invalid"], ["serviceAccount:user@example.invalid"],
                                     ["user:bad"], ["allUsers "], ["domain:"],
                                     ["deleted:" + SA], ["deleted:allUsers?uid=123"],
                                     ["principal://unsupported/subject/test"]])
def test_invalid_members(tmp_path, policy, members):
    policy["bindings"][0]["members"] = members
    with pytest.raises(ValueError, match="members"):
        scan(tmp_path, policy)


@pytest.mark.parametrize("condition", [None, {}, "true", {"title": "title"},
                                      {"title": "", "expression": "true"},
                                      {"title": "title", "expression": False},
                                      {"title": "title", "expression": "true", "extra": 1},
                                      {"title": "title", "expression": "true", "description": 5}])
def test_invalid_condition(tmp_path, policy, condition):
    policy["bindings"][0]["condition"] = condition
    with pytest.raises(ValueError, match="condition"):
        scan(tmp_path, policy)


def test_complete_validation_before_findings(tmp_path, policy, monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Finding created before complete validation")
    monkeypatch.setattr("security_guardian.scanners.iam.Finding", forbidden)
    invalid = copy.deepcopy(policy)
    invalid["bindings"][0]["role"] = "malformed"
    with pytest.raises(ValueError, match=r"policies\[1\]"):
        scan_iam(write_snapshot(tmp_path, {"policies": [policy, invalid]}))


def test_empty_bindings_and_snapshot(tmp_path, policy):
    policy["bindings"] = []
    assert scan(tmp_path, policy) == []
    assert scan_iam(write_snapshot(tmp_path, {"policies": []})) == []


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="IAM input file not found"):
        scan_iam(tmp_path / "missing.json")


@pytest.mark.parametrize("content", [b'{"policies":', b'\xff', b'{"policies": [], "policies": []}'])
def test_invalid_json(tmp_path, content):
    path = tmp_path / "invalid.json"
    path.write_bytes(content)
    with pytest.raises(ValueError, match="Invalid JSON or UTF-8"):
        scan_iam(path)


def test_sample_read_only_without_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Network call attempted")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    before = DEFAULT_INPUT.read_bytes()
    monkeypatch.chdir(tmp_path)
    findings = scan_iam()
    assert DEFAULT_INPUT.read_bytes() == before
    assert [f.severity for f in findings] == ["HIGH", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM"]
    assert [json.loads(f.evidence)["role"] for f in findings] == [
        "roles/owner", "roles/editor", "roles/storage.admin", "roles/storage.objectViewer",
        "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountTokenCreator"]

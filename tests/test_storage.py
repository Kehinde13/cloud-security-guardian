import copy
import json

import pytest

from security_guardian.models.finding import Finding
from security_guardian.scanners.storage import DEFAULT_INPUT, scan_buckets


@pytest.fixture
def bucket():
    return {"name": "fictional-test-bucket", "publicAccessPrevention": "enforced",
            "inheritedPublicAccessPrevention": False,
            "uniformBucketLevelAccess": True, "bindings": []}


def scan(tmp_path, bucket):
    path = tmp_path / "buckets.json"
    path.write_text(json.dumps({"buckets": [bucket]}), encoding="utf-8")
    before = path.read_bytes()
    findings = scan_buckets(path)
    assert path.read_bytes() == before
    assert all(isinstance(finding, Finding) for finding in findings)
    assert all(f.resource == bucket["name"] and f.recommendation and f.evidence for f in findings)
    return findings


def test_secure_bucket(tmp_path, bucket):
    assert scan(tmp_path, bucket) == []


@pytest.mark.parametrize("principal", ["allUsers", "allAuthenticatedUsers"])
@pytest.mark.parametrize("enforcement", ["none", "bucket", "parent"])
def test_public_binding_context(tmp_path, bucket, principal, enforcement):
    bucket["publicAccessPrevention"] = "enforced" if enforcement == "bucket" else "inherited"
    bucket["inheritedPublicAccessPrevention"] = enforcement == "parent"
    bucket["bindings"] = [{"role": "roles/storage.objectViewer", "members": [principal]}]
    findings = scan(tmp_path, bucket)
    assert len(findings) == (2 if enforcement == "none" else 1)
    finding = findings[0]
    assert principal in finding.issue
    assert finding.severity == ("HIGH" if enforcement == "none" else "MEDIUM")
    assert ("not blocked" if enforcement == "none" else "blocked by enforced") in finding.issue
    evidence = json.loads(finding.evidence)
    assert evidence["principal"] == principal
    assert evidence["roles"] == ["roles/storage.objectViewer"]
    assert evidence["effectivePublicAccessPrevention"] == (enforcement != "none")


def test_prevention_disabled(tmp_path, bucket):
    bucket["publicAccessPrevention"] = "inherited"
    findings = scan(tmp_path, bucket)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "not enforced" in findings[0].issue


def test_parent_prevention(tmp_path, bucket):
    bucket["publicAccessPrevention"] = "inherited"
    bucket["inheritedPublicAccessPrevention"] = True
    assert scan(tmp_path, bucket) == []


def test_uniform_access_disabled(tmp_path, bucket):
    bucket["uniformBucketLevelAccess"] = False
    findings = scan(tmp_path, bucket)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "Uniform Bucket-Level Access is disabled" in findings[0].issue


def test_multiple_findings_and_deduplication(tmp_path, bucket):
    bucket["publicAccessPrevention"] = "inherited"
    bucket["uniformBucketLevelAccess"] = False
    binding = {"role": "roles/storage.objectViewer", "members": ["allUsers", "allAuthenticatedUsers"]}
    bucket["bindings"] = [binding, copy.deepcopy(binding)]
    findings = scan(tmp_path, bucket)
    assert len(findings) == 4
    assert [f.severity for f in findings] == ["HIGH", "HIGH", "MEDIUM", "MEDIUM"]


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="Bucket input file not found"):
        scan_buckets(tmp_path / "missing.json")


@pytest.mark.parametrize("content", [b'{"buckets":', b'\xff'])
def test_invalid_json(tmp_path, content):
    path = tmp_path / "invalid.json"
    path.write_bytes(content)
    with pytest.raises(ValueError, match="Invalid JSON or UTF-8"):
        scan_buckets(path)


@pytest.mark.parametrize("field,value", [
    ("name", ""), ("name", None), ("publicAccessPrevention", "disabled"),
    ("publicAccessPrevention", []), ("inheritedPublicAccessPrevention", None),
    ("uniformBucketLevelAccess", "false"), ("uniformBucketLevelAccess", 0),
    ("bindings", {}), ("bindings", [None]),
    ("bindings", [{"role": "viewer", "members": "allUsers"}]),
    ("bindings", [{"role": "", "members": ["allUsers"]}]),
    ("bindings", [{"role": "viewer", "members": [12]}]),
    ("bindings", [{"role": "viewer", "members": []}]),
    ("bindings", [{"role": "viewer", "members": ["allUsers"], "condition": {}}]),
])
def test_invalid_bucket_fields(tmp_path, bucket, field, value):
    bucket[field] = value
    with pytest.raises(ValueError, match=r"Invalid bucket configuration.*buckets\[0\]"):
        scan(tmp_path, bucket)


@pytest.mark.parametrize("data", [None, [], {}, {"buckets": {}}, {"buckets": [None]},
                                       {"buckets": [{}]}])
def test_invalid_structure(tmp_path, data):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid bucket configuration"):
        scan_buckets(path)


def test_duplicate_names(tmp_path, bucket):
    path = tmp_path / "duplicates.json"
    path.write_text(json.dumps({"buckets": [bucket, bucket]}), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate bucket"):
        scan_buckets(path)


def test_empty_snapshot(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"buckets": []}', encoding="utf-8")
    assert scan_buckets(path) == []


def test_sample_data_and_default_path(tmp_path, monkeypatch):
    before = DEFAULT_INPUT.read_bytes()
    monkeypatch.chdir(tmp_path)
    findings = scan_buckets()
    assert DEFAULT_INPUT.read_bytes() == before
    assert len(findings) == 5
    assert [f.severity for f in findings] == ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM"]
    assert not any(f.resource == "fictional-aurora-private-archive" for f in findings)

import copy
import json
import socket

import pytest

from security_guardian.models.finding import Finding
from security_guardian.scanners.firewall import DEFAULT_INPUT, scan_firewalls


@pytest.fixture
def rule():
    return {"name": "fictional-test", "direction": "INGRESS", "action": "ALLOW",
            "disabled": False, "sourceRanges": ["0.0.0.0/0"],
            "protocols": [{"protocol": "tcp", "ports": ["22"]}]}


def write_snapshot(tmp_path, data):
    path = tmp_path / "firewalls.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def scan(tmp_path, rule):
    path = write_snapshot(tmp_path, {"firewalls": [rule]})
    before = path.read_bytes()
    result = scan_firewalls(path)
    assert path.read_bytes() == before
    for finding in result:
        assert isinstance(finding, Finding)
        assert finding.resource == rule["name"]
        assert finding.severity == "HIGH"
        assert finding.recommendation and finding.evidence
        assert "not verified internet reachability" in finding.issue
    return result


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "0:0:0:0:0:0:0:0/0"])
@pytest.mark.parametrize("port,service", [(22, "SSH"), (3389, "RDP")])
def test_public_services(tmp_path, rule, cidr, port, service):
    rule["sourceRanges"] = [cidr]
    rule["protocols"][0]["ports"] = [str(port)]
    findings = scan(tmp_path, rule)
    assert len(findings) == 1
    assert service in findings[0].issue
    evidence = json.loads(findings[0].evidence)
    assert evidence["port"] == port
    assert evidence["matchingProtocols"] == rule["protocols"]
    assert evidence["sourceRanges"] == (["0.0.0.0/0"] if cidr == "0.0.0.0/0" else ["::/0"])


@pytest.mark.parametrize("cidr", ["192.0.2.0/24", "10.0.0.0/8", "2001:db8::/32",
                                  "0.0.0.0/1", "::/1"])
def test_restricted_sources(tmp_path, rule, cidr):
    rule["sourceRanges"] = [cidr]
    assert scan(tmp_path, rule) == []


@pytest.mark.parametrize("entry,expected", [
    ({"protocol": "tcp"}, [22, 3389]),
    ({"protocol": "tcp", "ports": []}, [22, 3389]),
    ({"protocol": "6"}, [22, 3389]),
    ({"protocol": "006", "ports": ["22"]}, [22]),
    ({"protocol": "all"}, [22, 3389]),
    ({"protocol": "tcp", "ports": ["20-22"]}, [22]),
    ({"protocol": "tcp", "ports": ["22-23"]}, [22]),
    ({"protocol": "tcp", "ports": ["3388-3389"]}, [3389]),
    ({"protocol": "tcp", "ports": ["3389-3390"]}, [3389]),
    ({"protocol": "tcp", "ports": ["0-65535"]}, [22, 3389]),
    ({"protocol": "tcp", "ports": ["23-3388", "443"]}, []),
    ({"protocol": "udp", "ports": ["22", "3389"]}, []),
    ({"protocol": "17"}, []), ({"protocol": "icmp"}, []),
    ({"protocol": "58"}, []), ({"protocol": "sctp"}, []),
])
def test_protocols_and_ranges(tmp_path, rule, entry, expected):
    rule["protocols"] = [entry]
    assert [json.loads(f.evidence)["port"] for f in scan(tmp_path, rule)] == expected


@pytest.mark.parametrize("kind", ["disabled", "egress", "deny"])
def test_ignored_rules(tmp_path, rule, kind):
    if kind == "disabled":
        rule["disabled"] = True
    elif kind == "egress":
        rule["direction"] = "EGRESS"
        rule["destinationRanges"] = rule.pop("sourceRanges")
    else:
        rule["action"] = "DENY"
    assert scan(tmp_path, rule) == []


def test_multiple_entries_sources_and_rules(tmp_path, rule):
    rule["sourceRanges"] = ["0.0.0.0/0", "::/0", "0.0.0.0/0", "192.0.2.0/24"]
    rule["protocols"] = [{"protocol": "udp", "ports": ["3389"]},
                         {"protocol": "tcp", "ports": ["22", "20-3400"]}]
    rule["protocols"].append(copy.deepcopy(rule["protocols"][1]))
    other = copy.deepcopy(rule)
    other["name"] = "fictional-second"
    result = scan_firewalls(write_snapshot(tmp_path, {"firewalls": [rule, other]}))
    assert [f.resource for f in result] == [rule["name"]] * 2 + [other["name"]] * 2
    for finding in result:
        evidence = json.loads(finding.evidence)
        assert evidence["sourceRanges"] == ["0.0.0.0/0", "::/0"]
        assert len(evidence["matchingProtocols"]) == 1


@pytest.mark.parametrize("field,value", [
    ("name", ""), ("name", 12), ("name", " trailing "),
    ("direction", "ingress"), ("direction", None), ("action", "accept"),
    ("action", []), ("disabled", "false"), ("disabled", 0),
    ("sourceRanges", []), ("sourceRanges", "0.0.0.0/0"),
    ("sourceRanges", [None]), ("sourceRanges", ["garbage"]),
    ("sourceRanges", ["1.2.3.4"]), ("sourceRanges", ["192.0.2.1/24"]),
    ("sourceRanges", ["::/129"]), ("protocols", []), ("protocols", {}),
    ("protocols", [None]), ("protocols", [{}]),
])
def test_invalid_fields(tmp_path, rule, field, value):
    rule[field] = value
    with pytest.raises(ValueError, match=r"Invalid firewall configuration.*firewalls\[0\]"):
        scan(tmp_path, rule)


@pytest.mark.parametrize("field", ["name", "direction", "action", "disabled", "sourceRanges", "protocols"])
def test_missing_fields(tmp_path, rule, field):
    del rule[field]
    with pytest.raises(ValueError, match="Invalid firewall configuration"):
        scan(tmp_path, rule)


@pytest.mark.parametrize("entry", [
    {"protocol": "TCP"}, {"protocol": 6}, {"protocol": True},
    {"protocol": "256"}, {"protocol": "-1"}, {"protocol": "bogus"},
    {"protocol": "all", "ports": []}, {"protocol": "icmp", "ports": ["22"]},
    {"protocol": "tcp", "ports": None}, {"protocol": "tcp", "ports": "22"},
    {"protocol": "tcp", "extra": True},
])
def test_invalid_protocol_entries(tmp_path, rule, entry):
    rule["protocols"] = [entry]
    with pytest.raises(ValueError, match="Invalid firewall configuration"):
        scan(tmp_path, rule)


@pytest.mark.parametrize("port", [22, True, None, "", "-1", "65536", "23-22",
                                  "22-65536", "22-23-24", "22.0", " 22", "ssh", "２２"])
def test_invalid_ports(tmp_path, rule, port):
    rule["protocols"][0]["ports"] = [port]
    with pytest.raises(ValueError, match="Invalid firewall configuration"):
        scan(tmp_path, rule)


@pytest.mark.parametrize("data", [None, [], {}, {"firewalls": {}}, {"firewalls": [None]},
                                  {"firewalls": [], "extra": 1}])
def test_invalid_structure(tmp_path, data):
    with pytest.raises(ValueError, match="Invalid firewall configuration"):
        scan_firewalls(write_snapshot(tmp_path, data))


def test_validates_entire_snapshot_before_findings(tmp_path, rule, monkeypatch):
    def unexpected_finding(**kwargs):
        pytest.fail("Finding created before complete validation")
    monkeypatch.setattr("security_guardian.scanners.firewall.Finding", unexpected_finding)
    invalid = copy.deepcopy(rule)
    invalid.update(name="invalid-disabled-rule", disabled=True, protocols=[{}])
    with pytest.raises(ValueError, match=r"firewalls\[1\]"):
        scan_firewalls(write_snapshot(tmp_path, {"firewalls": [rule, invalid]}))


def test_duplicate_names(tmp_path, rule):
    with pytest.raises(ValueError, match="duplicate rule name"):
        scan_firewalls(write_snapshot(tmp_path, {"firewalls": [rule, rule]}))


def test_unknown_field(tmp_path, rule):
    rule["targetTags"] = ["admin"]
    with pytest.raises(ValueError, match="expected exactly"):
        scan(tmp_path, rule)


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="Firewall input file not found"):
        scan_firewalls(tmp_path / "missing.json")


@pytest.mark.parametrize("content", [b'{"firewalls":', b'\xff'])
def test_invalid_json(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    with pytest.raises(ValueError, match="Invalid JSON or UTF-8"):
        scan_firewalls(path)


def test_empty_snapshot(tmp_path):
    assert scan_firewalls(write_snapshot(tmp_path, {"firewalls": []})) == []


def test_sample_read_only_without_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Network access attempted")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    before = DEFAULT_INPUT.read_bytes()
    monkeypatch.chdir(tmp_path)
    findings = scan_firewalls()
    assert DEFAULT_INPUT.read_bytes() == before
    assert len(findings) == 6
    assert all(f.severity == "HIGH" for f in findings)
    assert [json.loads(f.evidence)["port"] for f in findings] == [22, 3389, 22, 3389, 22, 3389]
    assert [f.resource for f in findings] == [
        "fictional-aurora-public-ssh", "fictional-aurora-public-rdp",
        "fictional-aurora-public-range", "fictional-aurora-public-range",
        "fictional-aurora-ipv6-tcp", "fictional-aurora-ipv6-tcp"]

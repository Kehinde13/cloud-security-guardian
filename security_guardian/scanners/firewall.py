"""Read-only inspection of normalized local VPC firewall snapshots."""

import ipaddress
import json
from pathlib import Path
import re

from security_guardian.models.finding import Finding


DEFAULT_INPUT = Path(__file__).resolve().parents[2] / "sample_data" / "firewalls.json"
_PROTOCOLS = {"tcp", "udp", "icmp", "esp", "ah", "sctp", "ipip", "all"}


def _error(location, message):
    raise ValueError(f"{location}: {message}")


def _port_range(value, location):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", value):
        _error(location, "expected a port string or inclusive range, e.g. '22' or '20-30'")
    parts = value.split("-")
    start, end = int(parts[0]), int(parts[-1])
    if not 0 <= start <= end <= 65535:
        _error(location, "ports must be ordered and within 0-65535")
    return start, end


def _validate(data):
    if not isinstance(data, dict) or set(data) != {"firewalls"}:
        _error("input", "expected an object containing only firewalls")
    if not isinstance(data["firewalls"], list):
        _error("firewalls", "expected a list")
    names = set()
    for index, rule in enumerate(data["firewalls"]):
        loc = f"firewalls[{index}]"
        if not isinstance(rule, dict):
            _error(loc, "expected an object")
        if rule.get("direction") not in ("INGRESS", "EGRESS"):
            _error(loc + ".direction", "expected INGRESS or EGRESS")
        ranges_field = "sourceRanges" if rule["direction"] == "INGRESS" else "destinationRanges"
        if set(rule) != {"name", "direction", "action", "disabled", ranges_field, "protocols"}:
            _error(loc, f"expected exactly name, direction, action, disabled, {ranges_field}, protocols")
        name = rule["name"]
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            _error(loc + ".name", "expected a non-empty string without surrounding whitespace")
        if name in names:
            _error(loc + ".name", f"duplicate rule name {name!r}")
        names.add(name)
        if rule["action"] not in ("ALLOW", "DENY"):
            _error(loc + ".action", "expected ALLOW or DENY")
        if type(rule["disabled"]) is not bool:
            _error(loc + ".disabled", "expected a boolean")
        ranges = rule[ranges_field]
        if not isinstance(ranges, list) or not ranges:
            _error(loc + "." + ranges_field, "expected a non-empty CIDR list")
        for cidr in ranges:
            try:
                if not isinstance(cidr, str) or "/" not in cidr:
                    raise ValueError("CIDR prefix required")
                ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                _error(loc + "." + ranges_field, f"invalid network CIDR {cidr!r}: {exc}")
        if not isinstance(rule["protocols"], list) or not rule["protocols"]:
            _error(loc + ".protocols", "expected a non-empty list")
        for entry_index, entry in enumerate(rule["protocols"]):
            entry_loc = f"{loc}.protocols[{entry_index}]"
            if (not isinstance(entry, dict) or "protocol" not in entry
                    or set(entry) - {"protocol", "ports"}):
                _error(entry_loc, "expected protocol and optional ports")
            protocol = entry["protocol"]
            if not isinstance(protocol, str) or not (
                protocol in _PROTOCOLS or
                (re.fullmatch(r"[0-9]{1,3}", protocol) and 0 <= int(protocol) <= 255)
            ):
                _error(entry_loc + ".protocol", "expected a supported lowercase name or protocol number string 0-255")
            normalized = str(int(protocol)) if protocol.isdecimal() else protocol
            if "ports" in entry:
                if normalized not in ("tcp", "6", "udp", "17"):
                    _error(entry_loc, "ports are supported only for TCP or UDP")
                if not isinstance(entry["ports"], list):
                    _error(entry_loc + ".ports", "expected a list")
                for port in entry["ports"]:
                    _port_range(port, entry_loc + ".ports")


def scan_firewalls(path: str | Path = DEFAULT_INPUT) -> list[Finding]:
    """Validate the entire snapshot and return potential SSH/RDP exposure findings.

    Missing files raise FileNotFoundError; invalid UTF-8, JSON, and schema raise
    ValueError with input context. Other filesystem errors propagate unchanged.
    """
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as source:
            data = json.load(source)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Firewall input file not found: {path}") from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"Invalid JSON or UTF-8 in firewall input {path}: {exc}") from exc
    try:
        _validate(data)
    except ValueError as exc:
        raise ValueError(f"Invalid firewall configuration in {path}: {exc}") from exc

    findings = []
    for rule in data["firewalls"]:
        if rule["disabled"] or rule["direction"] != "INGRESS" or rule["action"] != "ALLOW":
            continue
        public_sources = sorted({str(ipaddress.ip_network(cidr)) for cidr in rule["sourceRanges"]
                                 if ipaddress.ip_network(cidr).prefixlen == 0})
        if not public_sources:
            continue
        for service, port in (("SSH", 22), ("RDP", 3389)):
            matches = []
            for entry in rule["protocols"]:
                protocol = entry["protocol"]
                if protocol.isdecimal():
                    protocol = str(int(protocol))
                if protocol not in ("tcp", "6", "all"):
                    continue
                ports = entry.get("ports", [])
                if not ports or any(start <= port <= end for start, end in
                                    (_port_range(p, "ports") for p in ports)):
                    if entry not in matches:
                        matches.append(entry)
            if matches:
                findings.append(Finding(
                    resource=rule["name"], severity="HIGH",
                    issue=f"Enabled ingress ALLOW rule permits {service} (TCP {port}) from unrestricted sources; potential exposure, not verified internet reachability.",
                    recommendation=f"Restrict {service} sources to approved CIDRs or remove the allowance; review target applicability and effective firewall policy.",
                    evidence=json.dumps({"service": service, "port": port,
                                         "sourceRanges": public_sources,
                                         "matchingProtocols": matches,
                                         "direction": rule["direction"], "action": rule["action"],
                                         "disabled": rule["disabled"]}, sort_keys=True),
                ))
    return findings

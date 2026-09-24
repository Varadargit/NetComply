"""
drift_detector.py

Compares a normalized device state dict (see collector.py) against
golden_rules.yaml and produces a list of DriftFinding objects.

Deliberately does NOT fix anything here — detection and remediation
are separate concerns, so detection stays simple, testable, and safe
to run constantly (e.g. every 15 minutes via cron) without any risk.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any
import yaml


@dataclass
class DriftFinding:
    hostname: str
    rule_type: str        # matches a key under rules_meta in golden_rules.yaml
    severity: str          # info | warning | critical
    label: str
    detail: str            # human-readable specifics, e.g. "VLAN 666 not in allowed list"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_golden_rules(path: str) -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


def _meta(rules: dict, rule_type: str) -> tuple[str, str]:
    m = rules["rules_meta"][rule_type]
    return m["severity"], m["label"]


def detect_drift(state: dict[str, Any], golden_rules: dict[str, Any]) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    hostname = state["hostname"]
    role_rules = golden_rules.get(state["role"])
    if role_rules is None:
        # No rules defined for this role — nothing to check against.
        return findings

    findings += _check_vlans(hostname, state, role_rules, golden_rules)
    findings += _check_trunks(hostname, state, role_rules, golden_rules)
    findings += _check_ntp(hostname, state, role_rules, golden_rules)
    findings += _check_banner(hostname, state, role_rules, golden_rules)
    findings += _check_interfaces(hostname, state, role_rules, golden_rules)
    return findings


def _check_vlans(hostname, state, role_rules, golden_rules) -> list[DriftFinding]:
    findings = []
    allowed = set(role_rules.get("allowed_vlans", []))
    for vlan in state.get("vlans", []):
        if vlan not in allowed:
            severity, label = _meta(golden_rules, "vlan_not_allowed")
            findings.append(DriftFinding(
                hostname, "vlan_not_allowed", severity, label,
                f"VLAN {vlan} present on device but not in allowed list {sorted(allowed)}",
            ))
    return findings


def _check_trunks(hostname, state, role_rules, golden_rules) -> list[DriftFinding]:
    findings = []
    required = set(role_rules.get("required_vlans_on_trunk", []))
    for iface, vlans in state.get("trunk_vlans", {}).items():
        missing = required - set(vlans)
        if missing:
            severity, label = _meta(golden_rules, "trunk_missing_vlan")
            findings.append(DriftFinding(
                hostname, "trunk_missing_vlan", severity, label,
                f"{iface} is missing required trunk VLAN(s) {sorted(missing)}",
            ))
    return findings


def _check_ntp(hostname, state, role_rules, golden_rules) -> list[DriftFinding]:
    findings = []
    expected = role_rules.get("ntp_servers", [])
    actual = state.get("ntp_servers", [])
    if sorted(expected) != sorted(actual):
        severity, label = _meta(golden_rules, "ntp_server_mismatch")
        findings.append(DriftFinding(
            hostname, "ntp_server_mismatch", severity, label,
            f"Expected NTP servers {expected}, found {actual}",
        ))
    return findings


def _check_banner(hostname, state, role_rules, golden_rules) -> list[DriftFinding]:
    findings = []
    required_text = role_rules.get("banner_motd_must_contain", "")
    if required_text and required_text not in state.get("banner_motd", ""):
        severity, label = _meta(golden_rules, "banner_missing_text")
        findings.append(DriftFinding(
            hostname, "banner_missing_text", severity, label,
            f"Banner does not contain required text: '{required_text}'",
        ))
    return findings


def _check_interfaces(hostname, state, role_rules, golden_rules) -> list[DriftFinding]:
    findings = []
    iface_rules = role_rules.get("interfaces", {})
    wildcard_rules = iface_rules.get("*", {})

    for name, iface_state in state.get("interfaces", {}).items():
        specific_rules = iface_rules.get(name, {})

        # Check description expectation (only if a specific rule defines one)
        expected_desc_substr = specific_rules.get("description_must_contain")
        if expected_desc_substr and expected_desc_substr not in iface_state.get("description", ""):
            severity, label = _meta(golden_rules, "interface_description_mismatch")
            findings.append(DriftFinding(
                hostname, "interface_description_mismatch", severity, label,
                f"{name} description '{iface_state.get('description', '')}' "
                f"does not contain required text '{expected_desc_substr}'",
            ))

        # Check unused interfaces are shut down (wildcard rule), skipping
        # interfaces that have an explicit description (treated as "in use")
        if wildcard_rules.get("shutdown_if_unused") and not iface_state.get("description"):
            if iface_state.get("admin_status") == "up":
                severity, label = _meta(golden_rules, "unused_interface_not_shutdown")
                findings.append(DriftFinding(
                    hostname, "unused_interface_not_shutdown", severity, label,
                    f"{name} has no description (appears unused) but is admin-up",
                ))

    return findings

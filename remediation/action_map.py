"""
remediation/action_map.py

Maps each drift rule_type (from drift_detector.py) to a concrete
remediation action: the exact device commands that would fix it, and
whether that fix is allowed to run automatically or requires a human
to approve it first.

This file is the single source of truth for "what does the system do
about problem X" — keeping it separate from the executor means you
can review/audit the entire remediation policy by reading one file,
without wading through execution/rollback logic.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from drift_detector import DriftFinding


@dataclass
class RemediationAction:
    finding: DriftFinding
    commands: list[str]           # exact CLI commands that would be sent to the device
    requires_approval: bool        # True = must NOT auto-execute
    explanation: str               # human-readable justification, shown in approval prompts/logs


# --- Per-rule-type command generators -------------------------------------
# Each function takes a DriftFinding and returns the list of IOS config
# commands that would fix it. Kept as small pure functions so each one
# is independently testable.

def _fix_vlan_not_allowed(f: DriftFinding) -> list[str]:
    # Extract the offending VLAN number out of the finding detail text.
    vlan = f.detail.split("VLAN ")[1].split(" ")[0]
    return [
        "configure terminal",
        f"no vlan {vlan}",
        "end",
    ]


def _fix_trunk_missing_vlan(f: DriftFinding) -> list[str]:
    iface = f.detail.split()[0]
    return [
        "configure terminal",
        f"interface {iface}",
        "switchport trunk allowed vlan add <missing_vlan_id>",  # filled in by caller with real ID in Stage 3
        "end",
    ]


def _fix_ntp_server_mismatch(f: DriftFinding) -> list[str]:
    return [
        "configure terminal",
        "ntp server 10.0.0.1",
        "ntp server 10.0.0.2",
        "end",
    ]


def _fix_banner_missing_text(f: DriftFinding) -> list[str]:
    return [
        "configure terminal",
        "banner motd ^Authorized access only. Violators will be prosecuted.^",
        "end",
    ]


def _fix_interface_description_mismatch(f: DriftFinding) -> list[str]:
    iface = f.detail.split()[0]
    return [
        "configure terminal",
        f"interface {iface}",
        "description UPLINK to Core",  # would be templated from golden_rules in Stage 3
        "end",
    ]


def _fix_unused_interface_not_shutdown(f: DriftFinding) -> list[str]:
    iface = f.detail.split()[0]
    return [
        "configure terminal",
        f"interface {iface}",
        "shutdown",
        "end",
    ]


# --- The policy table -------------------------------------------------------
# This is the important part: each rule_type is mapped to (command_fn,
# requires_approval, explanation). Severity from golden_rules.yaml
# informs this, but the approval flag is set explicitly here rather
# than derived automatically — a deliberate, auditable choice per
# action, not a blanket rule.

_POLICY: dict[str, tuple[Callable[[DriftFinding], list[str]], bool, str]] = {
    "vlan_not_allowed": (
        _fix_vlan_not_allowed,
        True,  # requires_approval — deleting a VLAN can drop live traffic
        "Removing a VLAN can disconnect any device still using it. "
        "Always requires human confirmation before executing.",
    ),
    "trunk_missing_vlan": (
        _fix_trunk_missing_vlan,
        True,  # requires_approval — changing trunk VLANs on a live port is risky
        "Changing allowed VLANs on a trunk port affects live traffic paths. "
        "Requires human confirmation.",
    ),
    "ntp_server_mismatch": (
        _fix_ntp_server_mismatch,
        False,  # safe to auto-fix
        "Adding NTP servers has no traffic impact. Safe to auto-remediate.",
    ),
    "banner_missing_text": (
        _fix_banner_missing_text,
        False,  # safe to auto-fix
        "Cosmetic/compliance-only change with zero traffic impact. Safe to auto-remediate.",
    ),
    "interface_description_mismatch": (
        _fix_interface_description_mismatch,
        False,  # safe to auto-fix
        "Cosmetic change with zero traffic impact. Safe to auto-remediate.",
    ),
    "unused_interface_not_shutdown": (
        _fix_unused_interface_not_shutdown,
        True,  # requires_approval — "unused" per our data might still be in use
        "Shutting down an interface risks an outage if it's actually in use "
        "despite lacking a description. Requires human confirmation.",
    ),
}


def build_remediation_action(finding: DriftFinding) -> RemediationAction | None:
    """Returns the remediation action for a finding, or None if no
    action is mapped (meaning: detected, but nothing to auto-fix yet)."""
    policy = _POLICY.get(finding.rule_type)
    if policy is None:
        return None
    command_fn, requires_approval, explanation = policy
    return RemediationAction(
        finding=finding,
        commands=command_fn(finding),
        requires_approval=requires_approval,
        explanation=explanation,
    )

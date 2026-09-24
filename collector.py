"""
collector.py

Collects normalized device state either from a real device (via
Netmiko) or from a mock dataset (for local development/testing
without needing live network access).

Output shape (same regardless of source) — this normalization is the
important part, since the drift engine only ever looks at this dict,
never raw CLI output:

{
    "hostname": str,
    "role": str,               # matches a top-level key in golden_rules.yaml
    "vlans": [int, ...],
    "trunk_vlans": {interface_name: [int, ...]},
    "ntp_servers": [str, ...],
    "banner_motd": str,
    "interfaces": {
        name: {
            "description": str,
            "admin_status": "up" | "down",
        }
    },
}
"""

from __future__ import annotations
import re
from typing import Any


def collect_from_device(host: str, username: str, password: str, device_type: str = "cisco_ios") -> dict[str, Any]:
    """Real collection path using Netmiko. Requires network access to
    the device — use collect_from_mock() for local development."""
    from netmiko import ConnectHandler  # imported lazily so mock mode
                                          # doesn't require netmiko installed

    conn = ConnectHandler(
        device_type=device_type, host=host, username=username, password=password
    )
    try:
        running_config = conn.send_command("show running-config")
        hostname = conn.send_command("show run | include ^hostname").split()[-1]
    finally:
        conn.disconnect()

    return _parse_running_config(hostname, running_config)


def _parse_running_config(hostname: str, config_text: str) -> dict[str, Any]:
    """Turns raw IOS config text into the normalized state dict.
    Deliberately simple regex parsing — good enough for the rule set
    we're checking; a production version would use a proper config
    parser (e.g. ciscoconfparse)."""

    vlans = [int(v) for v in re.findall(r"^vlan (\d+)", config_text, re.M)]

    trunk_vlans: dict[str, list[int]] = {}
    ntp_servers = re.findall(r"^ntp server (\S+)", config_text, re.M)

    banner_match = re.search(r"banner motd \^(.*?)\^", config_text, re.S)
    banner_motd = banner_match.group(1).strip() if banner_match else ""

    interfaces: dict[str, dict[str, str]] = {}
    for block in re.split(r"^interface ", config_text, flags=re.M)[1:]:
        lines = block.splitlines()
        name = lines[0].strip()
        description = ""
        admin_status = "up"
        allowed = []
        for line in lines[1:]:
            line = line.strip()
            if line.startswith("description"):
                description = line[len("description"):].strip()
            elif line == "shutdown":
                admin_status = "down"
            elif line.startswith("switchport trunk allowed vlan"):
                allowed = [int(v) for v in re.findall(r"\d+", line)]
        interfaces[name] = {"description": description, "admin_status": admin_status}
        if allowed:
            trunk_vlans[name] = allowed

    return {
        "hostname": hostname,
        "role": "access_switch",  # in a real system this would come from an inventory file
        "vlans": vlans,
        "trunk_vlans": trunk_vlans,
        "ntp_servers": ntp_servers,
        "banner_motd": banner_motd,
        "interfaces": interfaces,
    }


def collect_from_mock(scenario: str = "clean") -> dict[str, Any]:
    """Returns a canned state dict for local testing without a real
    device. `scenario` picks between a few pre-built situations."""

    base = {
        "hostname": "SW-ACCESS-01",
        "role": "access_switch",
        "vlans": [10, 20, 30, 99],
        "trunk_vlans": {"GigabitEthernet0/1": [10, 20, 30, 99]},
        "ntp_servers": ["10.0.0.1", "10.0.0.2"],
        "banner_motd": "Authorized access only. Violators will be prosecuted.",
        "interfaces": {
            "GigabitEthernet0/1": {"description": "UPLINK to Core", "admin_status": "up"},
            "GigabitEthernet0/2": {"description": "", "admin_status": "up"},
        },
    }

    if scenario == "clean":
        return base

    if scenario == "rogue_vlan":
        # Someone added an unauthorized VLAN -> should be critical severity
        base = dict(base)
        base["vlans"] = base["vlans"] + [666]
        return base

    if scenario == "missing_trunk_vlan":
        base = dict(base)
        base["trunk_vlans"] = {"GigabitEthernet0/1": [10, 20, 99]}  # missing 30
        return base

    if scenario == "ntp_drift":
        base = dict(base)
        base["ntp_servers"] = ["10.0.0.1"]  # missing second NTP server
        return base

    if scenario == "everything_wrong":
        base = dict(base)
        base["vlans"] = [10, 20, 666]
        base["trunk_vlans"] = {"GigabitEthernet0/1": [10, 99]}
        base["ntp_servers"] = []
        base["banner_motd"] = "Welcome"
        base["interfaces"]["GigabitEthernet0/1"]["description"] = "wrong desc"
        base["interfaces"]["GigabitEthernet0/2"]["admin_status"] = "up"  # unused, not shut
        return base

    raise ValueError(f"Unknown mock scenario: {scenario}")

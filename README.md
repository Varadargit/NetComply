# NetComply Self-Heal — Stage 1: Drift Detection

A network configuration compliance and drift detection engine, built
as the foundation for a self-remediation platform. This is Stage 1:
**detection only** — no remediation yet, by design (see project
philosophy below).

## What's built so far

- `rules/golden_rules.yaml` — the compliance baseline: what a
  correctly-configured device should look like, per device role.
- `collector.py` — pulls normalized device state either from a real
  device (Netmiko) or from mock data (for safe local development).
- `drift_detector.py` — compares collected state against golden rules,
  returns a list of severity-tagged findings.
- `run_mock_test.py` — proves the detection logic works correctly
  against five test scenarios before it ever touches a real device.

## Why detection is built and tested BEFORE remediation

Auto-remediation on real network infrastructure is dangerous if the
detection logic underneath it isn't trustworthy. Getting detection
provably correct against varied test scenarios first means that when
remediation is added in Stage 2, it's built on a foundation that's
already been validated — not on logic that might have bugs.

## Running the mock test

```bash
pip install pyyaml
python3 run_mock_test.py
```

This runs detection against 5 scenarios (clean, rogue VLAN, missing
trunk VLAN, NTP drift, and a device with everything wrong) and prints
a severity-tagged report for each.

## Connecting to a real device (Cisco DevNet Sandbox)

Cisco provides a free, always-on IOS-XE sandbox for exactly this kind
of testing — no lab setup required:

1. Go to https://developer.cisco.com/site/sandbox/ and reserve an
   "Always-On IOS XE" or similar sandbox.
2. Note the host, username, and password it gives you.
3. Use `collect_from_device()` in `collector.py`:

```python
from collector import collect_from_device
from drift_detector import detect_drift, load_golden_rules

state = collect_from_device(
    host="<sandbox-ip>",
    username="<sandbox-user>",
    password="<sandbox-password>",
)
golden_rules = load_golden_rules("rules/golden_rules.yaml")
findings = detect_drift(state, golden_rules)
for f in findings:
    print(f.severity, f.detail)
```

You'll likely need to adjust `rules/golden_rules.yaml` and the parsing
in `_parse_running_config()` to match whatever the sandbox device's
actual config looks like — that adjustment process is worth
documenting, since it's a real "adapting to real-world messiness"
story for an interview.

## Severity model

| Severity  | Meaning                                    | Stage 2 behavior (planned)      |
|-----------|---------------------------------------------|----------------------------------|
| info      | Cosmetic (e.g. missing description)         | Safe to auto-fix                |
| warning   | Should be fixed (e.g. missing NTP server)   | Auto-fix with rollback checks   |
| critical  | Risk of outage/security issue (e.g. rogue VLAN) | Requires human approval     |

## Stage 2 (in progress): remediation planning

- `remediation/action_map.py` — maps each drift `rule_type` to exact
  fix commands, plus a `requires_approval` flag set explicitly per
  action (not auto-derived from severity — see note below).
- `main.py` — single entry point: collect → detect → plan remediation.
  Dry-run only, sends nothing to any device.

Run it:
```bash
python3 main.py                       # all 5 mock scenarios
python3 main.py --scenario ntp_drift  # just one, for faster debugging
```

### Important design note: severity ≠ approval gate

It's tempting to gate approval purely off the `info`/`warning`/
`critical` severity in `golden_rules.yaml`, but this project
deliberately does NOT do that. `unused_interface_not_shutdown` is
`info` severity (cosmetic drift) but is still marked
`requires_approval: True` in `action_map.py`, because the *fix* — 
shutting down a port — carries real outage risk if the interface
turns out to be in use despite lacking a description. Severity
describes how bad the drift is; the approval flag describes how risky
the *fix* is. They're related but not the same axis, and conflating
them is how "safe" automation accidentally causes an outage.

## Reporting

Every run of `main.py` writes two report files to `reports/`, timestamped:

- **CSV** (`drift_report_<timestamp>.csv`) — flat, importable into a
  spreadsheet, a ticketing system, or any other tool.
- **HTML** (`drift_report_<timestamp>.html`) — rendered from a Jinja2
  template (`reporting/templates/report.html.j2`), grouped severity
  counts at the top, a full findings table with the remediation gate
  and planned commands per row.

Skip report generation with `python3 main.py --no-report` (useful
during fast iteration/debugging).

The reporting logic lives entirely in `reporting/report_writer.py`,
separate from detection and remediation — the report *format* can
change (add a JSON export, a Slack summary, whatever) without
touching any of the actual pipeline logic.

## Next (Stage 3 — not built yet)

- Executor: dry-run mode, pre-change config backup, apply, post-change
  health verification, auto-rollback on failure
- Approval gate: CLI or Slack-based human confirmation for
  `requires_approval` actions before they execute
- Audit logging to SQLite + Prometheus metrics export

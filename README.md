# NetComply — Network Configuration Compliance & Drift Detection

NetComply compares collected device state with YAML golden rules, explains configuration drift, stores scan history, and creates guarded remediation proposals. The included web demo uses **simulated device data only** and never sends configuration commands to network equipment.

## Features

1. **Interactive dashboard** — run a named demo scenario and inspect status, severity-tagged findings, remediation plans, and recent scans.
2. **Drift detection** — validates VLANs, trunk VLANs, NTP servers, banners, and interface policy against `rules/golden_rules.yaml`.
3. **Scan history and audit trail** — SQLite stores each scan and records scan/approval events. Collection failure is `failed`/unknown, never `compliant`.
4. **Approval-gated remediation preview** — shows planned commands and risk rationale. Approval is recorded as `approved_simulation`; no device command is executed by the web app.
5. **Reports and CLI** — retain the existing CSV/HTML reporting pipeline and command-line workflow.

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000. Choose a scenario and select **Run demo scan**. Try `Multiple configuration issues`, then `Collection timeout (failure handling)` to see that failed collection is not treated as compliance.

The database is created automatically as `netcomply.db`. Set `NETCOMPLY_DB` to use another path, for example in tests or deployment.

## Test

```bash
python -m unittest discover -s tests -v
```

Tests cover dashboard health, compliant and non-compliant scans, persistence, collection failure semantics, approval auditing, and invalid scenarios.

## CLI reports

```bash
python main.py
python main.py --scenario ntp_drift
python main.py --no-report
```

## API overview

- `GET /health` — health and demo-mode marker
- `GET /api/scenarios` — available simulated scenarios
- `POST /api/scans` with `{"scenario":"rogue_vlan"}` — run a simulated scan
- `GET /api/scans` — recent scan history
- `GET /api/scans/{scan_id}` — findings and remediation plans
- `GET /api/scans/{scan_id}/audit` — audit events
- `POST /api/scans/{scan_id}/actions/{action_index}/approve` — record demo approval; does not execute commands

Interactive API documentation is available at `/docs` while the server is running.

## Safety and limitations

- The browser-triggered scan API only calls `collect_from_mock`; it does not accept device addresses or credentials.
- Remediation approval is an audit/demo state transition only. It does not connect to devices, apply commands, verify a live change, or perform rollback.
- The existing `collector.py` contains a separate Netmiko helper for local experiments. It is not wired to the public web UI. Do not expose credentials or enable live execution without separate authentication, authorization, secret management, device allowlists, command validation, backups, rollback, and lab validation.
- The IOS configuration parser is intentionally basic and should not be considered a production-grade parser for arbitrary device output.
- SQLite is suitable for this portfolio-scale demo; a multi-user production deployment would need stronger access controls, database operations, retention policy, and monitoring.

## Project structure

```text
app.py                         FastAPI API and web routes
collector.py                   mock collection + optional Netmiko collector
drift_detector.py              golden-rule comparison
remediation/action_map.py      remediation proposal policy
reporting/                     CSV/HTML reports
rules/golden_rules.yaml        compliance baseline
templates/dashboard.html       dashboard markup
static/app.js                  dashboard interactions
static/style.css               responsive styles
tests/test_web_app.py          API and workflow tests
```

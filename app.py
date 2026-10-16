"""NetComply demo web app. All web-triggered scans use simulated devices only."""
from __future__ import annotations
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from collector import collect_from_mock
from drift_detector import detect_drift, load_golden_rules
from remediation.action_map import build_remediation_action

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("NETCOMPLY_DB", BASE_DIR / "netcomply.db"))
RULES_PATH = BASE_DIR / "rules" / "golden_rules.yaml"
SCENARIOS = ["clean", "rogue_vlan", "missing_trunk_vlan", "ntp_drift", "everything_wrong", "collection_failure"]
app = FastAPI(title="NetComply", version="1.0.0", description="Network configuration compliance demo; simulated devices only.")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


class ScanRequest(BaseModel):
    scenario: str = "everything_wrong"


class ApprovalRequest(BaseModel):
    note: str = "Approved in demo environment"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, scenario TEXT NOT NULL,
            hostname TEXT, status TEXT NOT NULL, error TEXT,
            findings_json TEXT NOT NULL, actions_json TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            created_at TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )""")


init_db()


def audit(scan_id: str, event: str, details: dict[str, Any]) -> None:
    with connect_db() as conn:
        conn.execute("INSERT INTO audit_events(scan_id, created_at, event, details) VALUES (?, ?, ?, ?)",
                     (scan_id, utc_now(), event, json.dumps(details)))


def serialize_action(finding: Any) -> dict[str, Any] | None:
    action = build_remediation_action(finding)
    if action is None:
        return None
    return {
        "rule_type": finding.rule_type,
        "label": finding.label,
        "severity": finding.severity,
        "detail": finding.detail,
        "commands": action.commands,
        "requires_approval": action.requires_approval,
        "explanation": action.explanation,
        "state": "approval_required" if action.requires_approval else "plan_ready",
    }


def scan_record(scan_id: str) -> dict[str, Any]:
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    result["actions"] = json.loads(result.pop("actions_json"))
    return result


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return (BASE_DIR / "templates" / "dashboard.html").read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "simulation-only"}


@app.get("/api/scenarios")
def get_scenarios() -> dict[str, Any]:
    return {"scenarios": SCENARIOS, "mode": "simulation-only"}


@app.get("/api/scans")
def list_scans(limit: int = 25) -> dict[str, Any]:
    limit = max(1, min(limit, 100))
    with connect_db() as conn:
        rows = conn.execute("SELECT id, created_at, scenario, hostname, status, error, findings_json, actions_json FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    scans = []
    for row in rows:
        item = dict(row)
        item["finding_count"] = len(json.loads(item.pop("findings_json")))
        item.pop("actions_json")
        scans.append(item)
    return {"scans": scans}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    return scan_record(scan_id)


@app.get("/api/scans/{scan_id}/audit")
def get_audit(scan_id: str) -> dict[str, Any]:
    scan_record(scan_id)  # validate id
    with connect_db() as conn:
        rows = conn.execute("SELECT created_at, event, details FROM audit_events WHERE scan_id = ? ORDER BY id DESC", (scan_id,)).fetchall()
    return {"events": [{**dict(r), "details": json.loads(r["details"])} for r in rows]}


@app.post("/api/scans")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    if request.scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose one of: {', '.join(SCENARIOS)}")
    scan_id = str(uuid.uuid4())
    created_at = utc_now()
    hostname = None
    findings: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    error = None
    try:
        if request.scenario == "collection_failure":
            raise TimeoutError("Simulated collection timeout: device did not respond within 5 seconds")
        state = collect_from_mock(request.scenario)
        hostname = state["hostname"]
        golden_rules = load_golden_rules(str(RULES_PATH))
        detected = detect_drift(state, golden_rules)
        findings = [f.to_dict() for f in detected]
        actions = [a for f in detected if (a := serialize_action(f)) is not None]
        status = "compliant" if not findings else "non_compliant"
    except Exception as exc:
        # A failed collection is never reported as compliant.
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"
    with connect_db() as conn:
        conn.execute("INSERT INTO scans(id, created_at, scenario, hostname, status, error, findings_json, actions_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (scan_id, created_at, request.scenario, hostname, status, error, json.dumps(findings), json.dumps(actions)))
    audit(scan_id, "scan_completed", {"scenario": request.scenario, "status": status, "finding_count": len(findings), "error": error})
    return scan_record(scan_id)


@app.post("/api/scans/{scan_id}/actions/{action_index}/approve")
def approve_action(scan_id: str, action_index: int, request: ApprovalRequest) -> dict[str, Any]:
    record = scan_record(scan_id)
    if record["status"] == "failed":
        raise HTTPException(status_code=409, detail="Cannot approve remediation for a failed scan")
    actions = record["actions"]
    if action_index < 0 or action_index >= len(actions):
        raise HTTPException(status_code=404, detail="Remediation action not found")
    action = actions[action_index]
    if not action["requires_approval"]:
        raise HTTPException(status_code=409, detail="This action does not require approval")
    if action["state"] == "approved_simulation":
        raise HTTPException(status_code=409, detail="Action has already been approved")
    # Deliberately does not connect to devices or execute commands.
    action["state"] = "approved_simulation"
    action["approval_note"] = request.note[:300]
    with connect_db() as conn:
        conn.execute("UPDATE scans SET actions_json = ? WHERE id = ?", (json.dumps(actions), scan_id))
    audit(scan_id, "remediation_approved_simulation_only", {"action_index": action_index, "rule_type": action["rule_type"], "note": request.note[:300], "commands_executed": False})
    return scan_record(scan_id)

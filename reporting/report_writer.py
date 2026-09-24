"""
reporting/report_writer.py

Takes the findings + remediation actions produced by a pipeline run
and writes them out as:
  - a CSV file (for spreadsheets, tickets, or feeding into another tool)
  - an HTML file rendered from a Jinja2 template (for a human to open
    and actually read)

Kept separate from main.py so the reporting format can change without
touching detection/remediation logic at all.
"""

from __future__ import annotations
import csv
import datetime
import os
from dataclasses import dataclass
from jinja2 import Environment, FileSystemLoader

from drift_detector import DriftFinding
from remediation.action_map import RemediationAction

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


@dataclass
class ReportRow:
    """One row = one finding, flattened together with its remediation
    plan (if any) so both CSV and HTML can consume the same shape."""
    scenario: str
    hostname: str
    severity: str
    rule_type: str
    detail: str
    gate: str               # "AUTO-SAFE" | "APPROVAL REQUIRED" | "NO ACTION MAPPED"
    explanation: str
    planned_commands: str    # semicolon-joined, empty string if no action


def build_report_rows(scenario: str, hostname: str, findings: list[DriftFinding],
                       actions: dict[str, RemediationAction | None]) -> list[ReportRow]:
    """`actions` maps finding.rule_type -> RemediationAction (or None),
    as produced per-finding in the pipeline run."""
    rows = []
    for finding in findings:
        action = actions.get(id(finding))
        if action is None:
            gate, explanation, commands = "NO ACTION MAPPED", "", ""
        else:
            gate = "APPROVAL REQUIRED" if action.requires_approval else "AUTO-SAFE"
            explanation = action.explanation
            commands = " ; ".join(action.commands)

        rows.append(ReportRow(
            scenario=scenario,
            hostname=hostname,
            severity=finding.severity,
            rule_type=finding.rule_type,
            detail=finding.detail,
            gate=gate,
            explanation=explanation,
            planned_commands=commands,
        ))
    return rows


def write_csv(rows: list[ReportRow], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario", "hostname", "severity", "rule_type", "detail",
            "gate", "explanation", "planned_commands",
        ])
        for r in rows:
            writer.writerow([
                r.scenario, r.hostname, r.severity, r.rule_type, r.detail,
                r.gate, r.explanation, r.planned_commands,
            ])


def write_html(rows: list[ReportRow], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html.j2")

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity_counts = {"critical": 0, "warning": 0, "info": 0}
    for r in rows:
        if r.severity in severity_counts:
            severity_counts[r.severity] += 1

    html = template.render(
        rows=rows,
        generated_at=generated_at,
        total_findings=len(rows),
        severity_counts=severity_counts,
    )
    with open(path, "w") as f:
        f.write(html)


def generate_reports(rows: list[ReportRow], output_dir: str = "reports") -> tuple[str, str]:
    """Writes both CSV and HTML reports with a shared timestamp, returns
    (csv_path, html_path)."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"drift_report_{timestamp}.csv")
    html_path = os.path.join(output_dir, f"drift_report_{timestamp}.html")

    write_csv(rows, csv_path)
    write_html(rows, html_path)

    return csv_path, html_path

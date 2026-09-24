"""
main.py

Single entry point for the pipeline: collect -> detect drift ->
plan remediation. Dry-run only — nothing is sent to a device yet
(that's Stage 3, the executor).

Usage:
    python3 main.py                      # runs all mock scenarios
    python3 main.py --scenario ntp_drift # runs just one
"""

import argparse
from collector import collect_from_mock
from drift_detector import detect_drift, load_golden_rules
from remediation.action_map import build_remediation_action
from reporting.report_writer import build_report_rows, generate_reports

GOLDEN_RULES_PATH = "rules/golden_rules.yaml"
ALL_SCENARIOS = ["clean", "rogue_vlan", "missing_trunk_vlan", "ntp_drift", "everything_wrong"]


def run_pipeline(scenario: str, golden_rules: dict) -> list:
    """Runs detection + remediation planning for one scenario, prints a
    summary, and returns the ReportRow list for this scenario so main()
    can aggregate them into a combined report."""
    print(f"\n{'=' * 70}")
    print(f"SCENARIO: {scenario}")
    print("=" * 70)

    state = collect_from_mock(scenario)
    findings = detect_drift(state, golden_rules)

    if not findings:
        print("  No drift detected — nothing to remediate.")
        return []

    actions_by_finding_id = {}
    for finding in findings:
        action = build_remediation_action(finding)
        actions_by_finding_id[id(finding)] = action

        print(f"\n  [{finding.severity.upper()}] {finding.rule_type}")
        print(f"    Detail: {finding.detail}")
        if action is None:
            print("    (No remediation mapped for this rule type yet)")
            continue
        gate = "APPROVAL REQUIRED" if action.requires_approval else "AUTO-SAFE"
        print(f"    Gate:   {gate}")
        print(f"    Why:    {action.explanation}")
        print(f"    Plan:   {' ; '.join(action.commands)}")

    return build_report_rows(scenario, state["hostname"], findings, actions_by_finding_id)


def main():
    parser = argparse.ArgumentParser(description="NetComply Self-Heal: detect + plan remediation")
    parser.add_argument(
        "--scenario", choices=ALL_SCENARIOS, default=None,
        help="Run a single mock scenario instead of all of them",
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Skip writing CSV/HTML report files",
    )
    args = parser.parse_args()

    golden_rules = load_golden_rules(GOLDEN_RULES_PATH)
    scenarios = [args.scenario] if args.scenario else ALL_SCENARIOS

    all_rows = []
    for scenario in scenarios:
        all_rows.extend(run_pipeline(scenario, golden_rules))

    if not args.no_report:
        csv_path, html_path = generate_reports(all_rows)
        print(f"\n{'=' * 70}")
        print(f"Reports written:")
        print(f"  CSV:  {csv_path}")
        print(f"  HTML: {html_path}")
        print("=" * 70)


if __name__ == "__main__":
    main()

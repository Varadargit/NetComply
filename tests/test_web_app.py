import json
import os
import tempfile
import unittest
from pathlib import Path

# Isolate the test database before importing the application.
tmpdir = tempfile.TemporaryDirectory()
os.environ["NETCOMPLY_DB"] = str(Path(tmpdir.name) / "test.db")
from fastapi.testclient import TestClient
import app as webapp

client = TestClient(webapp.app)

class NetComplyWebTests(unittest.TestCase):
    def test_health_and_dashboard(self):
        self.assertEqual(client.get("/health").json()["status"], "ok")
        self.assertIn("NetComply", client.get("/").text)

    def test_clean_scan_is_compliant_and_persisted(self):
        response = client.post("/api/scans", json={"scenario": "clean"})
        self.assertEqual(response.status_code, 200)
        scan = response.json()
        self.assertEqual(scan["status"], "compliant")
        self.assertEqual(scan["findings"], [])
        history = client.get("/api/scans").json()["scans"]
        self.assertTrue(any(item["id"] == scan["id"] for item in history))

    def test_drift_scan_contains_findings_and_actions(self):
        scan = client.post("/api/scans", json={"scenario": "rogue_vlan"}).json()
        self.assertEqual(scan["status"], "non_compliant")
        self.assertTrue(any(f["rule_type"] == "vlan_not_allowed" for f in scan["findings"]))
        self.assertTrue(any(a["requires_approval"] for a in scan["actions"]))

    def test_collection_failure_is_not_compliant(self):
        scan = client.post("/api/scans", json={"scenario": "collection_failure"}).json()
        self.assertEqual(scan["status"], "failed")
        self.assertIsNotNone(scan["error"])
        self.assertEqual(scan["findings"], [])
        self.assertEqual(client.post(f"/api/scans/{scan['id']}/actions/0/approve", json={}).status_code, 409)

    def test_approval_is_audited_but_does_not_execute_commands(self):
        scan = client.post("/api/scans", json={"scenario": "rogue_vlan"}).json()
        index = next(i for i, action in enumerate(scan["actions"]) if action["requires_approval"])
        response = client.post(f"/api/scans/{scan['id']}/actions/{index}/approve", json={"note":"test approval"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["actions"][index]["state"], "approved_simulation")
        events = client.get(f"/api/scans/{scan['id']}/audit").json()["events"]
        approval = next(e for e in events if e["event"] == "remediation_approved_simulation_only")
        self.assertFalse(approval["details"]["commands_executed"])

    def test_unknown_scenario_rejected(self):
        self.assertEqual(client.post("/api/scans", json={"scenario":"not-real"}).status_code, 400)

if __name__ == "__main__":
    unittest.main()

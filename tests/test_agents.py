"""
CyberGuard AI - Automated Unit Test Suite
Covers:
  - Ingest Agent (Schema validation, dropped malformed records, confidence scoring)
  - Detection Tools (Heuristics, brute-force frequency thresholds, credential stuffing)
  - Classification & MITRE ATT&CK Mapping (Risk scoring, severity derivation)
  - Containment Tools (Defensive script synthesis, rollback scripts, priority assignment)
  - Dynamic Severity Routing (Bypass on LOW/MED vs. trigger on HIGH/CRITICAL)
"""

import unittest
from agents.nodes import ingest_agent, detect_agent, classify_agent, response_agent
from tools.detection_tools import pattern_detector, anomaly_detector
from tools.containment_tools import generate_containment_action


class TestIngestAgent(unittest.TestCase):
    """Unit tests for telemetry validation and schema sanitization."""

    def test_valid_logs_pass_validation(self):
        valid_entries = [
            {"timestamp": "2026-11-21T00:00:00Z", "event_type": "login_success", "ip": "192.168.1.10", "user": "alice"},
            {"timestamp": "2026-11-21T00:01:00Z", "event_type": "login_failure", "ip": "10.0.0.5", "user": "bob"},
        ]
        state = {"raw_logs": valid_entries, "agent_trace": [], "confidence_scores": {}}
        result = ingest_agent(state)

        self.assertEqual(len(result["validated_logs"]), 2)
        self.assertEqual(result["confidence_scores"]["ingest"], 1.0)

    def test_malformed_logs_are_dropped(self):
        mixed_entries = [
            {"timestamp": "2026-11-21T00:00:00Z", "event_type": "login_success", "ip": "192.168.1.10"},
            {"event_type": "login_failure", "ip": "10.0.0.5"},  # missing timestamp
            {"timestamp": "2026-11-21T00:02:00Z", "ip": "10.0.0.6"},  # missing event_type
            {"timestamp": "2026-11-21T00:03:00Z", "event_type": "port_scan"},  # missing ip
        ]
        state = {"raw_logs": mixed_entries, "agent_trace": [], "confidence_scores": {}}
        result = ingest_agent(state)

        self.assertEqual(len(result["validated_logs"]), 1)
        self.assertEqual(result["confidence_scores"]["ingest"], 0.25)

    def test_empty_raw_logs_handled_gracefully(self):
        state = {"raw_logs": [], "agent_trace": [], "confidence_scores": {}}
        result = ingest_agent(state)

        self.assertEqual(len(result["validated_logs"]), 0)
        self.assertEqual(result["confidence_scores"]["ingest"], 0.0)


class TestDetectionTools(unittest.TestCase):
    """Unit tests for heuristic pattern matching and anomaly detection."""

    def test_brute_force_threshold_boundary(self):
        # Boundary: 2 failures should NOT trigger brute force
        two_failures = [
            {"timestamp": "t1", "event_type": "login_failure", "ip": "203.0.113.1", "user": "admin"},
            {"timestamp": "t2", "event_type": "login_failure", "ip": "203.0.113.1", "user": "admin"},
        ]
        res_below = pattern_detector.invoke({"events": two_failures})
        bf_below = [p for p in res_below["patterns"] if p["type"] == "brute_force"]
        self.assertEqual(len(bf_below), 0)

        # Boundary: 3 or more failures SHOULD trigger brute force
        three_failures = two_failures + [
            {"timestamp": "t3", "event_type": "login_failure", "ip": "203.0.113.1", "user": "admin"}
        ]
        res_above = pattern_detector.invoke({"events": three_failures})
        bf_above = [p for p in res_above["patterns"] if p["type"] == "brute_force"]
        self.assertEqual(len(bf_above), 1)
        self.assertEqual(bf_above[0]["count"], 3)
        self.assertGreaterEqual(bf_above[0]["confidence"], 0.75)

    def test_credential_stuffing_detection(self):
        events = [
            {"event_type": "login_failure", "ip": "198.51.100.22", "user": "user1"},
            {"event_type": "login_failure", "ip": "198.51.100.22", "user": "user2"},
            {"event_type": "login_failure", "ip": "198.51.100.22", "user": "user3"},
            {"event_type": "login_success", "ip": "198.51.100.22", "user": "user3"},
        ]
        res = pattern_detector.invoke({"events": events})
        stuffing = [p for p in res["patterns"] if p["type"] == "credential_stuffing"]
        self.assertEqual(len(stuffing), 1)
        self.assertEqual(stuffing[0]["ip"], "198.51.100.22")

    def test_data_exfiltration_anomaly(self):
        events = [
            {"event_type": "data_exfiltration", "ip": "10.0.0.15", "user": "dbadmin", "bytes_out": 750_000_000}
        ]
        res = anomaly_detector.invoke({"events": events})
        anomalies = res.get("anomalies", [])
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["type"], "data_exfiltration")
        self.assertEqual(anomalies[0]["severity"], "critical")


class TestContainmentTools(unittest.TestCase):
    """Unit tests for automated containment playbook and script synthesis."""

    def test_brute_force_containment_script(self):
        threat = {
            "type": "brute_force",
            "mitre_id": "T1110",
            "severity": "HIGH",
            "ip": "203.0.113.55",
            "user": "root",
            "count": 10,
        }
        action = generate_containment_action(threat, index=1)

        self.assertEqual(action["action_id"], "ACT-001")
        self.assertEqual(action["priority"], "P1 - IMMEDIATE")
        self.assertIn("iptables -A INPUT -s 203.0.113.55 -j DROP", action["remediation_script"])
        self.assertIn("New-NetFirewallRule", action["remediation_script"])
        self.assertIn("iptables -D INPUT -s 203.0.113.55 -j DROP", action["rollback_script"])

    def test_data_exfiltration_critical_containment(self):
        threat = {
            "type": "data_exfiltration",
            "mitre_id": "T1041",
            "severity": "CRITICAL",
            "ip": "10.0.0.99",
            "user": "exfil_user",
        }
        action = generate_containment_action(threat, index=2)

        self.assertEqual(action["action_id"], "ACT-002")
        self.assertEqual(action["priority"], "P0 - EMERGENCY")
        self.assertIn("ss -K dst 10.0.0.99", action["remediation_script"])


class TestRoutingAndClassification(unittest.TestCase):
    """Unit tests for MITRE taxonomy mapping and severity decision routing."""

    def test_low_severity_bypasses_response_agent(self):
        # Single medium event (e.g., small port scan)
        state = {
            "anomalies": [{"type": "port_scan", "ip": "10.0.0.1", "ports_scanned": 600}],
            "agent_trace": [],
            "confidence_scores": {},
        }
        classified_state = classify_agent(state)

        self.assertFalse(classified_state["has_critical_threats"])
        # Run response agent
        response_state = response_agent(classified_state)
        # Low/Medium should yield 0 containment actions
        self.assertEqual(len(response_state.get("containment_actions", [])), 0)

    def test_critical_severity_triggers_containment_actions(self):
        state = {
            "anomalies": [{"type": "data_exfiltration", "ip": "10.0.0.5", "user": "victim"}],
            "agent_trace": [],
            "confidence_scores": {},
        }
        classified_state = classify_agent(state)

        self.assertTrue(classified_state["has_critical_threats"])
        response_state = response_agent(classified_state)
        self.assertGreaterEqual(len(response_state["containment_actions"]), 1)


if __name__ == "__main__":
    unittest.main()

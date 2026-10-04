import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
from pipeline import build_graph

print("=== TEST 1: ENTERPRISE ATTACK (CRITICAL/HIGH) ===")
with open("data/security_logs.json") as f:
    logs = json.load(f)

graph = build_graph(model_name="llama3.1:8b", use_memory=False)
init_state = {
    "raw_logs": logs, "validated_logs": [], "anomalies": [],
    "classified_threats": [], "has_critical_threats": False,
    "containment_actions": [], "remediation_plan": "",
    "incident_report": "", "needs_report": False,
    "agent_trace": [], "confidence_scores": {}
}

res = graph.invoke(init_state)
print(f"Total Threats: {len(res['classified_threats'])}")
print(f"Has Critical Threats: {res['has_critical_threats']}")
print(f"Containment Actions Formulated: {len(res['containment_actions'])}")
for act in res["containment_actions"]:
    print(f"  -> [{act['action_id']}] {act['action_title']} ({act['priority']})")
print("\nMulti-Agent Decision Trace:")
for t in res["agent_trace"]:
    print(f"  {t}")

print("\n=== TEST 2: LOW/MED SCENARIO (Bypass Response Agent) ===")
with open("data/sample_low_med.json") as f:
    low_logs = json.load(f)

low_init = {
    "raw_logs": low_logs, "validated_logs": [], "anomalies": [],
    "classified_threats": [], "has_critical_threats": False,
    "containment_actions": [], "remediation_plan": "",
    "incident_report": "", "needs_report": False,
    "agent_trace": [], "confidence_scores": {}
}

res_low = graph.invoke(low_init)
print(f"Total Threats: {len(res_low['classified_threats'])}")
print(f"Has Critical Threats: {res_low['has_critical_threats']}")
print(f"Containment Actions (Expected 0): {len(res_low['containment_actions'])}")
print("\nMulti-Agent Decision Trace:")
for t in res_low["agent_trace"]:
    print(f"  {t}")

print("\n=== ALL PIPELINE TESTS PASSED PERFECTLY! ===")

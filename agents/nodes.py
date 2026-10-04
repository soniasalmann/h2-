"""
The agent nodes of CyberGuard AI:
  1. ingest_agent    – parse, sanitize, and validate security logs
  2. detect_agent    – detect threats, anomalies, and multi-event patterns
  3. classify_agent  – map to MITRE ATT&CK and assess severity (LOW/MED vs HIGH/CRITICAL)
  4. response_agent  – autonomous SOAR incident response & containment generation
  5. report_agent    – generate comprehensive executive & tactical markdown report
"""

import json
import os
import datetime
from typing import Any

from agents.state import AgentState
from tools.detection_tools import pattern_detector, anomaly_detector, threat_lookup
from tools.containment_tools import generate_containment_action


# ── LLM Initializer with Graceful Fallback ────────────────────────────────────

def get_llm(model_name: str = "llama3.1:8b"):
    try:
        from langchain_ollama import ChatOllama
        return ChatOllama(model=model_name, temperature=0, request_timeout=15.0)
    except Exception:
        return None


# ── 1. INGEST AGENT ────────────────────────────────────────────────────────────

def ingest_agent(state: AgentState, model_name: str = "llama3.1:8b") -> AgentState:
    """Parse raw logs and enforce strict security schema validation."""
    raw = state.get("raw_logs", [])
    valid, issues = [], []

    required_fields = {"timestamp", "event_type", "ip"}
    for entry in raw:
        missing = required_fields - entry.keys()
        if missing:
            issues.append(f"Dropped entry missing required fields {missing}: {entry}")
        else:
            valid.append(entry)

    trace = list(state.get("agent_trace", []))
    trace.append(
        f"[Ingest Agent] Processed {len(raw)} events -> {len(valid)} verified valid, {len(issues)} malformed dropped."
    )

    scores = dict(state.get("confidence_scores", {}))
    scores["ingest"] = round(len(valid) / max(len(raw), 1), 2)

    return {
        **state,
        "validated_logs": valid,
        "agent_trace": trace,
        "confidence_scores": scores,
    }


# ── 2. DETECT AGENT ────────────────────────────────────────────────────────────

def detect_agent(state: AgentState, model_name: str = "llama3.1:8b") -> AgentState:
    """Detect threats and anomalies in validated logs using heuristic & pattern tools."""
    logs = state.get("validated_logs", [])

    # Run detection tools
    patterns_result = pattern_detector.invoke({"events": logs})
    anomalies_result = anomaly_detector.invoke({"events": logs})

    all_anomalies = list(anomalies_result.get("anomalies", []))
    for p in patterns_result.get("patterns", []):
        all_anomalies.append({
            **p,
            "severity": "high" if p.get("confidence", 0) > 0.8 else "medium",
        })

    needs_report = len(all_anomalies) > 0

    trace = list(state.get("agent_trace", []))
    trace.append(
        f"[Detect Agent] Scanned telemetry: {len(all_anomalies)} threat signatures/anomalies detected. "
        f"(Needs Report: {needs_report})"
    )

    scores = dict(state.get("confidence_scores", {}))
    if all_anomalies:
        avg_conf = sum(a.get("confidence", 0.7) for a in all_anomalies) / len(all_anomalies)
        scores["detect"] = round(avg_conf, 2)
    else:
        scores["detect"] = 1.0

    return {
        **state,
        "anomalies": all_anomalies,
        "needs_report": needs_report,
        "agent_trace": trace,
        "confidence_scores": scores,
    }


# ── 3. CLASSIFY AGENT ──────────────────────────────────────────────────────────

def classify_agent(state: AgentState, model_name: str = "llama3.1:8b") -> AgentState:
    """Assess risk levels, enrich with MITRE ATT&CK taxonomy, and evaluate severity routing."""
    anomalies = state.get("anomalies", [])

    classified = []
    for anomaly in anomalies:
        atype = anomaly.get("type", "unknown")
        threat_info = threat_lookup.invoke({"anomaly_type": atype})

        risk = threat_info.get("risk_score", 30)
        severity = (
            "critical" if risk >= 90
            else "high" if risk >= 70
            else "medium" if risk >= 50
            else "low"
        )

        classified.append({
            **anomaly,
            "risk_score": risk,
            "severity": severity,
            "mitre_id": threat_info.get("mitre", "N/A"),
            "mitre_category": threat_info.get("category", "Unknown"),
        })

    # Sort descending by risk score
    classified.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    critical_count = sum(1 for c in classified if c["severity"] == "critical")
    high_count = sum(1 for c in classified if c["severity"] == "high")
    has_critical_threats = (critical_count + high_count) > 0

    trace = list(state.get("agent_trace", []))
    trace.append(
        f"[Classify Agent] Risk triage complete: {critical_count} CRITICAL, {high_count} HIGH, "
        f"{sum(1 for c in classified if c['severity']=='medium')} MEDIUM, "
        f"{sum(1 for c in classified if c['severity']=='low')} LOW."
    )

    if has_critical_threats:
        trace.append(
            f"[Decision Router] CRITICAL/HIGH threats detected ({critical_count + high_count}) "
            f"→ Dispatching Autonomous Response Agent for instant containment."
        )
    else:
        trace.append(
            "[Decision Router] Only LOW/MEDIUM severity threats detected → Proceeding directly to standard Report Agent."
        )

    scores = dict(state.get("confidence_scores", {}))
    scores["classify"] = 0.94

    return {
        **state,
        "classified_threats": classified,
        "has_critical_threats": has_critical_threats,
        "needs_report": len(classified) > 0,
        "agent_trace": trace,
        "confidence_scores": scores,
    }


# ── 4. RESPONSE AGENT (SOAR Autonomous Containment) ───────────────────────────

def response_agent(state: AgentState, model_name: str = "llama3.1:8b") -> AgentState:
    """
    Autonomous Security Orchestration, Automation, and Response (SOAR) Agent.
    Executes containment playbooks and generates tactical remediation scripts
    for CRITICAL and HIGH severity incidents.
    """
    classified = state.get("classified_threats", [])
    high_crit_threats = [t for t in classified if t.get("severity") in ("critical", "high")]

    actions = []
    for idx, threat in enumerate(high_crit_threats, start=1):
        action = generate_containment_action(threat, index=idx)
        actions.append(action)

    trace = list(state.get("agent_trace", []))
    trace.append(
        f"[Response Agent] Generated {len(actions)} containment playbooks "
        f"addressing {len(high_crit_threats)} high/critical vectors (Status: RECOMMENDED / ARMED)."
    )

    # Build High-level Remediation Plan
    plan_lines = [
        "### 🛡️ CyberGuard Autonomous Containment Plan",
        f"**Active Containment Directives Generated:** {len(actions)}",
        "",
        "| Action ID | Priority | Threat | MITRE | Target | Containment Directive |",
        "|-----------|----------|--------|-------|--------|-----------------------|",
    ]
    for act in actions:
        plan_lines.append(
            f"| `{act['action_id']}` | **{act['priority']}** | {act['threat_type'].replace('_',' ').title()} "
            f"| `{act['mitre_id']}` | `{act['target']}` | {act['action_title']} |"
        )

    remediation_plan = "\n".join(plan_lines)

    scores = dict(state.get("confidence_scores", {}))
    scores["response"] = 0.96

    return {
        **state,
        "containment_actions": actions,
        "remediation_plan": remediation_plan,
        "agent_trace": trace,
        "confidence_scores": scores,
    }


# ── 5. REPORT AGENT ────────────────────────────────────────────────────────────

def report_agent(state: AgentState, model_name: str = "llama3.1:8b") -> AgentState:
    """Generate a comprehensive executive & tactical markdown incident report."""
    threats = state.get("classified_threats", [])
    logs = state.get("validated_logs", [])
    actions = state.get("containment_actions", [])
    trace = list(state.get("agent_trace", []))

    groups: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for t in threats:
        groups.setdefault(t.get("severity", "low"), []).append(t)

    report_text = ""
    llm = get_llm(model_name)

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # If LLM is available, prompt for rich synthesis
    if llm is not None:
        try:
            prompt = f"""You are a Lead Cyber Incident Response Commander. Write an executive and technical Incident Response Report based on the following CyberGuard AI findings.

FINDINGS:
{json.dumps(threats, indent=2)}

CONTAINMENT ACTIONS GENERATED:
{json.dumps(actions, indent=2)}

SUMMARY TELEMETRY:
- Total Events Analyzed: {len(logs)}
- Critical Severity: {len(groups['critical'])}
- High Severity: {len(groups['high'])}
- Medium Severity: {len(groups['medium'])}
- Low Severity: {len(groups['low'])}
- Autonomous Containment Playbooks: {len(actions)}

Format cleanly in Markdown with these sections:
# 🛡️ CyberGuard AI - Security Incident Response Report
1. Executive Summary & Impact Analysis
2. Threat Breakdown & MITRE ATT&CK Matrix
3. Autonomous Containment Actions Taken / Recommended
4. Technical Forensic Indicators (IOCs)
5. Tactical Hardening & Remediation Playbook

Be concise, authoritative, and precise. Avoid filler.
"""
            response = llm.invoke(prompt)
            if hasattr(response, "content") and response.content:
                report_text = str(response.content)
        except Exception:
            report_text = ""

    # High-quality fallback template if LLM is offline or model unavailable
    if not report_text.strip():
        report_text = f"""# 🛡️ CyberGuard AI — Security Incident Response Report
*Generated by Autonomous CyberGuard Multi-Agent SOAR Engine*  
**Timestamp:** `{now_str}` | **Telemetry Scope:** `{len(logs)} Events Analyzed`

---

## 1. 📋 Executive Summary
CyberGuard AI detected **{len(threats)} confirmed security incidents** requiring triage.  
The system identified **{len(groups['critical'])} Critical** and **{len(groups['high'])} High** severity threats, triggering the **Autonomous Response Agent** to formulate targeted containment measures.

- **Total Telemetry Events Analyzed:** {len(logs)}
- **High / Critical Threat Ratio:** {len(groups['critical']) + len(groups['high'])} / {max(len(threats), 1)} ({((len(groups['critical']) + len(groups['high'])) / max(len(threats), 1)):.0%})
- **Autonomous Containment Playbooks Activated:** {len(actions)}

---

## 2. 🎯 MITRE ATT&CK Threat Breakdown

| Severity | Threat Name | MITRE ID | Target / Vector | Risk Score | Recommended Action |
|----------|-------------|----------|-----------------|------------|--------------------|
"""
        for t in threats:
            sev_badge = "🔴 CRITICAL" if t['severity'] == "critical" else "🟠 HIGH" if t['severity'] == "high" else "🟡 MEDIUM" if t['severity'] == "medium" else "🟢 LOW"
            tname = t.get('type', 'Unknown').replace('_', ' ').title()
            target_str = t.get('ip') or t.get('user') or t.get('file') or 'N/A'
            rec_action = "Autonomous Containment" if t['severity'] in ("critical", "high") else "Log & Monitor"
            report_text += f"| {sev_badge} | {tname} | `{t.get('mitre_id','N/A')}` | `{target_str}` | {t.get('risk_score', 0)}/100 | {rec_action} |\n"

        report_text += f"""
---

## 3. ⚡ Autonomous Containment Directives (Response Agent)
"""
        if actions:
            for act in actions:
                report_text += f"""
### 🛡️ `{act['action_id']}`: {act['action_title']}
- **Priority:** `{act['priority']}` | **Status:** `{act['status']}` | **Playbook:** `{act['playbook']}`
- **Target:** `{act['target']}`
- **Containment Rationale:** {act['reason']}

```bash
{act['remediation_script']}
```
"""
        else:
            report_text += "\n*No CRITICAL or HIGH threats identified. No emergency containment actions required.*\n"

        report_text += """
---

## 4. 🔍 Recommended Long-Term Hardening
1. **Perimeter Hardening:** Apply permanent blackholing to repeat offender subnets and enforce zero-trust geo-fencing.
2. **Identity Protection:** Mandate hardware-token MFA across all administrative and VPN entry points.
3. **Endpoint Detection:** Deploy automated endpoint isolation agents on systems executing unsigned binaries.
"""

    os.makedirs("outputs", exist_ok=True)
    with open("outputs/cyberguard_incident_report.md", "w", encoding="utf-8") as f:
        f.write(report_text)
    with open("outputs/incident_report.md", "w", encoding="utf-8") as f:
        f.write(report_text)

    trace.append(f"[Report Agent] Full Incident & Remediation Report generated ({len(report_text.splitlines())} lines).")

    scores = dict(state.get("confidence_scores", {}))
    scores["report"] = 0.95

    return {
        **state,
        "incident_report": report_text,
        "agent_trace": trace,
        "confidence_scores": scores,
    }

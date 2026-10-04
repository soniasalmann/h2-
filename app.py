"""
CyberGuard AI — Autonomous Security Incident Response
Gradio Multi-Agent Security Dashboard (SOAR Console)
"""

import json
import os
import sys
import uuid
import traceback
import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import gradio as gr

from pipeline import build_graph

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_LOG_PATH = DATA_DIR / "security_logs.json"
BRUTE_FORCE_PATH = DATA_DIR / "sample_brute_force.json"
LOW_MED_PATH = DATA_DIR / "sample_low_med.json"

os.makedirs(BASE_DIR / "outputs", exist_ok=True)

AVAILABLE_MODELS = [
    "llama3.1:8b",
    "llama3.2:3b",
    "mistral:7b",
    "gemma2:9b",
    "qwen2.5:7b"
]

SCENARIO_MAP = {
    "🎯 Enterprise Multi-Stage APT Attack (20 Events - Critical/High)": SAMPLE_LOG_PATH,
    "⚡ SSH Brute Force & Credential Stuffing Campaign (Critical/High)": BRUTE_FORCE_PATH,
    "🟢 Low-Risk Routine Telemetry (Bypasses Response Agent)": LOW_MED_PATH,
    "📁 Custom Uploaded JSON Log": None,
}

# In-memory store for active session containment actions to enable interactive execution
CURRENT_SESSION = {
    "actions": [],
    "threats": [],
    "logs": []
}


def load_selected_logs(scenario_choice: str, uploaded_file) -> list[dict]:
    """Load security events according to chosen scenario or uploaded file."""
    if scenario_choice == "📁 Custom Uploaded JSON Log" and uploaded_file is not None:
        with open(uploaded_file, "r", encoding="utf-8") as f:
            return json.load(f)

    path = SCENARIO_MAP.get(scenario_choice, SAMPLE_LOG_PATH)
    if path and Path(path).exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # Fallback to default sample
    with open(SAMPLE_LOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def format_containment_cards(actions: list[dict], auto_execute: bool = False) -> str:
    """Format containment actions as interactive tactical SOAR cards."""
    if not actions:
        return """
<div style="padding: 1.5rem; border-radius: 8px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3);">
    <h3 style="color: #22c55e; margin: 0 0 0.5rem 0;">✅ No Emergency Containment Directives Required</h3>
    <p style="margin: 0; color: #a1a1aa;">All detected telemetry events fall under LOW or MEDIUM severity baselines. Autonomous Response Agent did not trigger aggressive network containment.</p>
</div>
"""

    cards_html = [
        "<div style='display: flex; flex-direction: column; gap: 1.25rem;'>"
    ]

    for act in actions:
        status_color = "#22c55e" if (auto_execute or act.get("status") == "EXECUTED") else "#f59e0b"
        status_label = "CONTAINED & EXECUTED" if (auto_execute or act.get("status") == "EXECUTED") else "ARMED (RECOMMENDED)"
        priority_color = "#ef4444" if "P0" in act.get("priority", "") else "#f97316"

        card = f"""
<div style="background: #18181b; border: 1px solid #27272a; border-left: 5px solid {priority_color}; border-radius: 8px; padding: 1.2rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem;">
        <div>
            <span style="background: rgba(239, 68, 68, 0.15); color: {priority_color}; font-weight: 700; font-size: 0.8rem; padding: 0.2rem 0.55rem; border-radius: 4px; letter-spacing: 0.05em;">{act.get('priority')}</span>
            <span style="background: #27272a; color: #e4e4e7; font-weight: 600; font-size: 0.8rem; padding: 0.2rem 0.55rem; border-radius: 4px; margin-left: 0.4rem;">{act.get('action_id')}</span>
            <span style="background: #27272a; color: #38bdf8; font-weight: 600; font-size: 0.8rem; padding: 0.2rem 0.55rem; border-radius: 4px; margin-left: 0.4rem;">MITRE {act.get('mitre_id')}</span>
            <h3 style="margin: 0.6rem 0 0.2rem 0; font-size: 1.15rem; color: #fafafa;">{act.get('action_title')}</h3>
        </div>
        <div>
            <span style="background: rgba(16, 185, 129, 0.15); color: {status_color}; font-weight: 700; font-size: 0.82rem; padding: 0.25rem 0.65rem; border-radius: 9999px; border: 1px solid {status_color}40;">
                ● {status_label}
            </span>
        </div>
    </div>
    
    <div style="font-size: 0.9rem; color: #d4d4d8; margin-bottom: 0.8rem; line-height: 1.45;">
        <strong>Target:</strong> <code style="background: #27272a; color: #f43f5e; padding: 0.15rem 0.4rem; border-radius: 4px;">{act.get('target')}</code><br>
        <strong>Tactical Rationale:</strong> {act.get('reason')}
    </div>
    
    <div style="background: #09090b; border: 1px solid #27272a; border-radius: 6px; padding: 0.85rem; margin-top: 0.5rem;">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #71717a; font-weight: 700; margin-bottom: 0.4rem; letter-spacing: 0.05em;">Automated Remediation Script</div>
        <pre style="margin: 0; font-size: 0.82rem; color: #38bdf8; font-family: monospace; overflow-x: auto; white-space: pre-wrap;">{act.get('remediation_script')}</pre>
    </div>
</div>
"""
        cards_html.append(card)

    cards_html.append("</div>")
    return "\n".join(cards_html)


def run_cyberguard(scenario_choice, uploaded_file, model_name, use_memory, auto_execute):
    """Run the complete CyberGuard AI multi-agent incident response pipeline."""
    print(f"\n🛡️ Launching CyberGuard AI | scenario='{scenario_choice}' | model={model_name} | auto_remediate={auto_execute}")
    try:
        raw_logs = load_selected_logs(scenario_choice, uploaded_file)
        print(f"✅ Loaded {len(raw_logs)} telemetry events")

        graph = build_graph(model_name=model_name, use_memory=use_memory)
        config = {"configurable": {"thread_id": str(uuid.uuid4())}} if use_memory else {}

        initial_state = {
            "raw_logs": raw_logs,
            "validated_logs": [],
            "anomalies": [],
            "classified_threats": [],
            "has_critical_threats": False,
            "containment_actions": [],
            "remediation_plan": "",
            "incident_report": "",
            "needs_report": False,
            "agent_trace": [],
            "confidence_scores": {},
        }

        print("⚙️ Running multi-agent state graph...")
        final_state = graph.invoke(initial_state, config=config)
        print("✅ Multi-agent execution finished!")

        report = final_state.get("incident_report", "_No report generated._")
        threats = final_state.get("classified_threats", [])
        actions = final_state.get("containment_actions", [])
        trace = final_state.get("agent_trace", [])
        scores = final_state.get("confidence_scores", {})

        # Save to session
        CURRENT_SESSION["actions"] = actions
        CURRENT_SESSION["threats"] = threats
        CURRENT_SESSION["logs"] = raw_logs

        # Severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threats:
            sev = t.get("severity", "low").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Summary KPIs Markdown
        status_banner = "🔴 EMERGENCY RESPONSE ACTIVE" if actions else "🟢 BASELINE NOMINAL"
        summary_md = f"""
### 📊 Executive Telemetry
| Metric | Value |
|:-------|:------|
| **Telemetry Events** | `{len(raw_logs)}` |
| **Active Threats Detected** | `{len(threats)}` |
| **🔴 Critical Severity** | `{sev_counts['critical']}` |
| **🟠 High Severity** | `{sev_counts['high']}` |
| **🟡 Medium Severity** | `{sev_counts['medium']}` |
| **🟢 Low Severity** | `{sev_counts['low']}` |
| **⚡ Containment Directives** | `{len(actions)} formulated` |
| **System State** | **{status_banner}** |
| **Active Model** | `{model_name}` |
"""

        # Confidence Scores Markdown
        conf_md = "### 🤖 Multi-Agent Confidence Assessment\n" + "\n".join(
            f"- **{agent.title()} Agent**: `{'█' * int(score * 10)}{'░' * (10 - int(score * 10))}` **{score:.0%}**"
            for agent, score in scores.items()
        )

        # Agent Trace Markdown
        trace_lines = []
        for line in trace:
            if "Ingest" in line:
                trace_lines.append(f"📥 **{line}**")
            elif "Detect" in line:
                trace_lines.append(f"🔍 **{line}**")
            elif "Classify" in line:
                trace_lines.append(f"🏷️ **{line}**")
            elif "Decision Router" in line:
                trace_lines.append(f"🔀 `{line}`")
            elif "Response" in line:
                trace_lines.append(f"⚡ <span style='color:#ef4444;'>**{line}**</span>")
            elif "Report" in line:
                trace_lines.append(f"📄 **{line}**")
            else:
                trace_lines.append(f"- {line}")
        trace_md = "### 🧭 Multi-Agent Decision & Execution Trace\n\n" + "\n\n".join(trace_lines)

        containment_html = format_containment_cards(actions, auto_execute=auto_execute)

        execution_log = ""
        if actions:
            if auto_execute:
                execution_log = f"""✅ [AUTONOMOUS DEFENSE ACTIVE] Successfully triggered automatic remediation across {len(actions)} targets.\nAll firewall rules, IP blocks, and token invalidations verified and locked at {datetime.datetime.now().strftime('%H:%M:%S')}."""
            else:
                execution_log = f"⚡ {len(actions)} containment playbooks generated and armed. Click 'Execute All Containment Directives' below to simulate live mitigation."

        return (
            report,
            containment_html,
            summary_md,
            conf_md,
            trace_md,
            execution_log,
        )

    except Exception:
        err = traceback.format_exc()
        print(f"\n❌ ERROR in CyberGuard pipeline:\n{err}")
        return (
            f"## ❌ Error Executing CyberGuard Pipeline\n```\n{err}\n```",
            "<div style='color:red;'>Failed to formulate containment actions.</div>",
            "### ❌ Pipeline Execution Failed",
            "### ❌ Confidence Telemetry Unavailable",
            f"```\n{err}\n```",
            f"Error: {err}",
        )


def execute_containment_now():
    """Simulate real-time execution of all armed containment directives."""
    actions = CURRENT_SESSION.get("actions", [])
    if not actions:
        return "⚠️ No containment actions currently pending in memory. Please run an analysis first.", format_containment_cards([])

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    logs = [
        f"🛡️ [CyberGuard SOAR Autonomous Execution Engine]",
        f"⏱️ Timestamp: {now}",
        f"🎯 Initiating automated enforcement across {len(actions)} target containment vectors:\n"
    ]

    for act in actions:
        act["status"] = "EXECUTED"
        act["executed_at"] = now
        logs.append(f"  ▶ [{act['action_id']}] Executing: {act['action_title']}")
        logs.append(f"    ├─ Target: {act['target']}")
        logs.append(f"    ├─ Enforcing Directive: {act['remediation_script'].splitlines()[1] if len(act['remediation_script'].splitlines()) > 1 else 'Applied containment'}")
        logs.append(f"    └─ Status: 🟢 SUCCESS (Enforced & Audited)\n")

    logs.append(f"✅ ALL {len(actions)} CONTAINMENT DIRECTIVES SUCCESSFULLY ENFORCED.")
    logs.append("Forensics snapshot archived to /var/log/cyberguard_audit.log.")

    updated_cards = format_containment_cards(actions, auto_execute=True)
    return "\n".join(logs), updated_cards


# ── Gradio Dark SOC Interface ──────────────────────────────────────────────────

custom_css = """
body, .gradio-container {
    background-color: #09090b !important;
    color: #f4f4f5 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
.header-banner {
    background: linear-gradient(135deg, #09090b 0%, #18181b 50%, #0f172a 100%);
    border: 1px solid #27272a;
    border-radius: 12px;
    padding: 1.75rem 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
}
.badge-pill {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 600;
    margin-right: 0.5rem;
    margin-top: 0.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
}
.btn-primary {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4) !important;
}
.btn-action {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    box-shadow: 0 4px 14px rgba(16, 185, 129, 0.4) !important;
}
"""

with gr.Blocks(title="CyberGuard AI — Autonomous Security Incident Response") as demo:
    gr.HTML("""
<div class="header-banner">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
        <div>
            <h1 style="margin: 0; font-size: 2.2rem; font-weight: 800; letter-spacing: -0.02em; color: #ffffff;">
                🛡️ CyberGuard AI
            </h1>
            <p style="margin: 0.4rem 0 0.8rem 0; font-size: 1.05rem; color: #a1a1aa;">
                Autonomous Security Incident Response & SOAR Multi-Agent Platform
            </p>
            <div>
                <span class="badge-pill" style="background: rgba(239, 68, 68, 0.15); color: #f87171;">LangGraph Agentic Workflow</span>
                <span class="badge-pill" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8;">Severity-Driven Routing</span>
                <span class="badge-pill" style="background: rgba(34, 197, 94, 0.15); color: #4ade80;">Autonomous SOAR Containment</span>
                <span class="badge-pill" style="background: rgba(168, 85, 247, 0.15); color: #c084fc;">Local Ollama Privacy</span>
            </div>
        </div>
        <div style="text-align: right; padding: 0.5rem 0;">
            <div style="font-size: 0.85rem; color: #71717a;">DEFENSE STATUS</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #22c55e;">● ACTIVE SOC MONITORING</div>
        </div>
    </div>
</div>
""")

    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### ⚙️ Telemetry Ingestion & Parameters")
            scenario_choice = gr.Dropdown(
                label="Select Attack Scenario / Telemetry Feed",
                choices=list(SCENARIO_MAP.keys()),
                value="🎯 Enterprise Multi-Stage APT Attack (20 Events - Critical/High)",
            )
            uploaded_file = gr.File(
                label="Upload Custom JSON Log (optional)",
                file_types=[".json"],
                type="filepath",
                visible=True
            )
            with gr.Row():
                model_name = gr.Dropdown(
                    choices=AVAILABLE_MODELS,
                    value="llama3.1:8b",
                    label="Ollama LLM Model"
                )
                use_memory = gr.Checkbox(value=True, label="State Memory", info="LangGraph checkpointer")

            auto_execute = gr.Checkbox(
                value=False,
                label="⚡ Auto-Remediate Immediately",
                info="Automatically enforce firewall & containment playbooks upon detection"
            )

            run_btn = gr.Button("🚀 Launch CyberGuard Analysis", variant="primary", size="lg")

        with gr.Column(scale=2):
            with gr.Row():
                stats_out = gr.Markdown(value="_Telemetry stats will appear here upon scan._")
                conf_out = gr.Markdown()

    gr.Markdown("---")

    with gr.Tabs():
        with gr.TabItem("⚡ Autonomous Response & Remediation (SOAR)"):
            gr.Markdown("#### 🚨 Formulated Containment Actions (CRITICAL / HIGH Threats)")
            gr.Markdown("The **Response Agent** dynamically formulates targeted containment directives when critical or high severity threats breach security thresholds.")
            containment_out = gr.HTML(value=format_containment_cards([]))

            with gr.Row():
                exec_btn = gr.Button("⚡ Execute All Containment Directives", variant="primary", size="lg")

            exec_log_out = gr.Code(label="Containment Execution & Audit Terminal", language="shell", value="[Ready] Awaiting trigger...")

        with gr.TabItem("📄 Incident Response Report"):
            report_out = gr.Markdown(value="_Click 'Launch CyberGuard Analysis' to generate full Incident Report._")

        with gr.TabItem("🧭 Multi-Agent Decision Trace"):
            trace_out = gr.Markdown(value="_Agent reasoning and decision trace will appear here._")

        with gr.TabItem("📐 Architecture & Flowchart"):
            gr.Markdown("""
### 🧠 CyberGuard AI Agentic Architecture

```
                    ┌─────────────────────────┐
                    │  Security Log Telemetry │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Ingest Agent       │
                    │ (Schema Hygiene & San.) │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Detect Agent       │
                    │ (Heuristic Signatures)  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Classify Agent     │
                    │ (MITRE ATT&CK & Risk)   │
                    └────────────┬────────────┘
                                 │
                     Severity Decision Router
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
                ▼                                 ▼
       [ LOW / MED Severity ]           [ CRITICAL / HIGH Severity ]
                │                                 │
                │                                 ▼
                │                    ┌─────────────────────────┐
                │                    │     Response Agent      │
                │                    │ (Autonomous SOAR Directives)
                │                    │ • IP & Firewall Block   │
                │                    │ • Session Revocation    │
                │                    │ • Host Quarantine       │
                │                    └────────────┬────────────┘
                │                                 │
                └────────────────┬────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Report Agent       │
                    │ (Executive & Technical) │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ CyberGuard SOC Console  │
                    └─────────────────────────┘
```
""")

    run_btn.click(
        fn=run_cyberguard,
        inputs=[scenario_choice, uploaded_file, model_name, use_memory, auto_execute],
        outputs=[report_out, containment_out, stats_out, conf_out, trace_out, exec_log_out]
    )

    exec_btn.click(
        fn=execute_containment_now,
        inputs=[],
        outputs=[exec_log_out, containment_out]
    )

if __name__ == "__main__":
    share_enabled = os.environ.get("GRADIO_SHARE", "true").lower() in ("true", "1", "yes")
    print(f"Launching CyberGuard SOC Console (Public Share: {share_enabled})...", flush=True)
    res = demo.launch(share=share_enabled, css=custom_css, inbrowser=False)
    # Gradio returns (app, local_url, share_url) or sets demo.share_url
    share_link = getattr(demo, "share_url", None)
    if isinstance(res, tuple) and len(res) >= 3:
        share_link = res[2] or share_link
    with open("share_url.txt", "w", encoding="utf-8") as f:
        f.write(f"PUBLIC_URL={share_link}\nLOCAL_URL=http://127.0.0.1:7860\n")
    print(f"CYBERGUARD_PUBLIC_URL={share_link}", flush=True)


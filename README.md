# 🛡️ CyberGuard AI: Autonomous Security Incident Response

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-black.svg)](https://ollama.com)
[![Gradio](https://img.shields.io/badge/Gradio-SOC%20Console-orange.svg)](https://gradio.app)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Autonomous Multi-Agent SOAR Platform**  
> *From Telemetry Detection to Autonomous Network Containment in Seconds.*

---

## 💡 The Problem: SOC Alert Fatigue & Lagging MTTC

Traditional Security Operations Centers (SOCs) are overwhelmed by thousands of disconnected security alerts every day. Analysts spend hours triaging logs, cross-referencing MITRE ATT&CK tactics, and manually writing remediation scripts. By the time containment actions are authorized, attackers have already escalated privileges and exfiltrated sensitive data.

**CyberGuard AI** changes the paradigm from **passive detection** to **autonomous security incident response (SOAR)**. Using a multi-agent state graph orchestrated with **LangGraph**, it autonomously parses telemetry, correlates threats, assesses risk severity, and—when critical thresholds are breached—instantly synthesizes and executes targeted containment directives across operating systems and cloud environments.

---

## 🏗️ Architecture & Dynamic Severity Branching

CyberGuard AI introduces **dynamic severity-based routing** to balance operational uptime with aggressive threat neutralization:

```
                     Security Logs (JSON / Live Telemetry)
                                       │
                                 [Ingest Agent]
                            (Schema Hygiene & Validation)
                                       │
                                 [Detect Agent]
                            (Heuristics & Signatures)
                                       │
                                [Classify Agent]
                           (MITRE ATT&CK & Severity)
                                       │
                           Severity Decision Router
                                       │
                   ┌───────────────────┴───────────────────┐
                   ▼                                       ▼
          [ LOW / MED Threats ]                 [ CRITICAL / HIGH Threats ]
                   │                                       │
                   │                                       ▼
                   │                                [Response Agent]
                   │                            (Autonomous SOAR Directives)
                   │                            • iptables & Firewall Rule Gen
                   │                            • Endpoint Host Quarantine
                   │                            • Session Revocation & Lockout
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                                 [Report Agent]
                         (Executive & Tactical Report)
                                       │
                                       ▼
                            CyberGuard SOC Console
                    (One-Click Enforcement & Live Audit)
```

### Routing Logic
- **LOW / MEDIUM Severity**: Routine events (e.g., policy deviations, baseline scans) route directly to the **Report Agent** for compliance documentation without disrupting active network infrastructure.
- **CRITICAL / HIGH Severity**: High-risk attack vectors immediately trigger the **Autonomous Response Agent**, formulating instant containment playbooks (firewall drops, process kills, host isolation) before generating the final report.

---

## 🤖 The Multi-Agent Ecosystem

| Agent | Architecture | Responsibility |
|:------|:-------------|:---------------|
| **📥 Ingest Agent** | LangGraph Node | Sanitizes raw telemetry, validates schema integrity (`timestamp`, `ip`, `event_type`), drops malformed records, and computes ingest confidence scores. |
| **🔍 Detect Agent** | LangGraph Node + Heuristic Tools | Correlates multi-event attack patterns (brute force surges, credential stuffing) and flags behavioral anomalies. |
| **🏷️ Classify Agent** | LangGraph Node + MITRE Database | Enriches findings with MITRE ATT&CK IDs, calculates composite risk scores (0–100), tags severity, and sets the routing decision flag. |
| **⚡ Response Agent (SOAR)** | LangGraph Node + Containment Generators | **Core Innovation:** Formulates multi-platform mitigation scripts (Linux iptables, Windows Defender Firewall, Active Directory, AWS IAM/CLI). |
| **📄 Report Agent** | LangGraph Node + Ollama LLM | Produces an executive incident summary, forensic artifact table, and tactical remediation roadmap. |

---

## 🛡️ Autonomous Containment Playbooks

When critical or high threats are verified, the Response Agent generates actionable mitigation playbooks:

| Threat Vector | MITRE ID | Risk | Severity | Automated Containment Action |
|:---|:---|:---:|:---:|:---|
| **SSH Brute Force** | `T1110` | 75 | **HIGH** | Ingress IP drop (`iptables -A INPUT -s <IP> -j DROP`), Windows Firewall rule, account lock challenge. |
| **Credential Stuffing** | `T1110.004` | 85 | **HIGH** | Immediate perimeter blocklist, OAuth token purge, step-up MFA challenge. |
| **Data Exfiltration** | `T1041` | 95 | **CRITICAL** | Socket severance (`ss -K`), egress network filter, isolation to forensics VLAN. |
| **Privilege Escalation** | `T1068` | 90 | **HIGH** | Strip sudoer group membership, terminate process tree (`pkill -u <user> -9`). |
| **Malware Execution** | `T1204` | 98 | **CRITICAL** | Revoke execution permission (`chmod 000`), secure vault quarantine, SHA-256 IOC calculation. |
| **Compromised Account** | `T1078` | 70 | **HIGH** | Purge active Redis sessions, force password reset flag via identity provider. |

---

## 🖥️ Interactive SOC Console (Gradio)

The CyberGuard AI console provides security analysts with full command and visibility:

1. **Preset Telemetry & Scenario Feed**:
   - `🎯 Enterprise Multi-Stage APT Attack (20 Events)`: Full attack chain featuring reconnaissance, brute force, lateral escalation, and data exfiltration.
   - `⚡ SSH Brute Force Campaign`: High-frequency credential access assault demonstrating automated IP blocking.
   - `🟢 Low-Risk Routine Telemetry`: Demonstrates the LangGraph decision router bypassing the Response Agent directly to reporting.
   - `📁 Custom JSON Log Upload`: Upload your own enterprise telemetry logs.
2. **SOAR Containment Console**:
   - Real-time tactical cards displaying Priority (`P0 - EMERGENCY`, `P1 - IMMEDIATE`), Target, MITRE ATT&CK ID, and copy-ready scripts.
   - **"⚡ Execute All Containment Directives"** button to simulate live mitigation with a real-time audit terminal.
3. **Executive Incident Report Tab**:
   - Full rendered Markdown report with forensic IOCs, MITRE mapping, and executive hardening recommendations.
4. **Multi-Agent Decision Trace**:
   - Step-by-step reasoning trace revealing every agent's thought process, confidence score, and decision branches.

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- [Ollama](https://ollama.com) *(Optional for local LLM synthesis — built-in heuristic fallback runs seamlessly even without active models)*

### Setup

```bash
# 1. Clone repository
git clone https://github.com/soniasalmann/h2-.git
cd h2-

# 2. Create virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Launch the Application

```bash
python app.py
```

Then open **[http://localhost:7860](http://localhost:7860)** in your browser.

### Run Automated Pipeline Tests

```bash
python test_pipeline.py
```

---

## 📁 Repository Structure

```
h2-/
├── app.py                      # Gradio Dark SOC dashboard & execution engine
├── pipeline.py                 # LangGraph state graph & conditional severity router
├── requirements.txt            # Project dependencies
├── test_pipeline.py            # Automated test suite for multi-scenario verification
├── README.md                   # Project documentation & architecture guide
├── agents/
│   ├── __init__.py
│   ├── state.py                # AgentState TypedDict definition
│   └── nodes.py                # Ingest, Detect, Classify, Response, and Report agents
├── tools/
│   ├── __init__.py
│   ├── detection_tools.py      # Heuristic pattern & anomaly detection tools
│   └── containment_tools.py    # Autonomous SOAR containment script generators
└── data/
    ├── security_logs.json      # Enterprise 20-event multi-stage APT scenario
    ├── sample_brute_force.json # Targeted SSH brute force test dataset
    └── sample_low_med.json     # Low/Med routine telemetry scenario
```

---

## 🏆 Hackathon Alignment

- **Agentic AI & Multi-Agent Systems**: 5 coordinated agents operating over a shared state graph with conditional routing.
- **Autonomous Incident Response**: Proactive SOAR containment generation rather than passive alert generation.
- **Production-Ready & Privacy-Preserving**: Runs completely offline with Ollama or local deterministic engines — zero external API keys or cloud telemetry leakage required.
- **Standardized Frameworks**: Built on industry-standard MITRE ATT&CK taxonomy and LangGraph workflows.

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.

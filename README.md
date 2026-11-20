# 🛡️ CyberGuard AI: Multi-Agent SOC Simulation Lab

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Gradio](https://img.shields.io/badge/UI-Gradio-blueviolet.svg)](https://gradio.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Notice**: This project is built for **educational, learning, and practice purposes**. It provides a safe simulation environment demonstrating how multi-agent state machines can assist SOC analysts with log triage, threat classification, and response script formulation. Containment directives are generated for **demonstration/review only** and are not executed against production systems.

---

## 📌 Overview

Traditional Security Operations Centers (SOCs) face alert fatigue from high-volume security logs. **CyberGuard AI** is a prototype AI-assisted SOAR workflow that automates Tier-1 incident triage:

1. **Ingest & Validate**: Sanitizes JSON telemetry and validates schema consistency.
2. **Detect**: Correlates events to identify attack patterns (e.g., brute-force spikes, credential stuffing).
3. **Classify**: Assigns MITRE ATT&CK technique IDs and computes composite threat risk scores (0–100).
4. **Conditional Routing**:
   - `LOW / MEDIUM`: Directly summarized into reports without disrupting network configurations.
   - `HIGH / CRITICAL`: Triggers mitigation playbook generation for rapid response review.
5. **Report & Containment**: Generates an incident summary via local LLM (Ollama) or deterministic fallback, alongside copy-ready containment commands.

---

## 🏗️ Architecture

```
                 Raw Security Logs (JSON Telemetry)
                                │
                          [Ingest Agent]
                   (Schema Hygiene & Validation)
                                │
                          [Detect Agent]
                     (Pattern & Anomaly Checks)
                                │
                         [Classify Agent]
                    (MITRE ATT&CK & Severity)
                                │
                     Severity Routing Decision
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
    [ LOW / MEDIUM Severity ]            [ HIGH / CRITICAL Severity ]
             │                                     │
             │                                     ▼
             │                             [Response Agent]
             │                       (Containment Script Synthesis)
             │                       • iptables / Windows Firewall
             │                       • Host quarantine / Kill commands
             │                                     │
             └──────────────────┬──────────────────┘
                                │
                                ▼
                          [Report Agent]
                   (Forensic Summary & IOC Table)
                                │
                                ▼
                       Interactive SOC Console
                (Gradio Dashboard & Audit Simulation)
```

---

## 🤖 Agents & Roles

| Agent | Core Function |
| :--- | :--- |
| **📥 Ingest** | Sanitizes schema fields (`timestamp`, `ip`, `event_type`) and filters malformed events. |
| **🔍 Detect** | Evaluates heuristics and frequency thresholds to flag suspicious activities. |
| **🏷️ Classify** | Maps events to MITRE ATT&CK techniques and calculates severity ratings. |
| **⚡ Response** | Generates defensive commands (Linux `iptables`, Windows Firewall, `pkill`, account lock flags). |
| **📄 Report** | Assembles forensic artifacts, risk summaries, and remediation recommendations. |

---

## 🛡️ Sample Containment Playbooks

| Threat Vector | MITRE ID | Risk Score | Severity | Generated Containment Action |
| :--- | :---: | :---: | :---: | :--- |
| **SSH Brute Force** | `T1110` | 75 | **HIGH** | Ingress block (`iptables -A INPUT -s <IP> -j DROP`), Windows Firewall rule |
| **Credential Stuffing** | `T1110.004` | 85 | **HIGH** | Perimeter IP blocklist, account step-up MFA challenge |
| **Data Exfiltration** | `T1041` | 95 | **CRITICAL** | Socket severance (`ss -K`), egress network filter |
| **Privilege Escalation** | `T1068` | 90 | **HIGH** | User process tree termination (`pkill -u <user> -9`) |
| **Malware Execution** | `T1204` | 98 | **CRITICAL** | Revoke execution permissions (`chmod 000`), isolate host |

---

## 🚀 Quickstart

### 1. Prerequisites
- Python 3.10 or higher
- *(Optional)* [Ollama](https://ollama.com/) running locally (the application seamlessly falls back to local deterministic templates if Ollama is not active).

### 2. Setup & Installation

#### Option A: Quick Run with Docker (Recommended)
```bash
docker compose up --build
```
Open **`http://localhost:7860`** in your browser.

#### Option B: Standard Python Environment
```bash
# Clone the repository
git clone https://github.com/soniasalmann/h2-.git
cd h2-

# Create and activate virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Application

```bash
# Start Gradio SOC Console
python app.py
```
Open **`http://localhost:7860`** in your browser.

### 4. Run Tests

```bash
# Run unit test suite (schema validation, heuristics, and playbooks)
python -m unittest discover -s tests -v

# Run multi-scenario pipeline integration verification
python test_pipeline.py
```

---

## 📁 Repository Structure

```
h2-/
├── Dockerfile              # Container definition (non-root security compliance)
├── docker-compose.yml      # Single-command local container orchestration
├── app.py                  # Gradio SOC console interface
├── pipeline.py             # LangGraph state graph & conditional router
├── requirements.txt        # Python dependencies
├── test_pipeline.py        # Multi-scenario integration pipeline tests
├── tests/                  # Automated unit test suite
│   ├── __init__.py
│   └── test_agents.py      # Unit tests for Ingest, Detect, Classify, & Containment
├── agents/
│   ├── state.py            # Shared AgentState TypedDict schema
│   └── nodes.py            # Ingest, Detect, Classify, Response, and Report agents
├── tools/
│   ├── detection_tools.py  # Anomaly detection & heuristics
│   └── containment_tools.py# Defensive mitigation script generators
└── data/
    ├── security_logs.json      # Multi-stage attack scenario dataset
    ├── sample_brute_force.json # SSH brute-force telemetry
    └── sample_low_med.json     # Low/Medium routine telemetry dataset
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

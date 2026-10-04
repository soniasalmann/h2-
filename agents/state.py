"""
Shared agent state for the CyberGuard AI Autonomous Security Incident Response system.
"""

from typing import TypedDict, Any


class AgentState(TypedDict):
    """State passed across all agents in the CyberGuard AI pipeline."""
    raw_logs: list[dict[str, Any]]             # Raw ingested log events
    validated_logs: list[dict[str, Any]]       # Cleaned and schema-validated logs
    anomalies: list[dict[str, Any]]            # Detected anomalies & pattern matches
    classified_threats: list[dict[str, Any]]   # MITRE-enriched, risk-scored threats
    has_critical_threats: bool                 # Flag routing to Autonomous Response Agent
    containment_actions: list[dict[str, Any]]  # Autonomous SOAR containment actions
    remediation_plan: str                      # High-level remediation playbook summary
    incident_report: str                       # Markdown incident report
    needs_report: bool                         # Whether report generation is required
    agent_trace: list[str]                     # Multi-agent decision and execution trace
    confidence_scores: dict[str, float]        # Per-agent confidence telemetry

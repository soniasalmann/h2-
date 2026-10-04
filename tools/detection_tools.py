"""
Detection tools: pattern detection, anomaly detection, threat lookup.
Used by the Detect agent node.
"""

from langchain_core.tools import tool


@tool
def pattern_detector(events: list[dict]) -> dict:
    """
    Detect suspicious patterns in log events.
    Looks for: brute force, credential stuffing, repeated failures.
    Returns detected patterns with confidence scores.
    """
    patterns = []
    ip_failures: dict[str, list] = {}

    for event in events:
        if event.get("event_type") == "login_failure":
            ip = event.get("ip", "unknown")
            ip_failures.setdefault(ip, []).append(event)

    for ip, failures in ip_failures.items():
        if len(failures) >= 3:
            patterns.append({
                "type": "brute_force",
                "ip": ip,
                "user": failures[0].get("user"),
                "count": len(failures),
                "confidence": min(0.95, 0.6 + len(failures) * 0.05),
                "service": failures[0].get("service"),
            })

    # Detect success after many failures (credential stuffing)
    ip_events: dict[str, list] = {}
    for event in events:
        ip = event.get("ip", "unknown")
        ip_events.setdefault(ip, []).append(event)

    for ip, evts in ip_events.items():
        types = [e["event_type"] for e in evts]
        failures = types.count("login_failure")
        if failures >= 3 and "login_success" in types:
            patterns.append({
                "type": "credential_stuffing",
                "ip": ip,
                "failures_before_success": failures,
                "confidence": 0.88,
            })

    return {"patterns": patterns, "total": len(patterns)}


@tool
def anomaly_detector(events: list[dict]) -> dict:
    """
    Detect anomalies: unusual countries, large data transfers,
    privilege escalation, malware, port scans, config changes.
    """
    anomalies = []
    suspicious_countries = {"NZ", "CN", "RU", "KP", "IR"}

    for event in events:
        etype = event.get("event_type", "")
        country = event.get("country", "")

        # Foreign login anomaly
        if etype == "login_success" and country in suspicious_countries:
            anomalies.append({
                "type": "foreign_login",
                "user": event.get("user"),
                "ip": event.get("ip"),
                "country": country,
                "severity": "high",
                "confidence": 0.82,
            })

        # Data exfiltration
        if etype == "data_exfiltration":
            bytes_out = event.get("bytes_out", 0)
            anomalies.append({
                "type": "data_exfiltration",
                "user": event.get("user"),
                "ip": event.get("ip"),
                "bytes_out_mb": round(bytes_out / 1_000_000, 2),
                "severity": "critical",
                "confidence": 0.95,
            })

        # Privilege escalation
        if etype == "privilege_escalation":
            anomalies.append({
                "type": "privilege_escalation",
                "user": event.get("user"),
                "ip": event.get("ip"),
                "severity": "high",
                "confidence": 0.90,
            })

        # Malware
        if etype == "malware_detected":
            anomalies.append({
                "type": "malware",
                "file": event.get("file"),
                "ip": event.get("ip"),
                "severity": "critical",
                "confidence": 0.97,
            })

        # Port scan
        if etype == "port_scan":
            ports = event.get("ports_scanned", 0)
            if ports > 500:
                anomalies.append({
                    "type": "port_scan",
                    "ip": event.get("ip"),
                    "ports_scanned": ports,
                    "severity": "medium",
                    "confidence": 0.78,
                })

    # Deduplicate by type+ip
    seen = set()
    unique = []
    for a in anomalies:
        key = (a["type"], a.get("ip", ""))
        if key not in seen:
            seen.add(key)
            unique.append(a)

    return {"anomalies": unique, "total": len(unique)}


@tool
def threat_lookup(anomaly_type: str) -> dict:
    """
    Look up known risk scores and mitre ATT&CK tags for a given anomaly type.
    """
    threat_db = {
        "brute_force":          {"risk_score": 75, "mitre": "T1110", "category": "Credential Access"},
        "credential_stuffing":  {"risk_score": 85, "mitre": "T1110.004", "category": "Credential Access"},
        "foreign_login":        {"risk_score": 70, "mitre": "T1078", "category": "Valid Accounts"},
        "data_exfiltration":    {"risk_score": 95, "mitre": "T1041", "category": "Exfiltration"},
        "privilege_escalation": {"risk_score": 90, "mitre": "T1068", "category": "Privilege Escalation"},
        "malware":              {"risk_score": 98, "mitre": "T1204", "category": "Execution"},
        "port_scan":            {"risk_score": 55, "mitre": "T1046", "category": "Discovery"},
        "config_change":        {"risk_score": 40, "mitre": "T1562", "category": "Defense Evasion"},
    }
    return threat_db.get(anomaly_type, {"risk_score": 30, "mitre": "Unknown", "category": "Unknown"})

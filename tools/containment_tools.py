"""
CyberGuard AI - Autonomous Incident Response & Containment Tools.
Provides automated playbooks, script generators, and remediation actions
for CRITICAL and HIGH severity cyber threats.
"""

from typing import Any
import datetime


def generate_containment_action(threat: dict[str, Any], index: int = 1) -> dict[str, Any]:
    """
    Generate an autonomous containment and remediation action package
    for a classified threat.
    """
    ttype = threat.get("type", "unknown")
    mitre_id = threat.get("mitre_id", "N/A")
    severity = threat.get("severity", "high").upper()
    user = threat.get("user", "unknown")
    ip = threat.get("ip", "unknown")
    action_id = f"ACT-{index:03d}"

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if ttype in ("brute_force", "credential_stuffing"):
        attempts = threat.get("count", threat.get("failures_before_success", 5))
        reason = (
            f"Detected {attempts} failed login attempts followed by credential access activity "
            f"from IP {ip} targeting user '{user}'."
        )
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"IP: {ip} | User: {user}",
            "action_title": f"Block Attacker IP & Lock User Credential ({ip})",
            "playbook": "IR-PB-AUTH-BRUTEFORCE-01",
            "status": "RECOMMENDED",
            "priority": "P1 - IMMEDIATE",
            "reason": reason,
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# 1. Block malicious ingress traffic from {ip}\n"
                f"iptables -A INPUT -s {ip} -j DROP\n"
                f"# Windows Defender Firewall Alternative:\n"
                f"New-NetFirewallRule -DisplayName 'CyberGuard_Block_{ip}' -Direction Inbound -Action Block -RemoteAddress '{ip}'\n\n"
                f"# 2. Temporarily lock compromised account '{user}' & force MFA challenge\n"
                f"usermod -L '{user}'\n"
                f"# AD Alternative: Disable-ADAccount -Identity '{user}'"
            ),
            "rollback_script": (
                f"iptables -D INPUT -s {ip} -j DROP\n"
                f"usermod -U '{user}'"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

    elif ttype == "data_exfiltration":
        bytes_mb = threat.get("bytes_out_mb", "Unknown")
        reason = (
            f"Critical data egress anomaly: {bytes_mb} MB outbound transfer "
            f"detected from host {ip} by user '{user}' to external receiver."
        )
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"Host IP: {ip} | User: {user}",
            "action_title": f"Sever Egress Channel & Isolate Endpoint ({ip})",
            "playbook": "IR-PB-DATA-EXFIL-03",
            "status": "RECOMMENDED",
            "priority": "P0 - CRITICAL EMERGENCY",
            "reason": reason,
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# 1. Terminate active socket sessions associated with exfiltration\n"
                f"ss -K dst {ip}\n\n"
                f"# 2. Sever outbound traffic to unauthorized external endpoints\n"
                f"iptables -I OUTPUT -d {ip} -j REJECT --reject-with icmp-admin-prohibited\n\n"
                f"# 3. Quarantine endpoint to forensics VLAN (VLAN 999)\n"
                f"ip link set dev eth0 down && ip link set dev eth0-quarantine up\n\n"
                f"# 4. Snapshot memory and active connections for DFIR forensics\n"
                f"lime-snapshot --output /var/log/forensics_{ip}.raw"
            ),
            "rollback_script": (
                f"iptables -D OUTPUT -d {ip} -j REJECT\n"
                f"ip link set dev eth0-quarantine down && ip link set dev eth0 up"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

    elif ttype == "privilege_escalation":
        reason = (
            f"Unauthorized elevation of privileges detected for user '{user}' on {ip} "
            f"via exploitative sudo/privilege abuse."
        )
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"User: {user} | Host: {ip}",
            "action_title": f"Revoke Superuser Permissions & Kill Session Tree ({user})",
            "playbook": "IR-PB-HOST-PRIVESC-02",
            "status": "RECOMMENDED",
            "priority": "P1 - HIGH",
            "reason": reason,
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# 1. Strip user '{user}' from sudoers and administrative groups\n"
                f"gpasswd -d '{user}' sudo\n"
                f"gpasswd -d '{user}' wheel\n\n"
                f"# 2. Terminate all active shells and child processes for '{user}'\n"
                f"pkill -u '{user}' -9\n\n"
                f"# 3. Invalidate Kerberos / SSH authorized_keys entries\n"
                f"mv /home/{user}/.ssh/authorized_keys /home/{user}/.ssh/authorized_keys.quarantined"
            ),
            "rollback_script": (
                f"gpasswd -a '{user}' sudo\n"
                f"mv /home/{user}/.ssh/authorized_keys.quarantined /home/{user}/.ssh/authorized_keys"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

    elif ttype == "malware":
        filename = threat.get("file", "unknown_binary")
        reason = (
            f"Malicious artifact '{filename}' identified on host {ip}. "
            f"Requires instant quarantine to prevent lateral propagation."
        )
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"File: {filename} | Host: {ip}",
            "action_title": f"Quarantine Malicious Payload & Isolate Host ({filename})",
            "playbook": "IR-PB-ENDPOINT-MALWARE-01",
            "status": "RECOMMENDED",
            "priority": "P0 - CRITICAL EMERGENCY",
            "reason": reason,
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# 1. Revoke execute permissions and move payload to secure vault\n"
                f"chmod 000 /tmp/{filename}\n"
                f"mv /tmp/{filename} /var/cyberguard/quarantine/{filename}.locked\n\n"
                f"# 2. Calculate cryptographic SHA-256 for threat intelligence sharing\n"
                f"sha256sum /var/cyberguard/quarantine/{filename}.locked >> /var/log/iocs.txt\n\n"
                f"# 3. Terminate running process instances matching filename\n"
                f"killall -9 '{filename}' 2>/dev/null || true"
            ),
            "rollback_script": (
                f"mv /var/cyberguard/quarantine/{filename}.locked /tmp/{filename}\n"
                f"chmod 755 /tmp/{filename}"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

    elif ttype == "foreign_login":
        country = threat.get("country", "Unknown")
        reason = (
            f"High-risk authentication origin from restricted jurisdiction [{country}] "
            f"for user '{user}' from IP {ip}."
        )
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"User: {user} | Geo: {country} ({ip})",
            "action_title": f"Revoke Authentication Tokens & Enforce Geo-Fence ({user})",
            "playbook": "IR-PB-IDENTITY-GEOTHEFT-02",
            "status": "RECOMMENDED",
            "priority": "P1 - HIGH",
            "reason": reason,
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# 1. Invalidate active Redis / OAuth session tokens for '{user}'\n"
                f"redis-cli KEYS 'sess:{user}:*' | xargs redis-cli DEL\n\n"
                f"# 2. Force password reset flag in Identity Provider\n"
                f"aws cognito-idp admin-set-user-password --username '{user}' --permanent=false\n\n"
                f"# 3. Add source IP {ip} to temporary Geo-IP quarantine\n"
                f"iptables -A INPUT -s {ip} -j REJECT"
            ),
            "rollback_script": (
                f"iptables -D INPUT -s {ip} -j REJECT"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

    else:
        # Generic containment template
        return {
            "action_id": action_id,
            "threat_type": ttype,
            "mitre_id": mitre_id,
            "severity": severity,
            "target": f"Target: {ip or user}",
            "action_title": f"Containment & Monitoring Rule for {ttype.replace('_', ' ').title()}",
            "playbook": "IR-PB-GENERIC-CONTAIN-01",
            "status": "RECOMMENDED",
            "priority": "P2 - MEDIUM",
            "reason": f"Automated defensive containment for {ttype} threat detected at {ip}.",
            "remediation_script": (
                f"# [CyberGuard AI Autonomous SOAR]\n"
                f"# Apply rate limiting and security telemetry logging\n"
                f"iptables -A INPUT -s {ip} -m limit --limit 5/min -j LOG --log-prefix 'CYBERGUARD_ALERT: '"
            ),
            "rollback_script": (
                f"iptables -D INPUT -s {ip} -m limit --limit 5/min -j LOG --log-prefix 'CYBERGUARD_ALERT: '"
            ),
            "created_at": now_str,
            "executed_at": None,
        }

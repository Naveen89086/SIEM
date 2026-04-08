import json

class AIAnalyst:
    """
    Expert system for security alert analysis and automated response recommendations.
    Provides natural language explanations and suggested next steps for SOC analysts.
    """
    
    def __init__(self):
        # Expert knowledge base for alert explanations
        self.knowledge_base = {
            "RANSOMWARE": {
                "explanation": "High-volume file modifications correlated with suspicious process spawns and outbound network spikes. Pattern strongly indicative of active encryption and staging.",
                "impact": "CRITICAL - Total data loss and ransomware deployment imminent.",
                "recommendation": "Isolate the host immediately. Revoke all active sessions for local and domain accounts on this machine. Initiate incident response flow."
            },
            "AUTH_COMPROMISE": {
                "explanation": "Successful authentication detected immediately following a brute-force pattern from the same source IP. Indicates account takeover.",
                "impact": "CRITICAL - Unauthorized access to system/network with valid credentials.",
                "recommendation": "Disable the compromised account immediately. Force reset all passwords for the associated user. Audit all activity performed post-login."
            },
            "BRUTE_FORCE": {
                "explanation": "Sustained high-frequency failed login attempts targeting authentication ports (e.g., 22, 3389, 445).",
                "impact": "HIGH - Risk of credential exhaustion and potential account takeover.",
                "recommendation": "Block the source IP at the perimeter. Implement geofencing if the source is from an unexpected region. Verify if any attempts were successful."
            },
            "BEACONING": {
                "explanation": "Highly regular, periodic callbacks detected between an internal host and an external IP. Characteristic of C2 malware communication.",
                "impact": "HIGH - Persistent malware infection and potential Command & Control established.",
                "recommendation": "Capture full packet data for the established connection. Identify the parent process on the source host. Block the destination IP."
            },
            "DATA_EXFIL": {
                "explanation": "Large outbound data transfer exceeding baseline thresholds to an external destination.",
                "impact": "CRITICAL - Intellectual property, sensitive data, or database exfiltration.",
                "recommendation": "Terminate the network session immediately. Identify the files accessed and the user account responsible. Check for unauthorized tool usage (e.g., Rclone)."
            },
            "DNS_TUNNEL": {
                "explanation": "Large volume or high frequency of abnormal DNS queries, likely encapsulating non-DNS protocols.",
                "impact": "HIGH - Likely used for Command & Control or stealthy data exfiltration bypassing firewalls.",
                "recommendation": "Analyze the query subdomains for base64 or hex encoding. Block queries to the suspicious domain. Redirect DNS traffic to a secure resolver."
            },
            "PORT_SCAN": {
                "explanation": "Single source IP attempting to connect to numerous ports in a short duration (sweeping).",
                "impact": "MEDIUM - Reconnaissance phase. Attacker is identifying reachable services.",
                "recommendation": "Monitor for subsequent targeted exploitation attempts. Verify firewall rules and close any unnecessary exposed ports."
            },
            "SYN_FLOOD": {
                "explanation": "High rate of SYN packets without completing the TCP handshake. Classic Denial of Service pattern.",
                "impact": "MEDIUM/HIGH - Resource exhaustion on targeted services, leading to downtime.",
                "recommendation": "Enable SYN cookies on the target system. Apply rate-limiting at the firewall. Identify if the traffic is spoofed or from a specific botnet."
            },
            "BLOCKED_PORT": {
                "explanation": "Inbound or outbound connection attempt to a port known to be associated with malware or high-risk services.",
                "impact": "MEDIUM - Potential malware activity or policy violation.",
                "recommendation": "Identify the process attempting the connection. Verify if this is a known port for a legitimate but non-standard application."
            }
        }

    def explain_alert(self, alert):
        """Generates a detailed explanation for an alert."""
        event_type = alert.get("event_type", "UNKNOWN")
        kb_entry = self.knowledge_base.get(event_type)
        if not kb_entry:
            return {
                "explanation": alert.get("message", "Standard security event detected."),
                "impact": "Medium - Assessment required.",
                "recommendation": "Verify host baseline and check source IP reputation."
            }
        return kb_entry

    def get_response_actions(self, alert):
        """Suggests automated response actions based on alert type."""
        event_type = alert.get("event_type", "UNKNOWN")
        severity = alert.get("severity", "LOW")
        actions = []
        if severity in ["HIGH", "CRITICAL"]:
            actions.append({"id": "block_ip", "label": "Block Source IP", "icon": "shield-off"})
        if event_type in ["RANSOMWARE", "AUTH_COMPROMISE", "DATA_EXFIL"]:
            actions.append({"id": "quarantine_host", "label": "Quarantine Host", "icon": "zap-off"})
        actions.append({"id": "dismiss", "label": "Mark False Positive", "icon": "check-circle"})
        return actions

expert_analyst = AIAnalyst()

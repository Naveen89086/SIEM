"""
Correlation Engine — Links related security events into kill-chain incidents.
"""
import time
from collections import defaultdict
from app.database import create_incident
from app.config import MITRE_MAP

# Track events per source IP with timestamps
_ip_event_history = defaultdict(list)  # ip -> [(timestamp, event_type, event_id, severity)]

# Kill chain stages mapping
KILL_CHAIN = {
    "PORT_SCAN":    {"phase": "Reconnaissance",        "order": 1},
    "BRUTE_FORCE":  {"phase": "Weaponization",         "order": 2},
    "BLOCKED_PORT": {"phase": "Delivery",              "order": 3},
    "SYN_FLOOD":    {"phase": "Exploitation",          "order": 4},
    "DNS_TUNNEL":   {"phase": "Command & Control",     "order": 5},
    "BEACONING":    {"phase": "Command & Control",     "order": 5},
    "DATA_EXFIL":   {"phase": "Actions on Objectives", "order": 6},
    "RATE_LIMIT":   {"phase": "Impact",                "order": 7},
    "RANSOMWARE":   {"phase": "Impact",                "order": 7},
    "AUTH_COMPROMISE": {"phase": "Exploitation",       "order": 4},
}

_correlated_incidents = set()
CORRELATION_WINDOW = 1800

def add_event(src_ip: str, event_type: str, event_id: int, severity: str):
    now = time.time()
    _ip_event_history[src_ip].append((now, event_type, event_id, severity))
    _ip_event_history[src_ip] = [e for e in _ip_event_history[src_ip] if now - e[0] <= CORRELATION_WINDOW]
    return _check_correlation(src_ip)

def _check_correlation(src_ip: str):
    events = _ip_event_history[src_ip]
    if len(events) < 2:
        return None

    event_types = set(e[1] for e in events)
    event_ids = [e[2] for e in events]
    phases = set()
    for et in event_types:
        if et in KILL_CHAIN:
            phases.add(KILL_CHAIN[et]["phase"])

    if len(phases) < 2:
        return None

    sig = f"{src_ip}_{'_'.join(sorted(event_types))}"
    if sig in _correlated_incidents:
        return None

    _correlated_incidents.add(sig)
    max_order = max(KILL_CHAIN[et]["order"] for et in event_types if et in KILL_CHAIN)
    
    if len(phases) >= 3 or max_order >= 6:
        severity = "CRITICAL"
    elif max_order >= 4:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    sorted_phases = sorted(list(phases), key=lambda p: min([v["order"] for v in KILL_CHAIN.values() if v["phase"] == p] or [99]))
    chain_desc = " → ".join(sorted_phases)
    title = f"FULL KILL-CHAIN DETECTED: {src_ip}" if len(phases) >= 4 else f"Multi-Stage Attack from {src_ip}: {chain_desc}"

    incident_id = create_incident(
        title=title,
        severity=severity,
        event_ids=event_ids,
        src_ip=src_ip,
        kill_chain_phase=chain_desc
    )

    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "src_ip": src_ip,
        "phases": sorted_phases,
        "event_types": list(event_types),
        "event_count": len(events),
        "confidence": 70 + (len(phases) * 5)
    }

def get_ip_threat_score(ip: str) -> dict:
    events = _ip_event_history.get(ip, [])
    if not events:
        return {"ip": ip, "score": 0, "level": "low", "event_count": 0}

    now = time.time()
    recent = [e for e in events if now - e[0] <= CORRELATION_WINDOW]
    severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
    score = 0
    for _, event_type, _, sev in recent:
        score += severity_weights.get(sev, 1)

    unique_types = len(set(e[1] for e in recent))
    score = min(100, score + (unique_types * 3))

    if score >= 70: level = "critical"
    elif score >= 40: level = "high"
    elif score >= 20: level = "medium"
    else: level = "low"

    mitre_id, mitre_tactic = "", ""
    best_event = max(recent, key=lambda x: severity_weights.get(x[3], 0)) if recent else None
    if best_event:
        m_info = MITRE_MAP.get(best_event[1], {})
        mitre_id = m_info.get("id", "")
        mitre_tactic = m_info.get("tactic", "")

    return {
        "ip": ip, "score": score, "level": level, "event_count": len(recent),
        "attack_types": list(set(e[1] for e in recent)),
        "mitre_id": mitre_id, "mitre_tactic": mitre_tactic
    }

def get_all_threat_scores() -> list:
    return [get_ip_threat_score(ip) for ip in _ip_event_history if _ip_event_history[ip]]

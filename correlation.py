"""
Correlation Engine — Links related security events into kill-chain incidents.
"""
import time
from collections import defaultdict
from database import create_incident
from config import MITRE_MAP

# -------------------------
# Correlation State
# -------------------------
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

# Track which IP+chain combos already generated incidents
_correlated_incidents = set()

# Correlation window: 30 minutes
CORRELATION_WINDOW = 1800


def add_event(src_ip: str, event_type: str, event_id: int, severity: str):
    """
    Add an event to the correlation engine.
    Returns an incident dict if a correlated incident is created, else None.
    """
    now = time.time()
    _ip_event_history[src_ip].append((now, event_type, event_id, severity))

    # Prune old events
    _ip_event_history[src_ip] = [
        e for e in _ip_event_history[src_ip]
        if now - e[0] <= CORRELATION_WINDOW
    ]

    # Check for multi-stage attack
    return _check_correlation(src_ip)


def _check_correlation(src_ip: str):
    """Check if events from this IP form a kill-chain pattern."""
    events = _ip_event_history[src_ip]
    if len(events) < 2:
        return None

    # Get unique event types in this window
    event_types = set(e[1] for e in events)
    event_ids = [e[2] for e in events]

    # Map to kill chain phases
    phases = set()
    for et in event_types:
        if et in KILL_CHAIN:
            phases.add(KILL_CHAIN[et]["phase"])

    # Need at least 2 different kill chain phases to correlate
    if len(phases) < 2:
        return None

    # Create a signature to avoid duplicate incidents
    sig = f"{src_ip}_{'_'.join(sorted(event_types))}"
    if sig in _correlated_incidents:
        return None

    _correlated_incidents.add(sig)

    # Determine severity based on chain completeness
    max_order = max(
        KILL_CHAIN[et]["order"] for et in event_types if et in KILL_CHAIN
    )
    
    # Advanced logic: If we have 3+ phases, it's CRITICAL
    if len(phases) >= 3 or max_order >= 6:
        severity = "CRITICAL"
    elif max_order >= 4:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    # Build incident title
    sorted_phases = sorted(
        list(phases),
        key=lambda p: min([v["order"] for v in KILL_CHAIN.values() if v["phase"] == p] or [99])
    )
    chain_desc = " → ".join(sorted_phases)

    if len(phases) >= 4:
        title = f"FULL KILL-CHAIN DETECTED: {src_ip}"
    else:
        title = f"Multi-Stage Attack from {src_ip}: {chain_desc}"

    # Create incident in database
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
        "confidence": 70 + (len(phases) * 5) # Score increases with more phases
    }


def get_ip_threat_score(ip: str) -> dict:
    """Calculate a threat score for an IP based on recent activity."""
    events = _ip_event_history.get(ip, [])
    if not events:
        return {"ip": ip, "score": 0, "level": "low", "event_count": 0}

    now = time.time()
    recent = [e for e in events if now - e[0] <= CORRELATION_WINDOW]

    # Score based on: number of events, diversity of attack types, severity
    severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
    score = 0
    for _, event_type, _, sev in recent:
        score += severity_weights.get(sev, 1)

    # Bonus for attack diversity
    unique_types = len(set(e[1] for e in recent))
    score += unique_types * 3

    # Normalize to 0-100
    score = min(100, score)

    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    # Find the most serious MITRE info from the recent events
    mitre_id = ""
    mitre_tactic = ""
    attack_types = list(set(e[1] for e in recent))
    
    # Priority based on severity
    best_event = max(recent, key=lambda x: severity_weights.get(x[3], 0)) if recent else None
    if best_event:
        m_info = MITRE_MAP.get(best_event[1], {})
        mitre_id = m_info.get("id", "")
        mitre_tactic = m_info.get("tactic", "")

    return {
        "ip": ip,
        "score": score,
        "level": level,
        "event_count": len(recent),
        "attack_types": attack_types,
        "mitre_id": mitre_id,
        "mitre_tactic": mitre_tactic
    }


def get_all_threat_scores() -> list:
    """Get threat scores for all tracked IPs."""
    return [
        get_ip_threat_score(ip)
        for ip in _ip_event_history
        if _ip_event_history[ip]
    ]

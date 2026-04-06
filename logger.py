"""
Enhanced SIEM Logger — SQLite-backed with rate-limited email alerts.
"""
import json
import time
import os
from collections import deque
from alert_email import send_email

LOG_FILE = "alerts.json"

# In-memory ring buffers for dashboard
recent_alerts = deque(maxlen=200)
recent_packets = deque(maxlen=500)

# Email rate limiting: track last email time per alert type
_email_rate = {}
EMAIL_COOLDOWN = 300  # 5 minutes


def log_event(event_type, message, details=None, severity="MEDIUM",
              mitre_id="", mitre_tactic="", src_ip="", dst_ip="",
              protocol="", port=""):
    """
    Logs a security event to SQLite, in-memory buffer, and sends email.
    Returns the event ID from the database.
    """
    event = {
        "timestamp": time.time(),
        "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "severity": severity,
        "message": message,
        "details": details or {},
        "mitre_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
    }

    # Add to in-memory buffer
    recent_alerts.appendleft(event)

    # Print to console with color coding
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    icon = severity_icons.get(severity, "⚪")
    mitre_tag = f" [{mitre_id}]" if mitre_id else ""
    print(f"{icon} [{severity} - {event_type}]{mitre_tag} {message}")

    # Write to SQLite database
    event_id = None
    try:
        from database import insert_event
        event_id = insert_event(
            event_type=event_type,
            message=message,
            details=details,
            severity=severity,
            mitre_id=mitre_id,
            mitre_tactic=mitre_tactic,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port=port
        )
    except Exception as e:
        print(f"[ERROR] Failed to write to database: {e}")

    # Rate-limited email for HIGH and CRITICAL alerts
    if severity in ("HIGH", "CRITICAL") and event_type != "ERROR":
        now = time.time()
        last_sent = _email_rate.get(event_type, 0)
        if now - last_sent >= EMAIL_COOLDOWN:
            _email_rate[event_type] = now
            subject = f"⚠️ SOC SIEM ALERT [{severity}]: {event_type} - {mitre_id or 'General'}"
            
            # Professional HTML Template
            from alert_email import get_html_template
            html_body = get_html_template(
                severity=severity,
                event_type=event_type,
                mitre_id=mitre_id,
                mitre_tactic=mitre_tactic,
                message=message,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=event['timestamp_str'],
                details=details
            )
            
            send_email(subject, message, html_body=html_body)

    return event_id


def log_packet(packet_data):
    """Store packet in ring buffer and database."""
    packet_data["timestamp"] = time.time()
    packet_data["timestamp_str"] = time.strftime("%H:%M:%S")
    recent_packets.appendleft(packet_data)

    # Also store in database (async-friendly, non-blocking)
    try:
        from database import insert_packet
        insert_packet(packet_data)
    except Exception:
        pass  # Don't block capture on DB errors


def get_recent_alerts(limit=50):
    """Return recent alerts for API."""
    return list(recent_alerts)[:limit]


def get_recent_packets(limit=50):
    """Return recent packets for API."""
    return list(recent_packets)[:limit]


def get_all_alerts():
    """Read alerts from database, falling back to JSON file."""
    try:
        from database import query_events
        return query_events(limit=500)
    except Exception:
        pass

    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return []

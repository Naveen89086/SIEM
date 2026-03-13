"""
SIEM Database Layer — SQLite-backed event, packet, and incident storage.
"""
import sqlite3
import threading
import time
import json
import os
from config import DB_PATH, LOG_RETENTION_DAYS

_local = threading.local()


def _get_conn():
    """Thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            protocol TEXT DEFAULT '',
            port TEXT DEFAULT '',
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            details TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            timestamp_str TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT DEFAULT '{}',
            mitre_id TEXT DEFAULT '',
            mitre_tactic TEXT DEFAULT '',
            confidence REAL DEFAULT 0.8,
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            acknowledged INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port TEXT,
            dst_port TEXT,
            length INTEGER DEFAULT 0,
            flags TEXT DEFAULT '',
            is_threat INTEGER DEFAULT 0,
            threat_msg TEXT DEFAULT '',
            dns_query TEXT DEFAULT '',
            http_host TEXT DEFAULT '',
            tls_sni TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'OPEN',
            assigned_to TEXT DEFAULT '',
            event_ids TEXT DEFAULT '[]',
            notes TEXT DEFAULT '[]',
            src_ip TEXT DEFAULT '',
            kill_chain_phase TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            risk_score REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_logs_ts ON security_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_type ON security_logs(alert_type);
        CREATE INDEX IF NOT EXISTS idx_logs_src ON security_logs(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    """)
    conn.commit()


def insert_event(event_type, message, details=None, severity="MEDIUM",
                 mitre_id="", mitre_tactic="", confidence=0.8,
                 src_ip="", dst_ip=""):
    """Insert a security event and return its ID."""
    conn = _get_conn()
    now = time.time()
    
    # 1. Insert into legacy events table for backward compat
    cur = conn.execute(
        """INSERT INTO events
           (timestamp, timestamp_str, event_type, severity, message, details,
            mitre_id, mitre_tactic, confidence, src_ip, dst_ip)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now, time.strftime("%Y-%m-%d %H:%M:%S"), event_type, severity,
         message, json.dumps(details or {}), mitre_id, mitre_tactic,
         confidence, src_ip, dst_ip)
    )
    event_id = cur.lastrowid

    # 2. Insert into new structured security_logs table
    try:
        # Extract protocol and port from details if possible
        protocol = ""
        port = ""
        if details:
            if "protocol" in details:
                protocol = details["protocol"]
            if "port" in details:
                port = str(details["port"])
            elif "dst_port" in details:
                port = str(details["dst_port"])
            elif "target_port" in details:
                port = str(details["target_port"])

        conn.execute(
            """INSERT INTO security_logs
               (timestamp, src_ip, dst_ip, protocol, port, alert_type, severity, description, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, src_ip, dst_ip, protocol, port, event_type, severity, message, json.dumps(details or {}))
        )
    except Exception as e:
        print(f"[DB_ERROR] Failed to insert into security_logs: {e}")

    conn.commit()
    return event_id


def search_security_logs(alert_type=None, severity=None, src_ip=None,
                         search=None, limit=100, offset=0):
    """Structured query for security_logs."""
    conn = _get_conn()
    sql = "SELECT * FROM security_logs WHERE 1=1"
    params = []
    if alert_type:
        sql += " AND alert_type = ?"
        params.append(alert_type)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if src_ip:
        sql += " AND src_ip = ?"
        params.append(src_ip)
    if search:
        sql += " AND (description LIKE ? OR alert_type LIKE ?)"
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def insert_packet(pkt: dict):
    """Insert a packet record."""
    conn = _get_conn()
    conn.execute(
        """INSERT INTO packets
           (timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
            length, flags, is_threat, threat_msg, dns_query, http_host, tls_sni)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), pkt.get("src_ip", ""), pkt.get("dst_ip", ""),
         pkt.get("protocol", ""), pkt.get("src_port", ""),
         pkt.get("dst_port", ""), pkt.get("length", 0),
         pkt.get("flags", ""), int(pkt.get("is_threat", False)),
         pkt.get("threat_msg", ""), pkt.get("dns_query", ""),
         pkt.get("http_host", ""), pkt.get("tls_sni", ""))
    )
    conn.commit()


def query_events(event_type=None, severity=None, src_ip=None,
                 search=None, limit=100, offset=0):
    """Query events with optional filters."""
    conn = _get_conn()
    sql = "SELECT * FROM events WHERE 1=1"
    params = []
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if src_ip:
        sql += " AND src_ip = ?"
        params.append(src_ip)
    if search:
        sql += " AND message LIKE ?"
        params.append(f"%{search}%")
    sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_event_timeline(hours=24, unit="hour"):
    """Return event counts bucketed by hour or minute for the last N hours."""
    conn = _get_conn()
    cutoff = time.time() - (hours * 3600)
    
    # Define seconds per unit
    sec_per_unit = 3600 if unit == "hour" else 60
    
    rows = conn.execute(
        f"""SELECT
             CAST((timestamp - ?) / {sec_per_unit} AS INTEGER) AS bucket,
             severity,
             COUNT(*) as cnt
           FROM events
           WHERE timestamp >= ?
           GROUP BY bucket, severity
           ORDER BY bucket""",
        (cutoff, cutoff)
    ).fetchall()
    return [dict(r) for r in rows]


def get_top_attackers(limit=10):
    """Return IPs with the most alerts."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) as alert_count,
                  GROUP_CONCAT(DISTINCT event_type) as attack_types,
                  MAX(severity) as max_severity
           FROM events
           WHERE src_ip != ''
           GROUP BY src_ip
           ORDER BY alert_count DESC
           LIMIT ?""",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_protocol_stats():
    """Enhanced protocol distribution with complexity metrics."""
    conn = _get_conn()
    cutoff = time.time() - 3600  # last hour
    rows = conn.execute(
        """SELECT protocol, 
                  COUNT(*) as cnt,
                  AVG(length) as avg_len,
                  COUNT(DISTINCT dst_ip) as unique_dsts
           FROM packets 
           WHERE timestamp >= ? AND protocol != ''
           GROUP BY protocol ORDER BY cnt DESC""",
        (cutoff,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_network_topology(limit=200):
    """Unique IP pairs for network graph."""
    conn = _get_conn()
    cutoff = time.time() - 1800  # last 30 minutes
    rows = conn.execute(
        """SELECT src_ip, dst_ip, protocol, COUNT(*) as weight,
                  SUM(is_threat) as threat_count
           FROM packets
           WHERE timestamp >= ? AND src_ip != '' AND dst_ip != ''
           GROUP BY src_ip, dst_ip
           ORDER BY weight DESC
           LIMIT ?""",
        (cutoff, limit)
    ).fetchall()
    return [dict(r) for r in rows]


# -------------------------
# Incident Management
# -------------------------
def create_incident(title, severity, event_ids=None, src_ip="",
                    kill_chain_phase=""):
    """Create a new incident."""
    conn = _get_conn()
    now = time.time()
    cur = conn.execute(
        """INSERT INTO incidents
           (created_at, updated_at, title, severity, event_ids, src_ip,
            kill_chain_phase)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now, now, title, severity, json.dumps(event_ids or []),
         src_ip, kill_chain_phase)
    )
    conn.commit()
    return cur.lastrowid


def update_incident(incident_id, status=None, note=None, assigned_to=None):
    """Update incident status or add a note."""
    conn = _get_conn()
    now = time.time()

    if status:
        conn.execute(
            "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
            (status, now, incident_id)
        )
    if assigned_to is not None:
        conn.execute(
            "UPDATE incidents SET assigned_to=?, updated_at=? WHERE id=?",
            (assigned_to, now, incident_id)
        )
    if note:
        row = conn.execute(
            "SELECT notes FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        if row:
            notes = json.loads(row["notes"])
            notes.append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "text": note
            })
            conn.execute(
                "UPDATE incidents SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(notes), now, incident_id)
            )
    conn.commit()


def get_incidents(status=None, limit=50):
    """Get incidents, optionally filtered by status."""
    conn = _get_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT ?",
            (status, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["event_ids"] = json.loads(d["event_ids"])
        d["notes"] = json.loads(d["notes"])
        results.append(d)
    return results


def get_incident(incident_id):
    """Get a single incident by ID."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM incidents WHERE id=?", (incident_id,)
    ).fetchone()
    if row:
        d = dict(row)
        d["event_ids"] = json.loads(d["event_ids"])
        d["notes"] = json.loads(d["notes"])
        return d
    return None


def cleanup_old_records():
    """Remove records older than retention period."""
    conn = _get_conn()
    cutoff = time.time() - (LOG_RETENTION_DAYS * 86400)
    conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    conn.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
    conn.execute("DELETE FROM security_logs WHERE timestamp < ?", (cutoff,))
    conn.commit()


def get_severity_distribution():
    """Severity counts for the last 24 hours."""
    conn = _get_conn()
    cutoff = time.time() - 86400
    rows = conn.execute(
        """SELECT severity, COUNT(*) as cnt
           FROM events WHERE timestamp >= ?
           GROUP BY severity""",
        (cutoff,)
    ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}



def insert_risk_score(score):
    """Log current network risk score."""
    conn = _get_conn()
    conn.execute("INSERT INTO risk_history (timestamp, risk_score) VALUES (?, ?)", (time.time(), score))
    conn.commit()


def get_risk_trend(limit=50):
    """Get recent risk score history for charts."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT timestamp, risk_score FROM risk_history ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [{"time": r["timestamp"], "score": r["risk_score"]} for r in reversed(rows)]


def get_mitre_coverage():
    """MITRE ATT&CK techniques detected."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT mitre_id, mitre_tactic, event_type, COUNT(*) as cnt
           FROM events WHERE mitre_id != ''
           GROUP BY mitre_id"""
    ).fetchall()
    return [dict(r) for r in rows]

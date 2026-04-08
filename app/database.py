"""
SIEM Database Layer — SQLite-backed event, packet, and incident storage.
"""
import sqlite3
import threading
import time
import json
import os
from app.config import DB_PATH, LOG_RETENTION_DAYS
# MongoDB integration
from app.mongodb import insert_log_to_atlas

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
    """Create optimized tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL DEFAULT '0.0.0.0',
            dst_ip TEXT NOT NULL DEFAULT '0.0.0.0',
            protocol TEXT DEFAULT 'UNKNOWN',
            src_port INTEGER,
            dst_port INTEGER,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            message TEXT NOT NULL,
            details TEXT DEFAULT '{}',
            mitre_id TEXT DEFAULT '',
            mitre_tactic TEXT DEFAULT '',
            log_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS raw_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL DEFAULT '0.0.0.0',
            dst_ip TEXT NOT NULL DEFAULT '0.0.0.0',
            protocol TEXT DEFAULT 'UNKNOWN',
            src_port TEXT DEFAULT '',
            dst_port TEXT DEFAULT '',
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

        CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_packets_ts ON raw_packets(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_risk_ts ON risk_history(timestamp DESC);
    """)
    conn.commit()

import hashlib

def calculate_log_hash(prev_hash, current_data):
    data_str = f"{prev_hash}{json.dumps(current_data, sort_keys=True)}"
    return hashlib.sha256(data_str.encode()).hexdigest()

def get_last_log_hash():
    conn = _get_conn()
    row = conn.execute("SELECT log_hash FROM security_events ORDER BY id DESC LIMIT 1").fetchone()
    return row["log_hash"] if row else "INITIAL_ROOT_HASH"

def insert_event(event_type, message, details=None, severity="MEDIUM",
                  mitre_id="", mitre_tactic="", confidence=0.8,
                  src_ip="", dst_ip="", protocol="", port=""):
    conn = _get_conn()
    now = time.time()
    
    src_ip = src_ip or '0.0.0.0'
    dst_ip = dst_ip or '0.0.0.0'
    protocol = protocol or 'UNKNOWN'
    
    payload = {
        "timestamp": now, "src_ip": src_ip, "dst_ip": dst_ip, 
        "alert_type": event_type, "severity": severity, "message": message
    }
    prev_hash = get_last_log_hash()
    log_hash = calculate_log_hash(prev_hash, payload)

    cur = conn.execute(
        """INSERT INTO security_events
           (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, 
            alert_type, severity, message, details, mitre_id, mitre_tactic, log_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now, src_ip, dst_ip, protocol, port, port, 
         event_type, severity, message, json.dumps(details or {}), 
         mitre_id, mitre_tactic, log_hash)
    )
    conn.commit()

    try:
        insert_log_to_atlas(
            event_type=event_type,
            message=message,
            details=details,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port=port
        )
    except Exception as e:
        print(f"[MONGODB_ERROR] Automatic Atlas storage failed: {e}")

    return cur.lastrowid

import queue

class PacketBuffer:
    def __init__(self, batch_size=100, interval=1.0):
        self.queue = queue.Queue()
        self.batch_size = batch_size
        self.interval = interval
        self.stop_event = threading.Event()
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

    def add(self, pkt):
        self.queue.put(pkt)

    def _worker(self):
        while not self.stop_event.is_set() or not self.queue.empty():
            batch = []
            try:
                while len(batch) < self.batch_size:
                    batch.append(self.queue.get(timeout=self.interval))
            except queue.Empty:
                pass
            if batch:
                self._flush(batch)

    def _flush(self, batch):
        conn = _get_conn()
        try:
            conn.executemany(
                """INSERT INTO raw_packets
                   (timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
                    length, flags, is_threat, threat_msg, dns_query, http_host, tls_sni)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(time.time(), p.get("src_ip", "0.0.0.0"), p.get("dst_ip", "0.0.0.0"),
                  p.get("protocol", "UNKNOWN"), p.get("src_port", ""),
                  p.get("dst_port", ""), p.get("length", 0),
                  p.get("flags", ""), int(p.get("is_threat", False)),
                  p.get("threat_msg", ""), p.get("dns_query", ""),
                  p.get("http_host", ""), p.get("tls_sni", "")) for p in batch]
            )
            conn.commit()
        except Exception as e:
            print(f"[DB_ERROR] Batch flush failed: {e}")

    def stop(self):
        self.stop_event.set()
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2)

packet_buffer = PacketBuffer()

def search_security_logs(alert_type=None, severity=None, src_ip=None,
                          search=None, limit=100, offset=0):
    conn = _get_conn()
    sql = "SELECT * FROM security_events WHERE 1=1"
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
        sql += " AND (message LIKE ? OR alert_type LIKE ?)"
        params.append(f"%{search}%")
        params.append(f"%{search}%")
    sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]

def insert_packet(pkt: dict):
    packet_buffer.add(pkt)

def query_events(event_type=None, severity=None, src_ip=None,
                  search=None, limit=100, offset=0):
    return search_security_logs(event_type, severity, src_ip, search, limit, offset)

def get_event_timeline(hours=24, unit="hour"):
    conn = _get_conn()
    cutoff = time.time() - (hours * 3600)
    sec_per_unit = 3600 if unit == "hour" else 60
    rows = conn.execute(
        f"""SELECT
             CAST((timestamp - ?) / {sec_per_unit} AS INTEGER) AS bucket,
             severity,
             COUNT(*) as cnt
           FROM security_events
           WHERE timestamp >= ?
           GROUP BY bucket, severity
           ORDER BY bucket""",
        (cutoff, cutoff)
    ).fetchall()
    return [dict(r) for r in rows]

def get_top_attackers(limit=10):
    conn = _get_conn()
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) as alert_count,
                  GROUP_CONCAT(DISTINCT alert_type) as attack_types,
                  MAX(severity) as max_severity
           FROM security_events
           WHERE src_ip != '0.0.0.0'
           GROUP BY src_ip
           ORDER BY alert_count DESC
           LIMIT ?""",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]

def get_protocol_stats():
    conn = _get_conn()
    cutoff = time.time() - 3600
    rows = conn.execute(
        """SELECT protocol, 
                  COUNT(*) as cnt,
                  AVG(length) as avg_len,
                  COUNT(DISTINCT dst_ip) as unique_dsts
           FROM raw_packets 
           WHERE timestamp >= ? AND protocol != 'UNKNOWN'
           GROUP BY protocol ORDER BY cnt DESC""",
        (cutoff,)
    ).fetchall()
    return [dict(r) for r in rows]

def get_network_topology(limit=200):
    conn = _get_conn()
    cutoff = time.time() - 1800
    rows = conn.execute(
        """SELECT src_ip, dst_ip, protocol, COUNT(*) as weight,
                  SUM(is_threat) as threat_count
           FROM raw_packets
           WHERE timestamp >= ? AND src_ip != '0.0.0.0' AND dst_ip != '0.0.0.0'
           GROUP BY src_ip, dst_ip
           ORDER BY weight DESC
           LIMIT ?""",
        (cutoff, limit)
    ).fetchall()
    return [dict(r) for r in rows]

def create_incident(title, severity, event_ids=None, src_ip="",
                    kill_chain_phase=""):
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
    conn = _get_conn()
    now = time.time()
    if status:
        conn.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (status, now, incident_id))
    if assigned_to is not None:
        conn.execute("UPDATE incidents SET assigned_to=?, updated_at=? WHERE id=?", (assigned_to, now, incident_id))
    if note:
        row = conn.execute("SELECT notes FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row:
            notes = json.loads(row["notes"])
            notes.append({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "text": note})
            conn.execute("UPDATE incidents SET notes=?, updated_at=? WHERE id=?", (json.dumps(notes), now, incident_id))
    conn.commit()

def get_incidents(status=None, limit=50):
    conn = _get_conn()
    if status:
        rows = conn.execute("SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["event_ids"] = json.loads(d["event_ids"])
        d["notes"] = json.loads(d["notes"])
        results.append(d)
    return results

def get_incident(incident_id):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row:
        d = dict(row)
        d["event_ids"] = json.loads(d["event_ids"])
        d["notes"] = json.loads(d["notes"])
        return d
    return None

def cleanup_old_records():
    conn = _get_conn()
    cutoff = time.time() - (LOG_RETENTION_DAYS * 86400)
    conn.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff,))
    conn.execute("DELETE FROM raw_packets WHERE timestamp < ?", (cutoff,))
    conn.commit()

def get_severity_distribution():
    conn = _get_conn()
    cutoff = time.time() - 86400
    rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM security_events WHERE timestamp >= ? GROUP BY severity", (cutoff,)).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}

def insert_risk_score(score):
    conn = _get_conn()
    conn.execute("INSERT INTO risk_history (timestamp, risk_score) VALUES (?, ?)", (time.time(), score))
    conn.commit()

def get_risk_trend(limit=50):
    conn = _get_conn()
    rows = conn.execute("SELECT timestamp, risk_score FROM risk_history ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [{"time": r["timestamp"], "score": r["risk_score"]} for r in reversed(rows)]

def get_mitre_coverage():
    conn = _get_conn()
    rows = conn.execute("SELECT mitre_id, mitre_tactic, alert_type as event_type, COUNT(*) as cnt FROM security_events WHERE mitre_id != '' GROUP BY mitre_id").fetchall()
    return [dict(r) for r in rows]

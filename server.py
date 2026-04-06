"""
SIEM Dashboard Server
Enhanced FastAPI backend with WebSocket, incident management, and full SIEM API.
"""
import asyncio
import json
import threading
import time

import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import (
    SERVER_HOST, SERVER_PORT, MITRE_MAP,
    USE_HTTPS, SSL_CERT_FILE, SSL_KEY_FILE, REDIRECT_HTTP_TO_HTTPS
)
from packet_capture import start_capture
from detector import (
    analyze_packet_header, cleanup_old_data, get_stats, 
    get_network_risk, decay_network_risk
)
from logger import log_event, log_packet, get_recent_alerts, get_recent_packets, get_all_alerts
from database import (
    init_db, query_events, search_security_logs, get_event_timeline, get_top_attackers,
    get_network_topology, get_incidents, get_incident, update_incident,
    get_severity_distribution, get_mitre_coverage, get_protocol_stats,
    create_incident, insert_risk_score, get_risk_trend
)
from threat_intel import get_ip_summary, check_ip_reputation
from correlation import get_all_threat_scores, get_ip_threat_score
from ai_analyst import expert_analyst
from mongodb_storage import atlas_client
from traffic_intel_engine import engine as traffic_engine

app = FastAPI(title="SOC SIEM Dashboard")

# -------------------------
# Global State
# -------------------------
capture_proc = None
capture_thread = None
is_running = False
start_time = time.time()
connected_clients: list[WebSocket] = []
intel_clients: list[WebSocket] = [] # Dedicated clients for traffic intel view
packet_buffer: list[dict] = []
buffer_lock = threading.Lock()


# -------------------------
# System Metrics
# -------------------------
prev_net_io = psutil.net_io_counters()
prev_time = time.time()

def get_system_metrics():
    global prev_net_io, prev_time
    
    curr_net_io = psutil.net_io_counters()
    curr_time = time.time()
    dt = curr_time - prev_time
    
    # Calculate speed in Mbps
    sent_speed = ((curr_net_io.bytes_sent - prev_net_io.bytes_sent) * 8) / (dt * 1024 * 1024) if dt > 0 else 0
    recv_speed = ((curr_net_io.bytes_recv - prev_net_io.bytes_recv) * 8) / (dt * 1024 * 1024) if dt > 0 else 0
    
    prev_net_io = curr_net_io
    prev_time = curr_time

    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    
    return {
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "net_sent_mbps": round(sent_speed, 2),
        "net_recv_mbps": round(recv_speed, 2),
        "net_total_sent_mb": round(curr_net_io.bytes_sent / (1024**2), 2),
        "net_total_recv_mb": round(curr_net_io.bytes_recv / (1024**2), 2),
        "uptime_seconds": int(time.time() - start_time),
        "thread_count": psutil.Process().num_threads(),
        "mongodb_connected": atlas_client._connected,
    }


# -------------------------
# Utilities
# -------------------------
def is_internal_ip(ip):
    """Check if an IP address is internal (RFC1918) or localhost."""
    if not ip or ip == "Unknown": return False
    parts = ip.split('.')
    if len(parts) != 4: return False
    
    p1 = int(parts[0])
    p2 = int(parts[1])
    
    if p1 == 10: return True
    if p1 == 172 and (16 <= p2 <= 31): return True
    if p1 == 192 and p2 == 168: return True
    if p1 == 127: return True
    return False

# -------------------------
# Capture Thread
# -------------------------
def capture_worker():
    global capture_proc, is_running
    print("[+] Starting TShark capture (Enhanced)...")
    capture_proc = start_capture()
    is_running = True

    try:
        for line in capture_proc.stdout:
            if not is_running:
                break

            line = line.strip()
            if not line:
                continue

            fields = line.split("|")
            # Now expecting 15 fields (indices 0-14)
            if len(fields) < 15:
                fields += [""] * (15 - len(fields))

            src = fields[0]
            dst = fields[1]
            proto = fields[2]

            # Port extraction logic
            src_port = ""
            dst_port = ""
            proto_name = f"PROTO-{proto}"

            if proto == "6": # TCP
                src_port, dst_port, proto_name = fields[3], fields[4], "TCP"
            elif proto == "17": # UDP
                src_port, dst_port, proto_name = fields[5], fields[6], "UDP"
            elif proto == "1": # ICMP
                proto_name = "ICMP"
            
            length = int(fields[7]) if fields[7].isdigit() else 0
            flags = fields[8]
            
            # DNS details (9, 10)
            dns_query = fields[9]
            dns_type = fields[10]
            if dns_query: proto_name = "DNS"

            # HTTP details (11, 12)
            http_host = fields[11]
            http_method = fields[12]
            if http_host or http_method: proto_name = "HTTP"

            # TLS SNI (13)
            tls_sni = fields[13]

            # ICMP Type (14)
            icmp_type = fields[14]

            cleanup_old_data()

            # --- Classification & Intelligence ---
            src_type = "INT" if is_internal_ip(src) else "EXT"
            dst_type = "INT" if is_internal_ip(dst) else "EXT"

            packet_data = {
                "src_ip": src,
                "src_type": src_type,
                "dst_ip": dst,
                "dst_type": dst_type,
                "protocol": proto_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
                "flags": flags,
                "dns_query": dns_query,
                "dns_type": dns_type,
                "http_host": http_host,
                "http_method": http_method,
                "tls_sni": tls_sni,
                "icmp_type": icmp_type,
            }

            # --- Live Threat Layer ---
            is_threat, threat_msg = analyze_packet_header(packet_data)
            
            # Additional realtime checks for "Network Monitor" view
            security_status = "SAFE"
            if is_threat:
                security_status = "THREAT"
            elif dst_port in ["22", "3389", "4444", "445"]:
                security_status = "SUSPICIOUS"
                threat_msg = f"Suspicious port access: {dst_port}"
            elif length > 10000: # Simple large packet anomaly
                security_status = "SUSPICIOUS"
                threat_msg = "Large packet anomaly detected"

            packet_data["is_threat"] = is_threat
            packet_data["threat_msg"] = threat_msg if is_threat else ""
            packet_data["security_status"] = security_status

            log_packet(packet_data)
            traffic_engine.process_packet(packet_data)

            with buffer_lock:
                packet_data["id"] = int(time.time() * 1000000) # Microsecond ID
                packet_buffer.append(packet_data)

    except Exception as e:
        print(f"[ERROR] Capture error: {e}")
    finally:
        is_running = False
        if capture_proc and capture_proc.poll() is None:
            capture_proc.terminate()
# -------------------------
# Redirection Server
# -------------------------
def http_redirection_worker():
    """Very basic HTTP server to redirect to HTTPS."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Dynamic redirect to current LAN IP / Host
            new_url = BASE_URL + self.path
            self.send_response(301)
            self.send_header('Location', new_url)
            self.end_headers()
            
    try:
        httpd = HTTPServer(('0.0.0.0', 80), RedirectHandler)
        print(f"[+] HTTP to HTTPS Redirector running on port 80")
        httpd.serve_forever()
    except Exception as e:
        print(f"[WARN] Could not start HTTP redirection (Port 80 might be in use): {e}")

# Import BASE_URL for redirection
from config import BASE_URL


# -------------------------
# Risk Decay & Logging Loop
# -------------------------
async def risk_maintenance_loop():
    """Periodically decay risk and log it to database for historical trends."""
    while True:
        await asyncio.sleep(10) # Every 10 seconds
        new_risk = decay_network_risk(factor=0.95)
        insert_risk_score(new_risk)


# -------------------------
# WebSocket Broadcaster
# -------------------------
async def broadcast_loop():
    """Send buffered packets, metrics, and alerts to all WebSocket clients."""
    while True:
        await asyncio.sleep(0.5)

        with buffer_lock:
            packets = list(packet_buffer)
            packet_buffer.clear()

        if not packets and not connected_clients:
            continue

        payload = {
            "type": "update",
            "packets": packets[-50:],
            "stats": get_stats(),
            "network_risk": get_network_risk(),
            "risk_trend": get_risk_trend(30),
            "system": get_system_metrics(),
            "is_running": is_running,
        }

        msg = json.dumps(payload, default=str)

        disconnected = []
        for ws in connected_clients:
            try:
                await ws.send_text(msg)
            except:
                disconnected.append(ws)

        for ws in disconnected:
            if ws in connected_clients:
                connected_clients.remove(ws)

async def traffic_intel_broadcast_loop():
    """Send aggregated traffic intelligence metrics to all /ws/traffic-intel clients."""
    while True:
        await asyncio.sleep(1.5)

        if not intel_clients:
            continue

        metrics = traffic_engine.get_aggregated_metrics()
        msg = json.dumps({"type": "traffic_intel", "metrics": metrics}, default=str)

        disconnected = []
        for ws in intel_clients:
            try:
                await ws.send_text(msg)
            except:
                disconnected.append(ws)

        for ws in disconnected:
            if ws in intel_clients:
                intel_clients.remove(ws)


# -------------------------
# Routes — Dashboard
# -------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("templates/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()


# -------------------------
# Routes — Core Stats API
# -------------------------
@app.get("/api/stats")
async def api_stats():
    return JSONResponse(get_stats())


@app.get("/api/system")
async def api_system():
    return JSONResponse(get_system_metrics())


# -------------------------
# Routes — Events & Alerts
# -------------------------
@app.get("/api/alerts")
async def api_alerts():
    return JSONResponse(get_recent_alerts(50))


@app.get("/api/alerts/all")
async def api_alerts_all():
    return JSONResponse(get_all_alerts())


@app.get("/api/events")
async def api_events(
    event_type: str = None,
    severity: str = None,
    src_ip: str = None,
    search: str = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    """Paginated event search with filters."""
    return JSONResponse(search_security_logs(
        alert_type=event_type, severity=severity,
        src_ip=src_ip, search=search, limit=limit, offset=offset
    ))


@app.get("/api/events/timeline")
async def api_events_timeline(hours: int = 1, unit: str = "minute"):
    """Granular event counts for live pulse charts."""
    return JSONResponse(get_event_timeline(hours, unit))


@app.get("/api/severity")
async def api_severity():
    """Severity distribution."""
    return JSONResponse(get_severity_distribution())


# -------------------------
# Routes — Packets
# -------------------------
@app.get("/api/packets")
async def api_packets():
    return JSONResponse(get_recent_packets(100))


@app.get("/api/protocols")
async def api_protocols():
    """Protocol distribution stats."""
    return JSONResponse(get_protocol_stats())


# -------------------------
# Routes — Incidents
# -------------------------
@app.get("/api/incidents")
async def api_incidents(status: str = None):
    """Get incidents, optionally filtered by status."""
    return JSONResponse(get_incidents(status=status))


@app.get("/api/incidents/{incident_id}")
async def api_incident_detail(incident_id: int):
    """Get a single incident."""
    inc = get_incident(incident_id)
    if inc:
        return JSONResponse(inc)
    return JSONResponse({"error": "Not found"}, status_code=404)


@app.put("/api/incidents/{incident_id}")
async def api_incident_update(incident_id: int):
    """Update incident status or add a note."""
    from fastapi import Request
    # Parse body manually for simplicity
    import json as jsonlib
    return JSONResponse({"error": "Use POST"}, status_code=405)


@app.post("/api/incidents/{incident_id}")
async def api_incident_action(incident_id: int, action: str = "acknowledge", note: str = ""):
    """Update incident: acknowledge, investigate, resolve, false_positive."""
    status_map = {
        "acknowledge": "ACKNOWLEDGED",
        "investigate": "INVESTIGATING",
        "resolve": "RESOLVED",
        "false_positive": "FALSE_POSITIVE",
    }
    new_status = status_map.get(action)
    if not new_status:
        return JSONResponse({"error": f"Invalid action: {action}"}, status_code=400)

    update_incident(incident_id, status=new_status, note=note or f"Status changed to {new_status}")
    return JSONResponse({"ok": True, "status": new_status})


# -------------------------
# Routes — Investigations Page
# -------------------------
@app.get("/investigations", response_class=HTMLResponse)
async def investigations_page():
    with open("templates/investigations.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/investigations/{event_id}/start")
async def api_start_investigation(event_id: int):
    """Create a new incident from a detected threat event."""
    from database import _get_conn
    conn = _get_conn()
    row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "Event not found"}, status_code=404)

    ev = dict(row)
    title = f"[{ev['severity']}] {ev['event_type']} — {ev['src_ip'] or 'Unknown'}"
    incident_id = create_incident(
        title=title,
        severity=ev["severity"],
        event_ids=[event_id],
        src_ip=ev.get("src_ip", ""),
        kill_chain_phase=ev.get("mitre_tactic", "")
    )
    return JSONResponse({"ok": True, "incident_id": incident_id})


@app.post("/api/investigations/{incident_id}/update")
async def api_update_investigation(incident_id: int, request: Request):
    """Update investigation status and/or add a note."""
    body = await request.json()
    status = body.get("status")
    note = body.get("note")

    if not status and not note:
        return JSONResponse({"error": "Provide status or note"}, status_code=400)

    update_incident(incident_id, status=status, note=note)
    return JSONResponse({"ok": True})


# -------------------------
# Routes — Network & Topology
# -------------------------
@app.get("/api/topology")
async def api_topology():
    """Network topology data enriched with threat levels."""
    import socket
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except:
        local_ip = "127.0.0.1"

    topo = get_network_topology()
    enriched = []
    
    unique_ips = set()
    node_packet_counts = {} # ip -> count
    
    for entry in topo:
        s_ip, d_ip, w = entry["src_ip"], entry["dst_ip"], entry["weight"]
        unique_ips.add(s_ip)
        unique_ips.add(d_ip)
        node_packet_counts[s_ip] = node_packet_counts.get(s_ip, 0) + w
        node_packet_counts[d_ip] = node_packet_counts.get(d_ip, 0) + w

    # Get threat levels for all IPs involved
    threat_map = {}
    for ip in unique_ips:
        t_info = get_ip_threat_score(ip)
        # Add the packet counts into the threat_map for node display
        t_info["total_packets"] = node_packet_counts.get(ip, 0)
        threat_map[ip] = t_info

    for entry in topo:
        e = dict(entry)
        e["src_threat"] = threat_map.get(e["src_ip"], {}).get("level", "low")
        e["dst_threat"] = threat_map.get(e["dst_ip"], {}).get("level", "low")
        e["is_local_src"] = (e["src_ip"] == local_ip)
        e["is_local_dst"] = (e["dst_ip"] == local_ip)
        enriched.append(e)

    return JSONResponse({
        "links": enriched,
        "local_ip": local_ip,
        "threat_map": threat_map
    })


@app.get("/api/attackers")
async def api_attackers():
    """Top attacker IPs."""
    return JSONResponse(get_top_attackers())


@app.get("/api/threat-scores")
async def api_threat_scores():
    """IP threat scores from correlation engine."""
    return JSONResponse(get_all_threat_scores())


# -------------------------
# Routes — Threat Intelligence
# -------------------------
@app.get("/api/threat-intel/{ip}")
async def api_threat_intel(ip: str):
    """Threat intel lookup for an IP."""
    return JSONResponse(get_ip_summary(ip))


# -------------------------
# Routes — MITRE ATT&CK
# -------------------------
@app.get("/api/mitre")
async def api_mitre():
    """MITRE ATT&CK coverage map."""
    coverage = get_mitre_coverage()
    return JSONResponse({
        "coverage": coverage,
        "definitions": MITRE_MAP,
    })


# -------------------------
# Routes — AI Analyst
# -------------------------
@app.get("/api/ai/analyze/{event_id}")
async def api_ai_analyze(event_id: int):
    """Get AI analysis and recommendations for an alert."""
    alerts = get_all_alerts()
    alert = next((a for a in alerts if a["id"] == event_id), None)
    if not alert:
        return JSONResponse({"error": "Alert not found"}, status_code=404)
    
    explanation = expert_analyst.explain_alert(alert)
    actions = expert_analyst.get_response_actions(alert)
    
    return JSONResponse({
        "ok": True,
        "analysis": explanation,
        "actions": actions
    })


# -------------------------
# WebSocket
# -------------------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    print(f"[WS] Client connected ({len(connected_clients)} total)")
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in connected_clients:
            connected_clients.remove(ws)
        print(f"[WS] Client disconnected ({len(connected_clients)} total)")

@app.websocket("/ws/traffic-intel")
async def traffic_intel_websocket(ws: WebSocket):
    await ws.accept()
    intel_clients.append(ws)
    print(f"[WS-INTEL] Client connected ({len(intel_clients)} total)")
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in intel_clients:
            intel_clients.remove(ws)
        print(f"[WS-INTEL] Client disconnected ({len(intel_clients)} total)")


# -------------------------
# Lifecycle
# -------------------------
@app.on_event("startup")
async def on_startup():
    global capture_thread
    # Initialize database
    init_db()
    print("[+] Database initialized")

    # Initialize MongoDB Atlas connection
    if atlas_client.connect():
        print("[+] MongoDB Atlas connected and ready")
    else:
        print("[WARN] MongoDB Atlas connection failed or not configured")

    capture_thread = threading.Thread(target=capture_worker, daemon=True)
    capture_thread.start()

    if REDIRECT_HTTP_TO_HTTPS:
        # redir_thread = threading.Thread(target=http_redirection_worker, daemon=True)
        # redir_thread.start()
        pass

    asyncio.create_task(broadcast_loop())
    asyncio.create_task(traffic_intel_broadcast_loop())
    asyncio.create_task(risk_maintenance_loop())
    print(f"[+] SIEM Dashboard running at http://localhost:{SERVER_PORT}")


@app.on_event("shutdown")
async def on_shutdown():
    global is_running
    is_running = False
    
    # Ensure all buffered packets are flushed to DB
    from database import packet_buffer
    packet_buffer.stop()
    
    if capture_proc and capture_proc.poll() is None:
        capture_proc.terminate()
    print("[+] Server shutdown and buffer flushed")


if __name__ == "__main__":
    uvicorn.run("server:app", host=SERVER_HOST, port=SERVER_PORT, reload=False)

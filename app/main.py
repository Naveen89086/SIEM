"""
SIEM Dashboard Server - Reorganized for Production Deployment
Enhanced FastAPI backend with WebSocket, incident management, and full SIEM API.
"""
import asyncio
import json
import threading
import time
import os
import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import (
    SERVER_HOST, SERVER_PORT, MITRE_MAP,
    USE_HTTPS, SSL_CERT_FILE, SSL_KEY_FILE, REDIRECT_HTTP_TO_HTTPS, BASE_URL
)
from app.core.packet_capture import start_capture
from app.core.detector import (
    analyze_packet_header, cleanup_old_data, get_stats,
    get_network_risk, decay_network_risk
)
from app.core.logger import log_event, log_packet, get_recent_alerts, get_recent_packets, get_all_alerts
from app.database import (
    init_db, query_events, search_security_logs, get_event_timeline, get_top_attackers,
    get_network_topology, get_incidents, get_incident, update_incident,
    get_severity_distribution, get_mitre_coverage, get_protocol_stats,
    create_incident, insert_risk_score, get_risk_trend
)
from app.core.threat_intel import get_ip_summary, check_ip_reputation
from app.core.correlation import get_all_threat_scores, get_ip_threat_score
from app.core.ai_analyst import expert_analyst
from app.mongodb import atlas_client
from app.core.traffic_intel_engine import engine as traffic_engine

app = FastAPI(title="SOC SIEM Dashboard")

# Global State
capture_proc = None
capture_thread = None
is_running = False
start_time = time.time()
connected_clients: list[WebSocket] = []
intel_clients: list[WebSocket] = []
packet_buffer: list[dict] = []
buffer_lock = threading.Lock()

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def get_system_metrics():
    curr_net_io = psutil.net_io_counters()
    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "disk_percent": disk.percent,
        "net_total_sent_mb": round(curr_net_io.bytes_sent / (1024**2), 2),
        "net_total_recv_mb": round(curr_net_io.bytes_recv / (1024**2), 2),
        "uptime_seconds": int(time.time() - start_time),
        "mongodb_connected": atlas_client._connected,
    }

def is_internal_ip(ip):
    if not ip or ip == "Unknown": return False
    parts = ip.split('.')
    if len(parts) != 4: return False
    p1, p2 = int(parts[0]), int(parts[1])
    return p1 == 10 or (p1 == 172 and 16 <= p2 <= 31) or (p1 == 192 and p2 == 168) or p1 == 127

def capture_worker():
    global capture_proc, is_running
    capture_proc = start_capture()
    is_running = True
    try:
        for line in capture_proc.stdout:
            if not is_running: break
            line = line.strip()
            if not line: continue
            fields = line.split("|")
            if len(fields) < 15: fields += [""] * (15 - len(fields))
            src, dst, proto = fields[0], fields[1], fields[2]
            src_port, dst_port, proto_name = "", "", f"PROTO-{proto}"
            if proto == "6": src_port, dst_port, proto_name = fields[3], fields[4], "TCP"
            elif proto == "17": src_port, dst_port, proto_name = fields[5], fields[6], "UDP"
            elif proto == "1": proto_name = "ICMP"
            
            length = int(fields[7]) if fields[7].isdigit() else 0
            flags, dns_query, dns_type = fields[8], fields[9], fields[10]
            if dns_query: proto_name = "DNS"
            http_host, http_method, tls_sni, icmp_type = fields[11], fields[12], fields[13], fields[14]
            if http_host or http_method: proto_name = "HTTP"
            
            cleanup_old_data()
            src_type = "INT" if is_internal_ip(src) else "EXT"
            dst_type = "INT" if is_internal_ip(dst) else "EXT"
            packet_data = {
                 "src_ip": src, "src_type": src_type, "dst_ip": dst, "dst_type": dst_type,
                 "protocol": proto_name, "src_port": src_port, "dst_port": dst_port,
                 "length": length, "flags": flags, "dns_query": dns_query, "dns_type": dns_type,
                 "http_host": http_host, "http_method": http_method, "tls_sni": tls_sni, "icmp_type": icmp_type,
            }
            is_threat, threat_msg = analyze_packet_header(packet_data)
            security_status = "THREAT" if is_threat else ("SUSPICIOUS" if dst_port in ["22", "3389"] else "SAFE")
            packet_data.update({"is_threat": is_threat, "threat_msg": threat_msg if is_threat else "", "security_status": security_status})
            
            log_packet(packet_data)
            traffic_engine.process_packet(packet_data)
            with buffer_lock:
                packet_data["id"] = int(time.time() * 1000000)
                packet_buffer.append(packet_data)
    except Exception as e:
        print(f"[ERROR] Capture error: {e}")
    finally:
        is_running = False
        if capture_proc and capture_proc.poll() is None: capture_proc.terminate()

async def risk_maintenance_loop():
    while True:
        await asyncio.sleep(10)
        new_risk = decay_network_risk(factor=0.95)
        insert_risk_score(new_risk)

async def broadcast_loop():
    while True:
        await asyncio.sleep(0.5)
        with buffer_lock:
            packets, packet_buffer[:] = list(packet_buffer), []
        if not packets and not connected_clients: continue
        payload = {
            "type": "update", "packets": packets[-50:], "stats": get_stats(),
            "network_risk": get_network_risk(), "risk_trend": get_risk_trend(30),
            "system": get_system_metrics(), "is_running": is_running,
        }
        msg = json.dumps(payload, default=str)
        for ws in list(connected_clients):
            try: await ws.send_text(msg)
            except: connected_clients.remove(ws)

async def traffic_intel_broadcast_loop():
    while True:
        await asyncio.sleep(1.5)
        if not intel_clients: continue
        metrics = traffic_engine.get_aggregated_metrics()
        msg = json.dumps({"type": "traffic_intel", "metrics": metrics}, default=str)
        for ws in list(intel_clients):
            try: await ws.send_text(msg)
            except: intel_clients.remove(ws)

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/stats")
async def api_stats(): return JSONResponse(get_stats())

@app.get("/api/system")
async def api_system(): return JSONResponse(get_system_metrics())

@app.get("/api/alerts")
async def api_alerts(): return JSONResponse(get_recent_alerts(50))

@app.get("/api/events")
async def api_events(event_type: str = None, severity: str = None, src_ip: str = None, search: str = None, limit: int = 100, offset: int = 0):
    return JSONResponse(search_security_logs(event_type, severity, src_ip, search, limit, offset))

@app.get("/investigations", response_class=HTMLResponse)
async def investigations_page():
    with open(os.path.join(TEMPLATE_DIR, "investigations.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: pass
    finally:
        if ws in connected_clients: connected_clients.remove(ws)

@app.websocket("/ws/traffic-intel")
async def traffic_intel_websocket(ws: WebSocket):
    await ws.accept()
    intel_clients.append(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: pass
    finally:
        if ws in intel_clients: intel_clients.remove(ws)

@app.on_event("startup")
async def on_startup():
    global capture_thread
    init_db()
    if atlas_client.connect(): print("[+] MongoDB Atlas connected")
    
    # Disable packet capture on Render/cloud
    render_env = os.getenv("RENDER", "").lower() == "true"
    if not render_env:
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()
        print("[+] Local packet capture started")
    else:
        print("[+] Render environment detected - packet capture disabled")

    asyncio.create_task(broadcast_loop())
    asyncio.create_task(traffic_intel_broadcast_loop())
    asyncio.create_task(risk_maintenance_loop())

@app.on_event("shutdown")
async def on_shutdown():
    global is_running
    is_running = False
    from app.database import packet_buffer as db_packet_buffer
    db_packet_buffer.stop()
    if capture_proc and capture_proc.poll() is None: capture_proc.terminate()

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=SERVER_HOST, port=SERVER_PORT, reload=False)

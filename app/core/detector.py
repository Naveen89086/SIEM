"""
Enhanced SIEM Detection Engine
"""
import time
import statistics
from collections import defaultdict, deque
import threading
from app.config import (
    THRESHOLD, TIME_WINDOW, BLOCKED_PORTS, SCAN_THRESHOLD, SCAN_WINDOW,
    SYN_THRESHOLD, SYN_FLOOD_WINDOW, BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW, DNS_TUNNEL_SIZE, DNS_TUNNEL_RATE, DNS_TUNNEL_WINDOW,
    EXFIL_SIZE_THRESHOLD, EXFIL_WINDOW, BEACON_TOLERANCE,
    BEACON_MIN_COUNT, BEACON_INTERVAL_MIN, BEACON_WINDOW, 
    RANSOMWARE_FILE_MODS, RANSOMWARE_WINDOW, AUTH_PORTS, MITRE_MAP
)
from app.core.logger import log_event
from app.core.threat_intel import check_ip_reputation
from app.core.correlation import add_event as correlate_event

# STATE TRACKING
ip_activity = defaultdict(list)
port_scan_tracker = defaultdict(set)
syn_tracker = defaultdict(list)
brute_force_tracker = defaultdict(list)
dns_tracker = defaultdict(list)
outbound_tracker = defaultdict(list)
beacon_tracker = defaultdict(list)
alerted_ips = set()

class BehavioralTracker:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.history = defaultdict(deque)
        self.lock = threading.Lock()

    def add(self, key, value=None):
        now = time.time()
        with self.lock:
            self.history[key].append((now, value))
            self._prune(key, now)
    
    def get_count(self, key):
        now = time.time()
        with self.lock:
            self._prune(key, now)
            return len(self.history[key])

    def _prune(self, key, now):
        while self.history[key] and now - self.history[key][0][0] > self.window:
            self.history[key].popleft()

class RansomwareTracker:
    def __init__(self):
        self.file_mods = BehavioralTracker(window_seconds=RANSOMWARE_WINDOW)
        self.outbound_conns = BehavioralTracker(window_seconds=60)
        self.processes = BehavioralTracker(window_seconds=300)
    def record_file_mod(self, filepath): self.file_mods.add("system", filepath)
    def record_outbound(self, dst_ip): self.outbound_conns.add("system", dst_ip)
    def record_process(self, proc_name): self.processes.add("system", proc_name)

class AuthTracker:
    def __init__(self):
        self.failures = BehavioralTracker(window_seconds=120)
    def record_failure(self, ip): self.failures.add(ip, "fail")
    def reset(self, ip):
        with self.failures.lock:
            if ip in self.failures.history: self.failures.history[ip].clear()

ransomware_monitor = RansomwareTracker()
auth_monitor = AuthTracker()

stats = {
    "total_packets": 0, "total_alerts": 0,
    "by_type": defaultdict(int), "by_protocol": defaultdict(int),
    "by_severity": defaultdict(int), "packets_per_second": 0,
    "last_packet_time": 0, "network_risk": 0.0,
}

def get_network_risk(): return round(stats["network_risk"], 2)
def update_network_risk(event_risk):
    stats["network_risk"] = stats["network_risk"] * 0.7 + event_risk * 0.3
    stats["network_risk"] = min(100, stats["network_risk"])
    return stats["network_risk"]

def decay_network_risk(factor=0.98):
    stats["network_risk"] *= factor
    if stats["network_risk"] < 0.1: stats["network_risk"] = 0
    return stats["network_risk"]

_pps_timestamps = []

def get_stats():
    now = time.time()
    global _pps_timestamps
    _pps_timestamps = [t for t in _pps_timestamps if now - t <= 5]
    pps = len(_pps_timestamps) / 5.0 if _pps_timestamps else 0
    return {
        "total_packets": stats["total_packets"],
        "total_alerts": stats["total_alerts"],
        "by_type": dict(stats["by_type"]),
        "by_protocol": dict(stats["by_protocol"]),
        "by_severity": dict(stats["by_severity"]),
        "packets_per_second": round(pps, 1),
        "last_packet_time": stats["last_packet_time"],
    }

def cleanup_old_data():
    now = time.time()
    for ip in list(ip_activity.keys()):
        ip_activity[ip] = [t for t in ip_activity[ip] if now - t <= TIME_WINDOW]
        if not ip_activity[ip]: del ip_activity[ip]
    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [t for t in syn_tracker[ip] if now - t <= SYN_FLOOD_WINDOW]
        if not syn_tracker[ip]: del syn_tracker[ip]
    for ip in list(brute_force_tracker.keys()):
        brute_force_tracker[ip] = [t for t in brute_force_tracker[ip] if now - t <= BRUTE_FORCE_WINDOW]
        if not brute_force_tracker[ip]: del brute_force_tracker[ip]
    for ip in list(dns_tracker.keys()):
        dns_tracker[ip] = [(t, s) for t, s in dns_tracker[ip] if now - t <= DNS_TUNNEL_WINDOW]
        if not dns_tracker[ip]: del dns_tracker[ip]
    for ip in list(outbound_tracker.keys()):
        outbound_tracker[ip] = [(t, b) for t, b in outbound_tracker[ip] if now - t <= EXFIL_WINDOW]
        if not outbound_tracker[ip]: del outbound_tracker[ip]
    for key in list(beacon_tracker.keys()):
        beacon_tracker[key] = [t for t in beacon_tracker[key] if now - t <= BEACON_WINDOW]
        if not beacon_tracker[key]: del beacon_tracker[key]

def calculate_risk_score(severity, event_type, src_ip, correlation_count=1):
    sev_weights = {"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 5.0, "CRITICAL": 10.0}
    base = sev_weights.get(severity, 1.0)
    count = stats["by_type"][event_type] + 1
    freq_weight = 1.0 + (count / 50.0)
    corr_multi = 1.0 + (correlation_count * 0.5)
    criticality = 2.0 if src_ip.startswith(("192.168.", "10.", "172.16.")) else 1.0
    pps = get_stats()["packets_per_second"]
    anomaly = 1.0 + (pps / 100.0) if pps > 50 else 1.0
    return round(min(100, (base * freq_weight) * corr_multi * criticality * anomaly), 2)

def _record_alert(event_type, message, details, severity, src_ip="", dst_ip="", protocol="", port=""):
    mitre = MITRE_MAP.get(event_type, {})
    confidence = 95 if event_type in ["RANSOMWARE", "AUTH_COMPROMISE"] else 80
    score = calculate_risk_score(severity, event_type, src_ip)
    update_network_risk(score)
    enrichment = {"risk_score": score, "confidence": confidence, "asset_criticality": "HIGH" if src_ip.startswith("192.") else "MEDIUM"}
    
    if src_ip:
        intel = check_ip_reputation(src_ip)
        if intel.get("is_malicious"):
            details["threat_intel"] = {"tags": intel.get("tags", []), "region": intel.get("region", "Unknown"), "confidence": intel.get("confidence", 0)}
            if severity == "MEDIUM": severity = "HIGH"
            confidence += 5

    event_id = log_event(event_type, message, {**details, "enrichment": enrichment}, severity,
                        mitre_id=mitre.get("id", ""), mitre_tactic=mitre.get("tactic", ""),
                        src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=port)
    stats["total_alerts"] += 1
    stats["by_type"][event_type] += 1
    stats["by_severity"][severity] += 1
    if src_ip and event_id: correlate_event(src_ip, event_type, event_id, severity)
    return True, message

def analyze_packet_rate(src_ip, dst_ip):
    now = time.time()
    ip_activity[src_ip].append(now)
    count = len(ip_activity[src_ip])
    if count >= THRESHOLD and src_ip not in alerted_ips:
        alerted_ips.add(src_ip)
        severity = "CRITICAL" if count >= THRESHOLD * 3 else "HIGH"
        return _record_alert("RATE_LIMIT", f"High packet rate from {src_ip} -> {dst_ip}", {"src_ip": src_ip, "dst_ip": dst_ip, "count": count}, severity, src_ip, dst_ip, protocol="IP")
    return False, ""

def analyze_port_scan(src_ip, dst_port):
    if not dst_port: return False, ""
    port_scan_tracker[src_ip].add(dst_port)
    unique_ports = len(port_scan_tracker[src_ip])
    if unique_ports >= SCAN_THRESHOLD:
        alert_key = f"{src_ip}_SCAN"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            port_scan_tracker[src_ip].clear()
            severity = "HIGH" if unique_ports >= SCAN_THRESHOLD * 2 else "MEDIUM"
            return _record_alert("PORT_SCAN", f"Port Scan detected from {src_ip}", {"src_ip": src_ip, "ports_scanned": unique_ports}, severity, src_ip, port=dst_port)
    return False, ""

def analyze_syn_flood(src_ip, flags):
    if not flags: return False, ""
    try: flag_val = int(flags, 0); is_syn_only = (flag_val & 0x12) == 0x02
    except: is_syn_only = "0x0002" in str(flags) or "S" in str(flags)
    if not is_syn_only: return False, ""
    now = time.time()
    syn_tracker[src_ip].append(now)
    if len(syn_tracker[src_ip]) >= SYN_THRESHOLD:
        if f"{src_ip}_SYN" not in alerted_ips:
            alerted_ips.add(f"{src_ip}_SYN")
            return _record_alert("SYN_FLOOD", f"SYN Flood detected from {src_ip}", {"src_ip": src_ip}, "CRITICAL", src_ip, protocol="TCP")
    return False, ""

def analyze_dns_tunnel(src_ip, dst_port, length):
    if dst_port != "53": return False, ""
    now = time.time()
    dns_tracker[src_ip].append((now, length))
    recent = dns_tracker[src_ip]
    if len(recent) >= DNS_TUNNEL_RATE:
        avg_size = sum(s for _, s in recent) / len(recent)
        if avg_size >= DNS_TUNNEL_SIZE and f"{src_ip}_DNS" not in alerted_ips:
            alerted_ips.add(f"{src_ip}_DNS")
            return _record_alert("DNS_TUNNEL", f"Possible DNS Tunneling from {src_ip}", {"src_ip": src_ip, "avg_size": avg_size}, "HIGH", src_ip, protocol="UDP", port="53")
    return False, ""

def analyze_brute_force(src_ip, dst_port):
    if dst_port not in AUTH_PORTS: return False, ""
    now = time.time()
    brute_force_tracker[src_ip].append(now)
    if len(brute_force_tracker[src_ip]) >= BRUTE_FORCE_THRESHOLD and f"{src_ip}_BRUTE" not in alerted_ips:
        alerted_ips.add(f"{src_ip}_BRUTE")
        return _record_alert("BRUTE_FORCE", f"Brute Force attempt from {src_ip}", {"src_ip": src_ip, "target_port": dst_port}, "HIGH", src_ip, port=dst_port)
    return False, ""

def analyze_data_exfil(src_ip, length):
    now = time.time()
    outbound_tracker[src_ip].append((now, length))
    total = sum(b for _, b in outbound_tracker[src_ip])
    if total >= EXFIL_SIZE_THRESHOLD and f"{src_ip}_EXFIL" not in alerted_ips:
        alerted_ips.add(f"{src_ip}_EXFIL")
        return _record_alert("DATA_EXFIL", f"Possible Data Exfiltration from {src_ip}", {"src_ip": src_ip, "bytes_sent": total}, "CRITICAL", src_ip)
    return False, ""

def analyze_beaconing(src_ip, dst_ip):
    now = time.time()
    key = f"{src_ip}->{dst_ip}"
    beacon_tracker[key].append(now)
    if len(beacon_tracker[key]) < BEACON_MIN_COUNT: return False, ""
    timestamps = beacon_tracker[key][-20:]
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    try:
        avg_interval = statistics.mean(intervals)
        if avg_interval < 1: return False, ""
        jitter = (statistics.stdev(intervals) / avg_interval) if len(intervals) > 1 else 0
        if jitter <= BEACON_TOLERANCE and avg_interval >= BEACON_INTERVAL_MIN and f"{key}_BEACON" not in alerted_ips:
            alerted_ips.add(f"{key}_BEACON")
            return _record_alert("BEACONING", f"Beaconing detected: {src_ip} -> {dst_ip}", {"src_ip": src_ip, "dst_ip": dst_ip, "jitter": round(jitter, 3)}, "MEDIUM", src_ip, dst_ip)
    except: pass
    return False, ""

def analyze_packet_header(packet):
    stats["total_packets"] += 1
    stats["last_packet_time"] = time.time()
    _pps_timestamps.append(time.time())
    proto = packet.get("protocol", "OTHER")
    stats["by_protocol"][proto] += 1
    try:
        dst_ip, src_ip, dst_port, length = packet.get("dst_ip", "Unknown"), packet.get("src_ip", "Unknown"), packet.get("dst_port", ""), packet.get("length", 0)
        if not src_ip or not dst_ip: return True, "Missing IP"
        if dst_port in BLOCKED_PORTS: _record_alert("BLOCKED_PORT", f"Traffic to blocked port {dst_port} from {src_ip}", packet, "HIGH", src_ip, dst_ip, protocol=proto, port=dst_port)
        analyze_port_scan(src_ip, dst_port)
        if proto == "TCP": analyze_syn_flood(src_ip, packet.get("flags", ""))
        if proto == "UDP": analyze_dns_tunnel(src_ip, dst_port, length)
        analyze_brute_force(src_ip, dst_port)
        analyze_data_exfil(src_ip, length)
        analyze_beaconing(src_ip, dst_ip)
        if not dst_ip.startswith(("192.168.", "10.", "127.", "0.")): ransomware_monitor.record_outbound(dst_ip)
        analyze_packet_rate(src_ip, dst_ip)
        return False, "OK"
    except Exception as e:
        log_event("ERROR", f"Analysis error: {e}", severity="LOW")
        return True, str(e)

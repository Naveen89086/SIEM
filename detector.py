"""
Enhanced SIEM Detection Engine
8 detection rules with MITRE ATT&CK mapping and threat intelligence enrichment.
"""
import time
import statistics
from collections import defaultdict
from config import (
    THRESHOLD, TIME_WINDOW, BLOCKED_PORTS, SCAN_THRESHOLD, SCAN_WINDOW,
    SYN_THRESHOLD, SYN_FLOOD_WINDOW, BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW, DNS_TUNNEL_SIZE, DNS_TUNNEL_RATE, DNS_TUNNEL_WINDOW,
    EXFIL_SIZE_THRESHOLD, EXFIL_WINDOW, BEACON_TOLERANCE,
    BEACON_MIN_COUNT, BEACON_INTERVAL_MIN, BEACON_WINDOW, 
    RANSOMWARE_FILE_MODS, RANSOMWARE_WINDOW, AUTH_PORTS, MITRE_MAP
)
from logger import log_event
from threat_intel import check_ip_reputation
from correlation import add_event as correlate_event
from collections import deque
import threading

# -------------------------
# STATE TRACKING
# -------------------------
ip_activity = defaultdict(list)          # ip -> [timestamps]
port_scan_tracker = defaultdict(set)     # ip -> {ports}
syn_tracker = defaultdict(list)          # ip -> [timestamps of SYN packets]
brute_force_tracker = defaultdict(list)  # ip -> [timestamps to auth ports]
dns_tracker = defaultdict(list)          # ip -> [(timestamp, size)]
outbound_tracker = defaultdict(list)     # ip -> [(timestamp, bytes)]
beacon_tracker = defaultdict(list)       # ip -> [timestamps for interval analysis]
alerted_ips = set()

# -------------------------
# BEHAVIORAL TRACKERS
# -------------------------
class BehavioralTracker:
    """Thread-safe sliding window tracker for behavioral signals."""
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

    def get_values(self, key):
        now = time.time()
        with self.lock:
            self._prune(key, now)
            return [v for t, v in self.history[key]]

    def _prune(self, key, now):
        while self.history[key] and now - self.history[key][0][0] > self.window:
            self.history[key].popleft()

class RansomwareTracker:
    def __init__(self):
        self.file_mods = BehavioralTracker(window_seconds=RANSOMWARE_WINDOW)
        self.outbound_conns = BehavioralTracker(window_seconds=60)
        self.processes = BehavioralTracker(window_seconds=300)
    
    def record_file_mod(self, filepath):
        self.file_mods.add("system", filepath)
    
    def record_outbound(self, dst_ip):
        # We only care about unique connections for the spike detection
        self.outbound_conns.add("system", dst_ip)

    def record_process(self, proc_name):
        self.processes.add("system", proc_name)

class AuthTracker:
    def __init__(self):
        self.failures = BehavioralTracker(window_seconds=120)
        self.state = defaultdict(str) # ip -> 'PROBING' | 'LOCKED' | 'NORMAL'

    def record_failure(self, ip):
        self.failures.add(ip, "fail")
    
    def reset(self, ip):
        with self.failures.lock:
            if ip in self.failures.history:
                self.failures.history[ip].clear()

# Global Instances
ransomware_monitor = RansomwareTracker()
auth_monitor = AuthTracker()

# Stats for dashboard
stats = {
    "total_packets": 0,
    "total_alerts": 0,
    "by_type": defaultdict(int),
    "by_protocol": defaultdict(int),
    "by_severity": defaultdict(int),
    "packets_per_second": 0,
    "last_packet_time": 0,
    "network_risk": 0.0,
}

# -------------------------
# RISK INTELLIGENCE ENGINE
# -------------------------
def get_network_risk():
    return round(stats["network_risk"], 2)

def update_network_risk(event_risk):
    """Update global risk index with a weighted average."""
    old_risk = stats["network_risk"]
    stats["network_risk"] = stats["network_risk"] * 0.7 + event_risk * 0.3
    stats["network_risk"] = min(100, stats["network_risk"])
    if round(old_risk, 1) != round(stats["network_risk"], 1):
        print(f"[!] Network Risk Update: {old_risk:.1f} -> {stats['network_risk']:.1f} (Event Score: {event_risk})")
    return stats["network_risk"]

def decay_network_risk(factor=0.98):
    """Slowly reduce risk over time if no alerts occur."""
    old_risk = stats["network_risk"]
    stats["network_risk"] *= factor
    if stats["network_risk"] < 0.1:
        stats["network_risk"] = 0
    if round(old_risk, 1) != round(stats["network_risk"], 1):
        print(f"[-] Network Risk Decay: {old_risk:.1f} -> {stats['network_risk']:.1f}")
    return stats["network_risk"]

# Track packets per second
_pps_timestamps = []


def get_stats():
    """Return stats dict for API."""
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
    """Removes old timestamps to keep memory usage low."""
    now = time.time()
    for ip in list(ip_activity.keys()):
        ip_activity[ip] = [t for t in ip_activity[ip] if now - t <= TIME_WINDOW]
        if not ip_activity[ip]:
            del ip_activity[ip]

    for ip in list(port_scan_tracker.keys()):
        # Since port_scan_tracker is a set without timestamps in the original implementation,
        # we realistically can't prune it by time without changing its data structure.
        # For simplicity in this script, we'll clear it periodically or rely on the SIEM's 
        # broader IP tracking. A proper implementation would refactor port_scan_tracker 
        # to track timestamps per port probed.
        pass

    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [t for t in syn_tracker[ip] if now - t <= SYN_FLOOD_WINDOW]
        if not syn_tracker[ip]:
            del syn_tracker[ip]

    for ip in list(brute_force_tracker.keys()):
        brute_force_tracker[ip] = [t for t in brute_force_tracker[ip] if now - t <= BRUTE_FORCE_WINDOW]
        if not brute_force_tracker[ip]:
            del brute_force_tracker[ip]

    for ip in list(dns_tracker.keys()):
        dns_tracker[ip] = [(t, s) for t, s in dns_tracker[ip] if now - t <= DNS_TUNNEL_WINDOW]
        if not dns_tracker[ip]:
            del dns_tracker[ip]

    for ip in list(outbound_tracker.keys()):
        outbound_tracker[ip] = [(t, b) for t, b in outbound_tracker[ip] if now - t <= EXFIL_WINDOW]
        if not outbound_tracker[ip]:
            del outbound_tracker[ip]

    for key in list(beacon_tracker.keys()):
        beacon_tracker[key] = [t for t in beacon_tracker[key] if now - t <= BEACON_WINDOW]
        if not beacon_tracker[key]:
            del beacon_tracker[key]



def calculate_risk_score(severity, event_type, src_ip, correlation_count=1):
    """
    Tier-1 Risk Score = (Severity Weight × Event Count) 
                     × (Behavioral Multiplier) 
                     × (Asset Criticality) 
                     × (Anomaly Score)
    """
    # 1. Severity Weight
    sev_weights = {"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 5.0, "CRITICAL": 10.0}
    base = sev_weights.get(severity, 1.0)
    
    # 2. Event Count (Frequency)
    count = stats["by_type"][event_type] + 1
    freq_weight = 1.0 + (count / 50.0) # Slow scaling
    
    # 3. Behavioral Correlation Multiplier
    # (Provided as argument, e.g., how many related events in correlation engine)
    corr_multi = 1.0 + (correlation_count * 0.5)
    
    # 4. Asset Criticality Score
    # Local assets are 2x more important
    criticality = 2.0 if src_ip.startswith(("192.168.", "10.", "172.16.")) else 1.0
    
    # 5. Anomaly Deviation Score
    # Simplified: Higher packet rates than average increase risk
    pps = get_stats()["packets_per_second"]
    anomaly = 1.0 + (pps / 100.0) if pps > 50 else 1.0
    
    # Calculate raw score
    raw_score = (base * freq_weight) * corr_multi * criticality * anomaly
    
    # Normalize to 0-100
    final_score = min(100, raw_score)
    return round(final_score, 2)


def _record_alert(event_type, message, details, severity, src_ip="", dst_ip="", protocol="", port=""):
    """Log an alert with enhanced intelligence enrichment."""
    mitre = MITRE_MAP.get(event_type, {})
    
    # Advanced Intelligence Enrichment
    confidence = 80 # default
    if event_type in ["RANSOMWARE", "AUTH_COMPROMISE"]:
        confidence = 95 # Multi-signal correlation has higher confidence
        
    score = calculate_risk_score(severity, event_type, src_ip)
    
    # Update global risk
    update_network_risk(score)
    
    enrichment = {
        "risk_score": score,
        "confidence": confidence,
        "asset_criticality": "HIGH" if src_ip.startswith("192.") else "MEDIUM"
    }
    
    # Check threat intel
    intel = {}
    if src_ip:
        intel = check_ip_reputation(src_ip)
        if intel.get("is_malicious"):
            details["threat_intel"] = {
                "tags": intel.get("tags", []),
                "region": intel.get("region", "Unknown"),
                "confidence": intel.get("confidence", 0)
            }
            if severity == "MEDIUM": severity = "HIGH"
            confidence += 5

    event_id = log_event(
        event_type, message, {**details, "enrichment": enrichment}, severity,
        mitre_id=mitre.get("id", ""),
        mitre_tactic=mitre.get("tactic", ""),
        src_ip=src_ip, dst_ip=dst_ip,
        protocol=protocol, port=port
    )

    stats["total_alerts"] += 1
    stats["by_type"][event_type] += 1
    stats["by_severity"][severity] += 1

    if src_ip and event_id:
        correlate_event(src_ip, event_type, event_id, severity)

    return True, message


# -------------------------
# RULE 1: Packet Rate (DoS/DDoS)
# -------------------------
def analyze_packet_rate(src_ip, dst_ip):
    now = time.time()
    ip_activity[src_ip].append(now)
    count = len(ip_activity[src_ip])

    if count >= THRESHOLD and src_ip not in alerted_ips:
        alerted_ips.add(src_ip)
        severity = "CRITICAL" if count >= THRESHOLD * 3 else "HIGH"
        msg = f"High packet rate from {src_ip} → {dst_ip} ({count} pkts/{TIME_WINDOW}s)"
        return _record_alert("RATE_LIMIT", msg,
                             {"src_ip": src_ip, "dst_ip": dst_ip, "count": count},
                             severity, src_ip, dst_ip, protocol="IP", port="")
    return False, ""


# -------------------------
# RULE 2: Port Scan Detection
# -------------------------
def analyze_port_scan(src_ip, dst_port):
    if not dst_port:
        return False, ""

    port_scan_tracker[src_ip].add(dst_port)
    unique_ports = len(port_scan_tracker[src_ip])

    if unique_ports >= SCAN_THRESHOLD:
        alert_key = f"{src_ip}_SCAN"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            # Clear tracker after alerting to avoid spam and simulate a window reset
            port_scan_tracker[src_ip].clear()
            severity = "HIGH" if unique_ports >= SCAN_THRESHOLD * 2 else "MEDIUM"
            msg = f"Port Scan detected from {src_ip} ({unique_ports} unique ports probed)"
            return _record_alert("PORT_SCAN", msg,
                                 {"src_ip": src_ip, "ports_scanned": unique_ports},
                                 severity, src_ip, port=dst_port)
    return False, ""


# -------------------------
# RULE 3: SYN Flood Detection
# -------------------------
def analyze_syn_flood(src_ip, flags):
    if not flags:
        return False, ""

    # Check for SYN-only flag (0x0002)
    try:
        flag_val = int(flags, 0)
        is_syn_only = (flag_val & 0x12) == 0x02  # SYN set, ACK not set
    except (ValueError, TypeError):
        is_syn_only = "0x0002" in str(flags) or "S" in str(flags)

    if not is_syn_only:
        return False, ""

    now = time.time()
    syn_tracker[src_ip].append(now)
    count = len(syn_tracker[src_ip])

    if count >= SYN_THRESHOLD:
        alert_key = f"{src_ip}_SYN"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            severity = "CRITICAL"
            msg = f"SYN Flood detected from {src_ip} ({count} SYN packets/{SYN_FLOOD_WINDOW}s)"
            return _record_alert("SYN_FLOOD", msg,
                                 {"src_ip": src_ip, "syn_count": count},
                                 severity, src_ip, protocol="TCP")
    return False, ""


# -------------------------
# RULE 4: DNS Tunneling Detection
# -------------------------
def analyze_dns_tunnel(src_ip, dst_port, length):
    if dst_port != "53":
        return False, ""

    now = time.time()
    dns_tracker[src_ip].append((now, length))

    recent = dns_tracker[src_ip]
    if len(recent) >= DNS_TUNNEL_RATE:
        avg_size = sum(s for _, s in recent) / len(recent)
        if avg_size >= DNS_TUNNEL_SIZE:
            alert_key = f"{src_ip}_DNS"
            if alert_key not in alerted_ips:
                alerted_ips.add(alert_key)
                msg = f"Possible DNS Tunneling from {src_ip} (avg payload {avg_size:.0f}B, {len(recent)} queries)"
                return _record_alert("DNS_TUNNEL", msg,
                                     {"src_ip": src_ip, "avg_size": avg_size,
                                      "query_count": len(recent)},
                                     "HIGH", src_ip, protocol="UDP", port="53")
    return False, ""


# -------------------------
# RULE 5: Brute Force Detection
# -------------------------
def analyze_brute_force(src_ip, dst_port):
    if dst_port not in AUTH_PORTS:
        return False, ""

    now = time.time()
    brute_force_tracker[src_ip].append(now)
    count = len(brute_force_tracker[src_ip])

    if count >= BRUTE_FORCE_THRESHOLD:
        alert_key = f"{src_ip}_BRUTE"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            msg = f"Brute Force attempt from {src_ip} ({count} connections to port {dst_port})"
            return _record_alert("BRUTE_FORCE", msg,
                                 {"src_ip": src_ip, "target_port": dst_port,
                                  "attempt_count": count},
                                 "HIGH", src_ip, port=dst_port)
    return False, ""


# -------------------------
# RULE 6: Data Exfiltration Detection
# -------------------------
def analyze_data_exfil(src_ip, length):
    now = time.time()
    outbound_tracker[src_ip].append((now, length))

    total = sum(b for _, b in outbound_tracker[src_ip])
    if total >= EXFIL_SIZE_THRESHOLD:
        alert_key = f"{src_ip}_EXFIL"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            msg = f"Possible Data Exfiltration from {src_ip} ({total / 1_000_000:.1f}MB sent in {EXFIL_WINDOW}s)"
            return _record_alert("DATA_EXFIL", msg,
                                 {"src_ip": src_ip, "bytes_sent": total},
                                 "CRITICAL", src_ip)
    return False, ""


# -------------------------
# RULE 7: Beaconing Detection
# -------------------------
def analyze_beaconing(src_ip, dst_ip):
    now = time.time()
    key = f"{src_ip}->{dst_ip}"
    beacon_tracker[key].append(now)

    timestamps = beacon_tracker[key]
    if len(timestamps) < BEACON_MIN_COUNT:
        return False, ""

    # Keep only last 20 timestamps
    if len(timestamps) > 20:
        beacon_tracker[key] = timestamps[-20:]
        timestamps = beacon_tracker[key]

    # Calculate intervals between consecutive callbacks
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    if not intervals or len(intervals) < BEACON_MIN_COUNT - 1:
        return False, ""

    try:
        avg_interval = statistics.mean(intervals)
        if avg_interval < 1:  # too fast, likely normal traffic
            return False, ""

        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter = stdev / avg_interval if avg_interval > 0 else 1

        if jitter <= BEACON_TOLERANCE and avg_interval >= BEACON_INTERVAL_MIN:  # Regular interval
            alert_key = f"{key}_BEACON"
            if alert_key not in alerted_ips:
                alerted_ips.add(alert_key)
                msg = f"Beaconing detected: {src_ip} → {dst_ip} (interval ~{avg_interval:.1f}s, jitter {jitter:.2%})"
                return _record_alert("BEACONING", msg,
                                     {"src_ip": src_ip, "dst_ip": dst_ip,
                                      "avg_interval": round(avg_interval, 1),
                                      "jitter": round(jitter, 3)},
                                     "MEDIUM", src_ip, dst_ip)
    except (statistics.StatisticsError, ZeroDivisionError):
        pass

    return False, ""


# -------------------------
# RULE 8: Ransomware Behavioral Detection
# -------------------------
def analyze_ransomware_behavior(signal_type, data):
    """
    Correlates high-frequency file mods + outbound spikes + suspicious procs.
    """
    if signal_type == "FILE_MOD":
        ransomware_monitor.record_file_mod(data)
    elif signal_type == "OUTBOUND":
        ransomware_monitor.record_outbound(data)
    elif signal_type == "PROCESS":
        ransomware_monitor.record_process(data)

    # Correlation check
    file_count = ransomware_monitor.file_mods.get_count("system")
    outbound_count = ransomware_monitor.outbound_conns.get_count("system")
    proc_count = ransomware_monitor.processes.get_count("system")

    # Multi-signal evaluation
    signals = []
    if file_count >= RANSOMWARE_FILE_MODS: signals.append(f"High file mods ({file_count}/{RANSOMWARE_WINDOW}s)")
    if outbound_count >= 20: signals.append(f"Network spike ({outbound_count} unique IPs)")
    if proc_count >= 5: signals.append(f"Suspicious proc activity ({proc_count} newly spawned)")

    if len(signals) >= 2:
        alert_key = "RANSOMWARE_BEHAVIORAL"
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            msg = f"RANSOMWARE BEHAVIOR DETECTED: {', '.join(signals)}"
            return _record_alert("RANSOMWARE", msg, 
                                 {"file_mod_count": file_count, 
                                  "outbound_count": outbound_count,
                                  "signals": signals}, 
                                 "CRITICAL")
    return False, ""


# -------------------------
# RULE 9: Brute Force + Compromise Correlation
# -------------------------
def analyze_auth_correlation(ip, status):
    """
    Tracks failed -> success sequences to detect account compromise.
    """
    if status == "failure":
        auth_monitor.record_failure(ip)
        count = auth_monitor.failures.get_count(ip)
        
        if count >= BRUTE_FORCE_THRESHOLD:
            msg = f"Brute Force Pattern: {count} failed logins from {ip}"
            # Log as standard brute force first
            return _record_alert("BRUTE_FORCE", msg, {"ip": ip, "failures": count}, "HIGH", src_ip=ip)
            
    elif status == "success":
        # Check if this success followed a brute force pattern
        fail_count = auth_monitor.failures.get_count(ip)
        if fail_count >= BRUTE_FORCE_THRESHOLD:
            msg = f"CRITICAL: Account Compromised! Successful login after brute force from {ip}"
            # Reset counters
            auth_monitor.reset(ip)
            return _record_alert("AUTH_COMPROMISE", msg, 
                                 {"ip": ip, "previous_failures": fail_count}, 
                                 "CRITICAL", src_ip=ip)
        else:
            # Normal cleanup
            auth_monitor.reset(ip)
            
    return False, ""


# -------------------------
# MAIN ANALYSIS ENTRY POINT
# -------------------------
def analyze_packet_header(packet):
    """Analyze a packet through all detection rules."""
    stats["total_packets"] += 1
    stats["last_packet_time"] = time.time()
    _pps_timestamps.append(time.time())

    proto = packet.get("protocol", "OTHER")
    stats["by_protocol"][proto] += 1

    try:
        dst_ip = packet.get("dst_ip", "Unknown")
        src_ip = packet.get("src_ip", "Unknown")
        dst_port = packet.get("dst_port", "")
        src_port = packet.get("src_port", "")
        length = packet.get("length", 0)
        flags = packet.get("flags", "")

        if not src_ip or not dst_ip:
            return True, "Missing IP addresses"

        # Run all detection rules
        # Rule 1: Suspicious Ports
        if dst_port in BLOCKED_PORTS:
            severity = "HIGH"
            msg = f"Traffic to blocked port {dst_port} from {src_ip}"
            result = _record_alert("BLOCKED_PORT", msg, packet, severity, src_ip, dst_ip, protocol=proto, port=dst_port)
            # Don't return — run other rules too

        # Rule 2: Port Scan Check
        is_scan, scan_msg = analyze_port_scan(src_ip, dst_port)

        # Rule 3: SYN Flood Check (TCP only)
        if proto == "TCP":
            analyze_syn_flood(src_ip, flags)

        # Rule 4: DNS Tunneling (UDP port 53)
        if proto == "UDP":
            analyze_dns_tunnel(src_ip, dst_port, length)

        # Rule 5: Brute Force
        analyze_brute_force(src_ip, dst_port)

        # Rule 6: Data Exfiltration
        analyze_data_exfil(src_ip, length)

        # Rule 7: Beaconing Detection
        analyze_beaconing(src_ip, dst_ip)

        # Rule 8: Ransomware Outbound Spike check
        # We consider a spike if connecting to external IPs
        if not dst_ip.startswith(("192.168.", "10.", "127.", "0.")):
             analyze_ransomware_behavior("OUTBOUND", dst_ip)

        # Rule 9: Rate Check (always last)
        is_rate, rate_msg = analyze_packet_rate(src_ip, dst_ip)

        # Return the first threat found
        if dst_port in BLOCKED_PORTS:
            return True, f"Traffic to blocked port {dst_port}"
        if is_scan:
            return True, scan_msg
        if is_rate:
            return True, rate_msg

        return False, "OK"

    except Exception as e:
        log_event("ERROR", f"Analysis error: {e}", severity="LOW")
        return True, f"Error: {e}"

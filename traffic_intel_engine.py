import time
import math
from collections import deque, defaultdict
import threading

class TrafficIntelligenceEngine:
    """Real-time Traffic Analytics & Behavioral Engine."""
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.packets = deque()
        self.lock = threading.Lock()
        self.protocol_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "src_ips": set(),
            "dst_ips": set(),
            "last_pps": 0,
            "last_bps": 0,
            "entropy": 0.0,
            "threat_level": "NORMAL",
            "type": "External"
        })
        self.malicious_ips = {"1.1.1.1", "8.8.8.8"} # Mock threat list
        self.alerts = []

    def process_packet(self, pkt):
        """Feed a packet into the real-time engine."""
        now = time.time()
        with self.lock:
            # Store metadata
            meta = {
                "ts": now,
                "src": pkt.get("src_ip"),
                "dst": pkt.get("dst_ip"),
                "proto": pkt.get("protocol", "OTHER"),
                "len": pkt.get("length", 0),
                "port": pkt.get("dst_port")
            }
            self.packets.append(meta)
            self._prune(now)

    def _prune(self, now):
        """Remove packets outside the rolling window."""
        while self.packets and now - self.packets[0]["ts"] > self.window:
            self.packets.popleft()

    def _calculate_entropy(self, dst_ips):
        """Calculate Shannon Entropy for destination IP distribution."""
        if not dst_ips: return 0.0
        counts = defaultdict(int)
        for ip in dst_ips:
            counts[ip] += 1
        
        total = len(dst_ips)
        entropy = 0.0
        for ip in counts:
            p = counts[ip] / total
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def get_aggregated_metrics(self):
        """Return the current 60s aggregation for all active protocols."""
        now = time.time()
        aggr = defaultdict(lambda: {
            "packet_count": 0, "byte_count": 0, 
            "src_ips": set(), "dst_ips": set(),
            "ports": set(), "threat_level": "NORMAL"
        })

        with self.lock:
            for p in self.packets:
                proto = p["proto"]
                aggr[proto]["packet_count"] += 1
                aggr[proto]["byte_count"] += p["len"]
                aggr[proto]["src_ips"].add(p["src"])
                aggr[proto]["dst_ips"].add(p["dst"])
                if p["port"]: aggr[proto]["ports"].add(p["port"])

        # Finalize stats
        results = []
        for proto, data in aggr.items():
            duration = self.window if len(self.packets) > 1 else 1
            pps = round(data["packet_count"] / duration, 1)
            bps = round(data["byte_count"] / duration, 1)
            entropy = self._calculate_entropy(list(data["dst_ips"]))
            
            # Classification
            is_internal = all(self._is_internal(ip) for ip in data["src_ips"])
            traffic_type = "Internal" if is_internal else "External"
            
            # Threat Level Logic
            threat_level = "NORMAL"
            if entropy > 4.5 or len(data["ports"]) > 20:
                threat_level = "ANOMALY"
            if any(ip in self.malicious_ips for ip in data["src_ips"]):
                threat_level = "THREAT"
            
            if pps > 500: # DDoS indicator
                threat_level = "THREAT"

            # Custom Variance Calculation (Unique Dst / Total Packets)
            variance = round((len(data["dst_ips"]) / data["packet_count"] * 100), 1) if data["packet_count"] > 0 else 0

            results.append({
                "protocol": proto,
                "packet_count": data["packet_count"],
                "avg_size": round(data["byte_count"] / data["packet_count"], 1) if data["packet_count"] > 0 else 0,
                "pps": pps,
                "bps": bps,
                "unique_src": len(data["src_ips"]),
                "unique_dst": len(data["dst_ips"]),
                "entropy": entropy,
                "traffic_type": traffic_type,
                "threat_level": threat_level,
                "variance": variance
            })
        
        return sorted(results, key=lambda x: x["packet_count"], reverse=True)

    def _is_internal(self, ip):
        if not ip: return False
        return ip.startswith(("127.", "192.168.", "10.", "172."))

# Global instance
engine = TrafficIntelligenceEngine(window_seconds=60)

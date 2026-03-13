import time
from collections import defaultdict
from config import THRESHOLD, TIME_WINDOW
from alert_email import send_email

# -------------------------
# RULE 1: Packet rate tracking
# -------------------------
ip_activity = defaultdict(list)
alerted_ips = set()

# -------------------------
# RULE 1 FUNCTION
# -------------------------
def analyze_packet_rate(dst_ip):
    now = time.time()

    ip_activity[dst_ip].append(now)

    # keep only recent packets
    ip_activity[dst_ip] = [
        t for t in ip_activity[dst_ip] if now - t <= TIME_WINDOW
    ]

    count = len(ip_activity[dst_ip])

    if count >= THRESHOLD and dst_ip not in alerted_ips:
        alerted_ips.add(dst_ip)
        send_email(dst_ip, count, TIME_WINDOW)
        return True, f"High packet rate to {dst_ip}"

    return False, "Normal traffic"


# -------------------------
# RULE 2: Header validation
# -------------------------
def analyze_packet_header(packet):
    try:
        # 1. Source IP
        if not packet.get("src_ip"):
            return True, "Missing Source IP"

        # 2. Destination IP
        if not packet.get("dst_ip"):
            return True, "Missing Destination IP"

        # 3. Protocol
        protocol = packet.get("protocol")
        if protocol not in ["TCP", "UDP", "ICMP"]:
            return True, f"Invalid protocol: {protocol}"

        # 4. Port numbers
        if protocol in ["TCP", "UDP"]:
            if not packet.get("src_port") or not packet.get("dst_port"):
                return True, "Missing port numbers"

        # 5. Packet length
        if not packet.get("length") or packet.get("length") <= 0:
            return True, "Invalid packet length"

        # 6. TCP flags
        if protocol == "TCP" and not packet.get("flags"):
            return True, "Missing TCP flags"

        return False, "Header valid"

    except Exception as e:
        return True, f"Header analysis error: {e}"

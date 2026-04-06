import sys
from packet_capture import start_capture
from detector import analyze_packet_header, cleanup_old_data
from logger import log_event, log_packet
from database import init_db

# Initialize database
init_db()

print("[+] SOC Endpoint Monitor (SIEM Mode) Started")
print("[+] Press Ctrl + C to stop\n")

proc = start_capture()

try:
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        fields = line.split("|")
        if len(fields) < 12:
            fields += [""] * (12 - len(fields))

        src = fields[0]
        dst = fields[1]
        proto = fields[2]

        if proto == "6":
             src_port, dst_port, proto_name = fields[3], fields[4], "TCP"
        elif proto == "17":
             src_port, dst_port, proto_name = fields[5], fields[6], "UDP"
        else:
             src_port, dst_port, proto_name = "", "", f"PROTO-{proto}"

        length = fields[7]
        flags = fields[8]
        dns_query = fields[9]
        http_host = fields[10]
        tls_sni = fields[11]

        cleanup_old_data()

        packet_data = {
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": int(length) if length.isdigit() else 0,
            "flags": flags,
            "dns_query": dns_query,
            "http_host": http_host,
            "tls_sni": tls_sni,
        }

        is_threat, threat_msg = analyze_packet_header(packet_data)
        packet_data["is_threat"] = is_threat
        packet_data["threat_msg"] = threat_msg if is_threat else ""
        log_packet(packet_data)

except KeyboardInterrupt:
    print("\n[+] Monitoring stopped by user")

finally:
    print("[+] Stopping tshark process...")
    # Flush packet buffer
    from database import packet_buffer
    packet_buffer.stop()
    
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except:
            proc.kill()
    print("[+] Capture closed safely and buffer flushed")
    sys.exit(0)

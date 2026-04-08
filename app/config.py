import os

# -------------------------
# Detection Thresholds
# -------------------------
THRESHOLD = int(os.getenv("DOS_THRESHOLD", 500))
TIME_WINDOW = int(os.getenv("DOS_WINDOW", 10))

SCAN_THRESHOLD = int(os.getenv("SCAN_THRESHOLD", 15))
SCAN_WINDOW = int(os.getenv("SCAN_WINDOW", 60))

SYN_THRESHOLD = int(os.getenv("SYN_THRESHOLD", 60))
SYN_FLOOD_WINDOW = int(os.getenv("SYN_FLOOD_WINDOW", 1))

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
BRUTE_FORCE_WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW", 180))

DNS_TUNNEL_SIZE = int(os.getenv("DNS_TUNNEL_SIZE", 60))
DNS_TUNNEL_RATE = int(os.getenv("DNS_TUNNEL_RATE", 15))
DNS_TUNNEL_WINDOW = int(os.getenv("DNS_TUNNEL_WINDOW", 60))

EXFIL_SIZE_THRESHOLD = int(os.getenv("EXFIL_SIZE_THRESHOLD", 50_000_000))
EXFIL_WINDOW = int(os.getenv("EXFIL_WINDOW", 300))

BEACON_TOLERANCE = float(os.getenv("BEACON_TOLERANCE", 0.05))
BEACON_MIN_COUNT = int(os.getenv("BEACON_MIN_COUNT", 8))
BEACON_INTERVAL_MIN = int(os.getenv("BEACON_INTERVAL_MIN", 5))
BEACON_WINDOW = int(os.getenv("BEACON_WINDOW", 3600))

RANSOMWARE_FILE_MODS = int(os.getenv("RANSOMWARE_FILE_MODS", 40))
RANSOMWARE_WINDOW = int(os.getenv("RANSOMWARE_WINDOW", 10))

# -------------------------
# MITRE ATT&CK Mapping
# -------------------------
MITRE_MAP = {
    "RATE_LIMIT":     {"id": "T1498",     "tactic": "Impact",              "name": "Network Denial of Service"},
    "PORT_SCAN":      {"id": "T1046",     "tactic": "Discovery",           "name": "Network Service Scanning"},
    "BLOCKED_PORT":   {"id": "T1571",     "tactic": "Command and Control", "name": "Non-Standard Port"},
    "SYN_FLOOD":      {"id": "T1499.001", "tactic": "Impact",              "name": "SYN Flood"},
    "DNS_TUNNEL":     {"id": "T1071.004", "tactic": "Command and Control", "name": "DNS Tunneling"},
    "BRUTE_FORCE":    {"id": "T1110",     "tactic": "Credential Access",   "name": "Brute Force"},
    "DATA_EXFIL":     {"id": "T1048",     "tactic": "Exfiltration",        "name": "Exfiltration Over Alternative Protocol"},
    "BEACONING":      {"id": "T1071.001", "tactic": "Command and Control", "name": "Application Layer Protocol"},
    "RANSOMWARE":     {"id": "T1486",     "tactic": "Impact",              "name": "Data Encrypted for Impact"},
    "AUTH_COMPROMISE":{"id": "T1110",     "tactic": "Credential Access",   "name": "Brute Force -> Successful Logon"},
}

BLOCKED_PORTS = os.getenv("BLOCKED_PORTS", "23,445,3389,135,139").split(",")
AUTH_PORTS = os.getenv("AUTH_PORTS", "22,23,3389,21,5900").split(",")

# -------------------------
# Email config (Injected via ENV for security)
# -------------------------
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
EMAIL_RATE_LIMIT = int(os.getenv("EMAIL_RATE_LIMIT", 300))

# -------------------------
# Database
# -------------------------
# Use a path relative to the current file or absolute from ENV
DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "siem.db"))
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", 30))

# -------------------------
# Server config
# -------------------------
# Render provides PORT env variable
SERVER_HOST = "0.0.0.0"
SERVER_PORT = int(os.getenv("PORT", 8000))

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "localhost"

# For Render, BASE_URL should be the public URL if possible, otherwise generic
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", f"http://{get_local_ip()}:{SERVER_PORT}")

# -------------------------
# SSL / HTTPS config
# -------------------------
USE_HTTPS = os.getenv("USE_HTTPS", "False").lower() == "true"
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", os.path.join(os.path.dirname(os.path.dirname(__file__)), "cert.pem"))
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", os.path.join(os.path.dirname(os.path.dirname(__file__)), "key.pem"))
REDIRECT_HTTP_TO_HTTPS = os.getenv("REDIRECT_HTTP", "False").lower() == "true"

# -------------------------
# MongoDB Atlas
# -------------------------
# Support both names, prefer MONGO_URI if both exist
MONGODB_URI = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "siemdb")
MONGODB_COLLECTION = os.getenv("MONGODB_COLLECTION", "security_logs")

# -------------------------
# Platform / Capture
# -------------------------
TSHARK_PATH = os.getenv("TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
INTERFACE = os.getenv("INTERFACE", "Wi-Fi")

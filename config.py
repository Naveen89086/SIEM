import os

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "Wi-Fi"

# -------------------------
# Detection Thresholds (Real-time Single Laptop)
# -------------------------
THRESHOLD = 500            # packets per window for rate-limit (DoS)
TIME_WINDOW = 10           # seconds for rate-limit

SCAN_THRESHOLD = 15        # distinct ports for port-scan
SCAN_WINDOW = 60           # seconds for port-scan

SYN_THRESHOLD = 60         # bare SYN packets per window for SYN flood
SYN_FLOOD_WINDOW = 1       # seconds for SYN flood

BRUTE_FORCE_THRESHOLD = 5  # failed logins / connections to auth ports per window
BRUTE_FORCE_WINDOW = 180   # seconds (3 minutes)

DNS_TUNNEL_SIZE = 60       # average suspicious DNS payload length
DNS_TUNNEL_RATE = 15       # DNS queries per window to same domain
DNS_TUNNEL_WINDOW = 60     # seconds (1 minute)

EXFIL_SIZE_THRESHOLD = 50_000_000  # 50MB outbound in window
EXFIL_WINDOW = 300         # seconds (5 minutes)

BEACON_TOLERANCE = 0.05    # jitter tolerance for beaconing (5%)
BEACON_MIN_COUNT = 8       # minimum callbacks to detect beaconing
BEACON_INTERVAL_MIN = 5    # minimum seconds between beacons
BEACON_WINDOW = 3600       # seconds (60 minutes)

RANSOMWARE_FILE_MODS = 40
RANSOMWARE_WINDOW = 10

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

# Suspicious / blocked ports
BLOCKED_PORTS = ["23", "445", "3389", "135", "139"]
AUTH_PORTS = ["22", "23", "3389", "21", "5900"]  # SSH, Telnet, RDP, FTP, VNC

# -------------------------
# Email config
# -------------------------
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
EMAIL_RATE_LIMIT = 300   # max 1 email per alert type per 5 minutes

# -------------------------
# Database
# -------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "siem.db")
LOG_RETENTION_DAYS = 30

# -------------------------
# Server config
# -------------------------
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

def get_local_ip():
    import socket
    try:
        # Create a dummy socket to find the primary interface IP
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

BASE_URL = f"http://{get_local_ip()}:{SERVER_PORT}"

# -------------------------
# SSL / HTTPS config
# -------------------------
USE_HTTPS = False
SSL_CERT_FILE = os.path.join(os.path.dirname(__file__), "cert.pem")
SSL_KEY_FILE = os.path.join(os.path.dirname(__file__), "key.pem")
REDIRECT_HTTP_TO_HTTPS = False
HTTP_PORT = 80  # Optional: Standard HTTP port for redirection

# -------------------------
# MongoDB Atlas
# -------------------------
# Support both names, prefer MONGO_URI
MONGODB_URI = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "siemdb")
MONGODB_COLLECTION = os.getenv("MONGODB_COLLECTION", "security_logs")

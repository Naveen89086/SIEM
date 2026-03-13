import os

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "Wi-Fi"

# -------------------------
# Detection Thresholds
# -------------------------
THRESHOLD = 20           # packets per window for rate-limit
TIME_WINDOW = 60         # seconds
SCAN_THRESHOLD = 5       # distinct ports for port-scan
SYN_THRESHOLD = 50       # SYN packets per window for SYN flood
SYN_FLOOD_WINDOW = 30    # seconds
BRUTE_FORCE_THRESHOLD = 10  # connections to auth ports per window
BRUTE_FORCE_WINDOW = 60
DNS_TUNNEL_SIZE = 200    # suspicious DNS payload bytes
DNS_TUNNEL_RATE = 15     # DNS queries per window
EXFIL_SIZE_THRESHOLD = 5_000_000  # 5MB outbound in window
EXFIL_WINDOW = 120       # seconds
BEACON_TOLERANCE = 0.15  # jitter tolerance for beaconing (15%)
BEACON_MIN_COUNT = 5     # minimum callbacks to detect beaconing

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
EMAIL_FROM = "naveenkumar062005@gmail.com"
EMAIL_TO = "naveenkumar062005@gmail.com"
EMAIL_PASSWORD = "apmkoglpfoeydgle"
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

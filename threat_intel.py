"""
Threat Intelligence Module — Local IP reputation and enrichment.
Provides offline threat context without needing external API keys.
"""
import time
from collections import defaultdict

# -------------------------
# Known-bad IP ranges (simulated threat feed)
# In production, this would be loaded from external feeds
# -------------------------
KNOWN_BAD_RANGES = [
    # Common scanner/attacker ranges (for demonstration)
    "185.220.101.",  # Tor exit nodes
    "185.220.102.",
    "45.148.10.",    # Known scanners
    "193.142.146.",
    "89.248.167.",   # Recyber scanners
    "92.118.36.",
    "141.98.10.",    # BinaryEdge
    "162.142.125.",  # Censys scanners
    "167.94.138.",
    "71.6.135.",     # Shodan
    "71.6.146.",
    "71.6.167.",
    "80.82.77.",     # Shadowserver
    "198.235.24.",
]

# Suspicious countries (simplified GeoIP by common ranges)
SUSPICIOUS_RANGES = {
    "185.": "Eastern Europe",
    "141.98.": "Netherlands (Scanner)",
    "45.148.": "Russia",
    "89.248.": "Netherlands (Scanner)",
    "193.142.": "Sweden (Scanner)",
}

# Common Tor exit node indicators
TOR_EXIT_PREFIXES = ["185.220.101.", "185.220.102.", "178.17."]

# -------------------------
# IP Reputation Cache
# -------------------------
_reputation_cache = {}
_ip_first_seen = {}
_ip_hit_count = defaultdict(int)


def check_ip_reputation(ip: str) -> dict:
    """
    Check if an IP is in known-bad lists and return enrichment data.
    Returns dict with: is_malicious, threat_type, confidence, region, tags
    """
    if ip in _reputation_cache:
        cached = _reputation_cache[ip]
        if time.time() - cached["checked_at"] < 600:  # 10 min cache
            return cached

    result = {
        "ip": ip,
        "is_malicious": False,
        "threat_type": "none",
        "confidence": 0.0,
        "region": "Unknown",
        "tags": [],
        "first_seen": _ip_first_seen.get(ip, time.time()),
        "hit_count": _ip_hit_count[ip],
        "checked_at": time.time(),
    }

    # Track first-seen
    if ip not in _ip_first_seen:
        _ip_first_seen[ip] = time.time()
    _ip_hit_count[ip] += 1
    result["hit_count"] = _ip_hit_count[ip]

    # Check known-bad ranges
    for prefix in KNOWN_BAD_RANGES:
        if ip.startswith(prefix):
            result["is_malicious"] = True
            result["threat_type"] = "known_scanner"
            result["confidence"] = 0.9
            result["tags"].append("known-bad")
            break

    # Check Tor exit nodes
    for prefix in TOR_EXIT_PREFIXES:
        if ip.startswith(prefix):
            result["tags"].append("tor-exit")
            result["threat_type"] = "tor_exit_node"
            result["confidence"] = max(result["confidence"], 0.85)
            result["is_malicious"] = True

    # GeoIP approximation
    for prefix, region in SUSPICIOUS_RANGES.items():
        if ip.startswith(prefix):
            result["region"] = region
            if not result["is_malicious"]:
                result["tags"].append("suspicious-geo")
                result["confidence"] = max(result["confidence"], 0.4)

    # Private/internal IPs
    if (ip.startswith("192.168.") or ip.startswith("10.") or
            ip.startswith("172.16.") or ip.startswith("172.17.") or
            ip.startswith("127.")):
        result["region"] = "Internal"
        result["tags"].append("internal")
        result["is_malicious"] = False
        result["confidence"] = 0.0

    _reputation_cache[ip] = result
    return result


def get_ip_summary(ip: str) -> dict:
    """Get a summary of everything we know about an IP."""
    rep = check_ip_reputation(ip)
    return {
        "ip": ip,
        "reputation": rep,
        "first_seen": _ip_first_seen.get(ip),
        "total_packets": _ip_hit_count.get(ip, 0),
    }


def get_all_known_threats() -> list:
    """Return all IPs currently flagged as malicious."""
    return [
        v for v in _reputation_cache.values()
        if v.get("is_malicious")
    ]


def clear_cache():
    """Clear the reputation cache."""
    _reputation_cache.clear()

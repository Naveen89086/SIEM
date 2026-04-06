import subprocess
from config import TSHARK_PATH, INTERFACE


def start_capture():
    """Start tshark with enhanced field extraction for SIEM analysis."""
    cmd = [
        TSHARK_PATH,
        "-i", INTERFACE,
        "-T", "fields",

        # Basic fields (indices 0-2)
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",

        # TCP ports (indices 3, 4)
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",

        # UDP ports (indices 5, 6)
        "-e", "udp.srcport",
        "-e", "udp.dstport",

        # Packet length (index 7)
        "-e", "frame.len",

        # TCP flags (index 8)
        "-e", "tcp.flags",

        # Enhanced fields for deeper analysis
        # DNS (indices 9, 10)
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",

        # HTTP (indices 11, 12)
        "-e", "http.host",
        "-e", "http.request.method",

        # TLS SNI / Server Name (index 13)
        "-e", "tls.handshake.extensions_server_name",

        # ICMP (index 14)
        "-e", "icmp.type",

        "-E", "separator=|",
        "-l"
    ]

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

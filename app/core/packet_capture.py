import subprocess
from app.config import TSHARK_PATH, INTERFACE

def start_capture():
    """Start tshark with enhanced field extraction for SIEM analysis."""
    cmd = [
        TSHARK_PATH,
        "-i", INTERFACE,
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len", "-e", "tcp.flags",
        "-e", "dns.qry.name", "-e", "dns.qry.type",
        "-e", "http.host", "-e", "http.request.method",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "icmp.type",
        "-E", "separator=|", "-l"
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

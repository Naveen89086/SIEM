import socket
import time
import random

def simulate_port_scan(target_ip='127.0.0.1', start_port=1000, end_port=1050):
    print(f"[+] Simulating Port Scan on {target_ip}...")
    for port in range(start_port, end_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            sock.connect((target_ip, port))
            sock.close()
        except:
            pass
        if port % 10 == 0:
            time.sleep(0.1)

def simulate_syn_flood(target_ip='127.0.0.1', count=100):
    print(f"[+] Simulating SYN Activity (Rate Limit) on {target_ip}...")
    for _ in range(count):
        try:
            # We just open/close connections rapidly to trigger rate limit
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.01)
            sock.connect((target_ip, 8000))
            sock.close()
        except:
            pass

if __name__ == "__main__":
    time.sleep(2) # Wait for server to be ready
    while True:
        choice = random.choice(['scan', 'rate'])
        if choice == 'scan':
            simulate_port_scan()
        else:
            simulate_syn_flood()
        
        print("[*] Activity paused. Waiting for risk decay...")
        time.sleep(15) # Wait for some decay before hitting it again

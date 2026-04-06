import socket
import ssl
import certifi
import requests

def debug_connection():
    print("--- SSL/Network Debugging ---")
    
    # 1. Check Internet and Public IP
    try:
        ip = requests.get('https://api.ipify.org').text
        print(f"✅ Current Public IP: {ip}")
        print("   NOTE: Ensure this IP (or 0.0.0.0/0) is in your Atlas IP Access List.")
    except Exception as e:
        print(f"❌ Could not determine public IP: {e}")

    # 2. Check Port 27017 (MongoDB) connectivity
    # Using a direct shard hostname because the cluster root doesn't have an A record
    host = "ac-73s0hqg-shard-00-00.ancn7wb.mongodb.net"
    port = 27017
    print(f"\nChecking connectivity to {host}:{port}...")
    try:
        s = socket.create_connection((host, port), timeout=5)
        print(f"✅ Port {port} is reachable.")
        s.close()
    except Exception as e:
        print(f"❌ Port {port} is NOT reachable: {e}")

    # 3. Check SSL Handshake
    print("\nAttempting SSL handshake...")
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"✅ SSL Handshake successful! Protocol: {ssock.version()}")
    except Exception as e:
        print(f"❌ SSL Handshake failed: {e}")

if __name__ == "__main__":
    debug_connection()

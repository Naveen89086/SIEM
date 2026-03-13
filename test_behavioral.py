import time
import sys
import os

# Ensure we can import detector
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from detector import (
    analyze_ransomware_behavior, 
    analyze_auth_correlation,
    analyze_packet_header,
    get_stats
)

def test_ransomware_detection():
    print("\n[+] Testing Ransomware Correlation...")
    # Signal 1: High frequency file mods
    print("    - Simulating 105 file modifications...")
    for i in range(105):
        analyze_ransomware_behavior("FILE_MOD", f"/data/doc_{i}.enc")
    
    # Signal 2: Network spike
    print("    - Simulating outbound connection spike to 25 unique IPs...")
    for i in range(25):
        analyze_ransomware_behavior("OUTBOUND", f"192.168.1.{i}")
        
    print("    - Check if alert triggered (RANSOMWARE)...")
    stats = get_stats()
    if stats["by_type"].get("RANSOMWARE", 0) > 0:
        print("    ✅ SUCCESS: Ransomware alert detected!")
    else:
        print("    ❌ FAILURE: Ransomware alert not detected.")

def test_auth_compromise():
    print("\n[+] Testing Brute Force -> Compromise Correlation...")
    test_ip = "192.168.1.50"
    
    print(f"    - Simulating 12 failed logins from {test_ip}...")
    for i in range(12):
        analyze_auth_correlation(test_ip, "failure")
        
    print(f"    - Simulating 1 successful login from {test_ip}...")
    analyze_auth_correlation(test_ip, "success")
    
    print("    - Check if alert triggered (AUTH_COMPROMISE)...")
    stats = get_stats()
    if stats["by_type"].get("AUTH_COMPROMISE", 0) > 0:
        print("    ✅ SUCCESS: Account compromise detected!")
    else:
        print("    ❌ FAILURE: Account compromise not detected.")

if __name__ == "__main__":
    test_ransomware_detection()
    test_auth_compromise()
    print("\n[+] Testing Completed.")

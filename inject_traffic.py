#!/usr/bin/env python3
"""Inject some test traffic data directly into the running system."""

import requests
import time
import json
from collections import defaultdict

def inject_traffic_data():
    """Inject traffic data directly via the running system."""
    base_url = "http://localhost:5000"
    
    # Test if server is running
    try:
        response = requests.get(f"{base_url}/test", timeout=5)
        if response.status_code == 200:
            print("✓ Server is running")
            print(f"Current stats: {response.json()}")
        else:
            print("✗ Server not responding properly")
            return False
    except Exception as e:
        print(f"✗ Cannot connect to server: {e}")
        return False
    
    # Get system info
    try:
        response = requests.get(f"{base_url}/api/system-info", timeout=5)
        if response.status_code == 200:
            print("✓ System info available")
        else:
            print("⚠ System info not available")
    except Exception as e:
        print(f"⚠ System info error: {e}")
    
    # Get current stats
    try:
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print(f"Current active connections: {stats.get('active_connections', 0)}")
            print(f"Current blocked IPs: {stats.get('blocked_ips', 0)}")
            print(f"Total packets: {stats.get('total_packets', 0)}")
        else:
            print("⚠ Stats not available")
    except Exception as e:
        print(f"⚠ Stats error: {e}")
    
    return True

if __name__ == "__main__":
    print("Testing DDoS Detection System connectivity...")
    inject_traffic_data()

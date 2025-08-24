#!/usr/bin/env python3
"""
Simple test script to verify the DDoS detection application is working.
"""

import requests
import json
import time

def test_server():
    """Test basic server functionality."""
    base_url = "http://localhost:5000"
    
    print("Testing DDoS Detection Application...")
    print("=" * 50)
    
    # Test 1: Basic connectivity
    try:
        response = requests.get(f"{base_url}/test", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Server is running: {data['message']}")
            print(f"  Traffic data count: {data['traffic_data_count']}")
            print(f"  Blocked IPs count: {data['blocked_ips_count']}")
        else:
            print(f"✗ Server returned status {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to server: {e}")
        return False
    
    # Test 2: Check system status
    try:
        response = requests.get(f"{base_url}/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ System status retrieved: {data['status']}")
            print(f"  Network interface: {data.get('network_interface', 'Unknown')}")
            print(f"  Total packets captured: {data.get('total_packets', 0)}")
        else:
            print(f"✗ Failed to get system status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Error getting system status: {e}")
    
    # Test 3: Get stats
    try:
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Stats retrieved successfully")
            print(f"  Active connections: {data['active_connections']}")
            print(f"  Blocked IPs: {data['blocked_ips']}")
            print(f"  Total packets: {data['total_packets']}")
        else:
            print(f"✗ Failed to get stats: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Error getting stats: {e}")
    
    # Test 4: Wait and check for real traffic updates
    print("\nWaiting 10 seconds for real network traffic processing...")
    print("(Generate some network activity to see traffic data)")
    time.sleep(10)
    
    try:
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Stats after monitoring period:")
            print(f"  Active connections: {data['active_connections']}")
            print(f"  Total packets: {data['total_packets']}")
            
            if data['active_connections'] > 0:
                print("✓ Real network traffic is being captured and processed!")
            else:
                print("⚠ No network traffic detected - try browsing the web or generating network activity")
                print("  Note: Run as Administrator on Windows for packet capture to work")
        else:
            print(f"✗ Failed to get updated stats: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Error getting updated stats: {e}")
    
    print("\n" + "=" * 50)
    print("Real Network Monitoring Test completed!")
    print("\nTo view the web interface, open: http://localhost:5000")
    print("The system now monitors REAL network traffic only.")
    print("Generate network activity (browse web, download files) to see traffic data.")
    print("On Windows, run as Administrator for full packet capture capabilities.")
    
    return True

if __name__ == "__main__":
    test_server()

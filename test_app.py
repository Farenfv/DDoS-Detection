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
    
    # Test 2: Generate test traffic
    try:
        response = requests.post(f"{base_url}/api/generate-test-traffic", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Test traffic generated: {data['message']}")
            print(f"  Generated IPs: {', '.join(data['ips'])}")
        else:
            print(f"✗ Failed to generate test traffic: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Error generating test traffic: {e}")
    
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
    
    # Test 4: Wait and check for traffic updates
    print("\nWaiting 5 seconds for traffic processing...")
    time.sleep(5)
    
    try:
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Stats after processing:")
            print(f"  Active connections: {data['active_connections']}")
            print(f"  Total packets: {data['total_packets']}")
            
            if data['active_connections'] > 0:
                print("✓ Traffic is being processed!")
            else:
                print("⚠ No active connections detected")
        else:
            print(f"✗ Failed to get updated stats: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Error getting updated stats: {e}")
    
    print("\n" + "=" * 50)
    print("Test completed!")
    print("\nTo view the web interface, open: http://localhost:5000")
    print("Check the browser console for WebSocket connection status and traffic updates.")
    
    return True

if __name__ == "__main__":
    test_server()

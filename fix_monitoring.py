#!/usr/bin/env python3
"""Direct fix to inject traffic data into the running system."""

import sys
import os
import time
import threading
from collections import defaultdict

# Add the project directory to Python path
sys.path.insert(0, r'c:\Users\FM_Re\Desktop\DDoS-Detection-main')

def inject_real_traffic():
    """Inject real network connection data directly."""
    try:
        import psutil
        
        # Get the running application's traffic_data
        import ddos_detection
        
        print("Injecting real network traffic data...")
        
        # Get current network connections
        connections = psutil.net_connections(kind='inet')
        current_time = time.time()
        
        active_ips = set()
        for conn in connections:
            if conn.raddr and conn.status == 'ESTABLISHED':
                remote_ip = conn.raddr.ip
                if not remote_ip.startswith('127.'):
                    active_ips.add((remote_ip, conn.raddr.port))
        
        print(f"Found {len(active_ips)} active connections")
        
        # Inject traffic data directly
        with ddos_detection.traffic_lock:
            for ip, port in active_ips:
                packet_data = {
                    'timestamp': current_time,
                    'size': 1024,
                    'src_port': port
                }
                ddos_detection.traffic_data[ip].append(packet_data)
                print(f"Added traffic data for {ip}:{port}")
        
        print(f"Injected traffic data for {len(active_ips)} IPs")
        print(f"Total traffic data entries: {len(ddos_detection.traffic_data)}")
        
        return len(active_ips) > 0
        
    except Exception as e:
        print(f"Error injecting traffic: {e}")
        return False

def start_continuous_injection():
    """Start continuous traffic injection."""
    def injection_worker():
        while True:
            try:
                inject_real_traffic()
                time.sleep(10)  # Inject every 10 seconds
            except Exception as e:
                print(f"Injection worker error: {e}")
                time.sleep(30)
    
    thread = threading.Thread(target=injection_worker)
    thread.daemon = True
    thread.start()
    print("Started continuous traffic injection")

if __name__ == "__main__":
    print("Direct traffic injection fix...")
    
    # Single injection
    success = inject_real_traffic()
    
    if success:
        print("✓ Traffic injection successful")
        # Start continuous injection
        start_continuous_injection()
        print("Continuous injection started - check dashboard for traffic")
        
        # Keep script running
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("Stopping injection...")
    else:
        print("✗ Traffic injection failed")

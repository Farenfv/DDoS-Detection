#!/usr/bin/env python3
"""Quick test script to verify alternative monitoring works."""

import psutil
import time
from collections import defaultdict

def test_alternative_monitoring():
    """Test the alternative monitoring approach."""
    print("Testing alternative network monitoring...")
    
    traffic_data = defaultdict(list)
    
    try:
        # Get network connections
        connections = psutil.net_connections(kind='inet')
        current_time = time.time()
        
        print(f"Found {len(connections)} total network connections")
        
        # Process active connections
        active_ips = set()
        for conn in connections:
            if conn.raddr and conn.status == 'ESTABLISHED':
                remote_ip = conn.raddr.ip
                
                # Include all external IPs (not just localhost)
                if not remote_ip.startswith('127.'):
                    active_ips.add((remote_ip, conn.raddr.port))
        
        print(f"Found {len(active_ips)} active external connections:")
        
        # Create traffic data for active connections
        for ip, port in active_ips:
            print(f"  - {ip}:{port}")
            packet_data = {
                'timestamp': current_time,
                'size': 1024,
                'src_port': port
            }
            traffic_data[ip].append(packet_data)
        
        print(f"\nTraffic data created for {len(traffic_data)} IPs")
        return len(traffic_data) > 0
        
    except Exception as e:
        print(f"Error in alternative monitoring test: {e}")
        return False

if __name__ == "__main__":
    success = test_alternative_monitoring()
    if success:
        print("✓ Alternative monitoring test PASSED - should show traffic")
    else:
        print("✗ Alternative monitoring test FAILED - no traffic detected")

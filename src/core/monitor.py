"""
Network Traffic Monitor

Handles network packet capture and traffic monitoring using multiple
methods including raw packet capture and system connection monitoring.
"""

import time
import logging
import threading
import psutil
from typing import Dict, List, Optional, Set, Callable
from collections import defaultdict
from dataclasses import dataclass

from config import config


@dataclass
class PacketData:
    """Represents a network packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int
    protocol: str


class NetworkMonitor:
    """
    Professional network traffic monitoring system.
    
    Supports multiple monitoring methods:
    - Raw packet capture (requires admin privileges)
    - System connection monitoring (fallback)
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        self.logger = logging.getLogger(__name__)
        self.callback = callback
        self.is_running = False
        self.monitoring_thread = None
        self.shutdown_event = threading.Event()
        
        # Traffic data storage
        self.traffic_data: Dict[str, List[PacketData]] = defaultdict(list)
        self.traffic_lock = threading.Lock()
        
        # Monitoring state
        self.packet_capture_available = False
        self.alternative_monitoring_active = False
        
    def start(self) -> bool:
        """
        Start network monitoring.
        
        Returns:
            bool: True if monitoring started successfully
        """
        if self.is_running:
            self.logger.warning("Monitor is already running")
            return True
            
        self.logger.info("Starting network monitor...")
        
        # Try packet capture first
        if self._try_packet_capture():
            self.logger.info("Using raw packet capture")
            self.packet_capture_available = True
        else:
            self.logger.info("Falling back to connection monitoring")
            self.packet_capture_available = False
            
        # Start monitoring thread
        self.is_running = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="NetworkMonitor",
            daemon=True
        )
        self.monitoring_thread.start()
        
        return True
    
    def stop(self):
        """Stop network monitoring."""
        if not self.is_running:
            return
            
        self.logger.info("Stopping network monitor...")
        self.is_running = False
        self.shutdown_event.set()
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
            
        self.logger.info("Network monitor stopped")
    
    def _try_packet_capture(self) -> bool:
        """
        Attempt to initialize packet capture.
        
        Returns:
            bool: True if packet capture is available
        """
        try:
            # Try importing scapy
            from scapy.all import sniff, get_if_list
            
            # Test packet capture capability
            interfaces = get_if_list()
            if not interfaces:
                return False
                
            # Try a test capture
            sniff(count=1, timeout=1)
            return True
            
        except Exception as e:
            self.logger.warning(f"Packet capture not available: {e}")
            return False
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        self.logger.info("Network monitoring loop started")
        
        try:
            if self.packet_capture_available:
                self._packet_capture_loop()
            else:
                self._connection_monitoring_loop()
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
        finally:
            self.logger.info("Network monitoring loop ended")
    
    def _packet_capture_loop(self):
        """Raw packet capture monitoring loop."""
        try:
            from scapy.all import sniff, IP
            
            def packet_handler(packet):
                if self.shutdown_event.is_set():
                    return
                    
                try:
                    if IP in packet:
                        ip_layer = packet[IP]
                        
                        packet_data = PacketData(
                            timestamp=time.time(),
                            src_ip=ip_layer.src,
                            dst_ip=ip_layer.dst,
                            src_port=getattr(packet, 'sport', 0),
                            dst_port=getattr(packet, 'dport', 0),
                            size=len(packet),
                            protocol=ip_layer.proto
                        )
                        
                        self._process_packet(packet_data)
                        
                except Exception as e:
                    self.logger.debug(f"Error processing packet: {e}")
            
            # Start packet capture
            interface = config.INTERFACE or None
            sniff(
                iface=interface,
                prn=packet_handler,
                stop_filter=lambda x: self.shutdown_event.is_set(),
                store=False
            )
            
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
            # Fallback to connection monitoring
            self._connection_monitoring_loop()
    
    def _connection_monitoring_loop(self):
        """System connection monitoring loop (fallback)."""
        self.logger.info("Starting connection monitoring")
        
        while not self.shutdown_event.is_set():
            try:
                current_time = time.time()
                connections = psutil.net_connections(kind='inet')
                
                # Track active IPs
                active_ips: Set[str] = set()
                connection_counts = defaultdict(int)
                
                for conn in connections:
                    if (conn.raddr and 
                        conn.status == 'ESTABLISHED' and
                        self._is_valid_ip(conn.raddr.ip)):
                        
                        remote_ip = conn.raddr.ip
                        active_ips.add(remote_ip)
                        connection_counts[remote_ip] += 1
                
                # Update traffic data
                with self.traffic_lock:
                    # Remove old IPs
                    old_ips = set(self.traffic_data.keys()) - active_ips
                    for ip in old_ips:
                        if ip in self.traffic_data:
                            del self.traffic_data[ip]
                    
                    # Add/update current IPs
                    for ip in active_ips:
                        conn_count = connection_counts[ip]
                        
                        # Create synthetic packet data
                        packet_data = PacketData(
                            timestamp=current_time,
                            src_ip=ip,
                            dst_ip='localhost',
                            src_port=80,
                            dst_port=443,
                            size=64 + (conn_count * 5),
                            protocol='TCP'
                        )
                        
                        # Replace old data to prevent accumulation
                        self.traffic_data[ip] = [packet_data]
                
                # Notify callback if set
                if self.callback and active_ips:
                    self.callback(dict(self.traffic_data))
                
                # Log activity
                if active_ips:
                    self.logger.debug(f"Monitoring {len(active_ips)} active connections")
                
                time.sleep(config.MONITORING_INTERVAL)
                
            except Exception as e:
                self.logger.error(f"Connection monitoring error: {e}")
                time.sleep(5)
    
    def _process_packet(self, packet: PacketData):
        """Process a captured packet."""
        if not self._is_valid_ip(packet.src_ip):
            return
            
        with self.traffic_lock:
            self.traffic_data[packet.src_ip].append(packet)
            
            # Limit packet history per IP
            if len(self.traffic_data[packet.src_ip]) > 100:
                self.traffic_data[packet.src_ip] = self.traffic_data[packet.src_ip][-50:]
        
        # Notify callback
        if self.callback:
            self.callback({packet.src_ip: [packet]})
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP should be monitored."""
        if not ip:
            return False
            
        # Filter out local/private IPs
        if (ip.startswith('127.') or 
            ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.') or
            ip == '::1' or
            ':' in ip):  # IPv6
            return False
            
        return True
    
    def get_traffic_data(self) -> Dict[str, List[Dict]]:
        """
        Get current traffic data.
        
        Returns:
            Dict mapping IP addresses to packet lists
        """
        with self.traffic_lock:
            # Convert to serializable format
            result = {}
            for ip, packets in self.traffic_data.items():
                result[ip] = [
                    {
                        'timestamp': p.timestamp,
                        'size': p.size,
                        'src_port': p.src_port,
                        'dst_port': p.dst_port,
                        'protocol': p.protocol
                    }
                    for p in packets
                ]
            return result
    
    def clear_old_data(self, max_age: int = None):
        """Clear old traffic data."""
        max_age = max_age or config.HISTORY_WINDOW
        current_time = time.time()
        
        with self.traffic_lock:
            for ip in list(self.traffic_data.keys()):
                # Filter recent packets
                recent_packets = [
                    p for p in self.traffic_data[ip]
                    if current_time - p.timestamp <= max_age
                ]
                
                if recent_packets:
                    self.traffic_data[ip] = recent_packets
                else:
                    del self.traffic_data[ip]
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics."""
        with self.traffic_lock:
            total_packets = sum(len(packets) for packets in self.traffic_data.values())
            
            return {
                'is_running': self.is_running,
                'packet_capture_available': self.packet_capture_available,
                'monitored_ips': len(self.traffic_data),
                'total_packets': total_packets,
                'monitoring_method': 'packet_capture' if self.packet_capture_available else 'connection_monitoring'
            }

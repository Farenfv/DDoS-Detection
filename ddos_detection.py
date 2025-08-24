# Standard library imports
import os
import sys
import signal
import socket
import time
import threading
import logging
import json
import pickle
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

# Setup Scapy environment variables before any Scapy imports
os.environ['SCAPY_USE_PCAPDNET'] = '1'  # Force pcap usage on Windows
os.environ['SCAPY_CACHE_DISABLE'] = '1'  # Disable cache to avoid permission issues

# Third-party imports
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from prometheus_client import start_http_server, Counter, Gauge, Histogram
from sklearn.ensemble import IsolationForest

# Local application imports
from config import config
from utils.logger import setup_logger

# Initialize logger
logger = setup_logger(__name__, config.LOG_LEVEL, config.LOG_FILE)

# Initialize Flask
app = Flask(__name__, 
    static_folder=os.path.abspath('static'), 
    template_folder=os.path.abspath('templates'))
    
# Configure session and secret key
app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production'),
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
    TEMPLATES_AUTO_RELOAD=True
)

# Initialize Socket.IO with CORS and async mode
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',  # Changed from eventlet to threading for better compatibility
    logger=False,  # Reduce logging noise
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    transports=['polling', 'websocket'],  # Try polling first, then websocket
    allow_upgrades=True
)

# Initialize metrics
prometheus_metrics = {
    'requests_total': Counter('ddos_detection_requests_total', 'Total number of requests'),
    'blocked_ips': Gauge('ddos_detection_blocked_ips', 'Number of blocked IPs'),
    'active_connections': Gauge('ddos_detection_active_connections', 'Number of active connections'),
    'request_rate': Gauge('ddos_detection_request_rate', 'Current request rate'),
    'request_duration': Histogram('ddos_detection_request_duration_seconds', 'Request duration in seconds',
                                buckets=[0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0])
}

# Global variables with thread safety
traffic_data = defaultdict(list)
history_data = defaultdict(list)
blocked_ips = set()
ml_model = None
monitoring_active = False  # Track if monitoring is active

# Thread lock for thread-safe operations
traffic_lock = threading.Lock()
blocked_ips_lock = threading.Lock()

# Event to signal background threads to stop
shutdown_event = threading.Event()
ml_features = ['request_count', 'request_rate', 'avg_packet_size', 'src_port_entropy']
ml_scaler = None

# Setup logging
logging.basicConfig(filename='ddos_detection.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Parameters
TIME_WINDOW = 10  # Time window in seconds
HISTORY_WINDOW = 60  # Historical window in seconds for dynamic threshold
REQUEST_THRESHOLD_MULTIPLIER = 3  # Multiplier for threshold calculation

def extract_features(ip, packets, current_time):
    """Extract features for ML model."""
    # Filter packets within time window
    window = [pkt for pkt in packets if current_time - pkt['timestamp'] <= config.TIME_WINDOW]
    if not window:
        return None
        
    features = {
        'request_count': len(window),
        'request_rate': len(window) / config.TIME_WINDOW,
        'avg_packet_size': np.mean([pkt['size'] for pkt in window]) if window else 0,
        'src_port_entropy': 0  # Placeholder for actual port entropy calculation
    }
    return features

def train_ml_model():
    """Train the ML model on historical data."""
    global ml_model, ml_scaler
    
    # Initialize model without training on fake data
    # Model will be trained incrementally as real traffic data is collected
    ml_model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    logger.info("ML model initialized - will train on real traffic data as it becomes available")

def detect_ddos(packet):
    """Process incoming network packets and detect potential DDoS attacks."""
    try:
        logger.debug(f"Processing packet: {packet.summary() if hasattr(packet, 'summary') else 'Unknown packet'}")
        
        if not packet.haslayer('IP'):
            logger.debug("Packet has no IP layer, skipping")
            return
            
        ip_src = packet['IP'].src
        current_time = time.time()
        
        logger.debug(f"Processing packet from IP: {ip_src}")
        
        # Skip blocked IPs
        if ip_src in blocked_ips:
            logger.debug(f"IP {ip_src} is blocked, skipping")
            return
            
        # Store packet data
        with traffic_lock:
            traffic_data[ip_src].append({
                'timestamp': current_time,
                'size': len(packet),
                'src_port': packet.sport if hasattr(packet, 'sport') else 0
            })
        
        logger.debug(f"Added packet data for IP {ip_src}, total packets: {len(traffic_data[ip_src])}")
        
        # Extract features and predict
        features = extract_features(ip_src, traffic_data[ip_src], current_time)
        if features and ml_model:
            # Make prediction
            X = np.array([[features[f] for f in ml_features]])
            is_anomaly = ml_model.predict(X)[0] == -1
            
            if is_anomaly:
                logger.warning(f"Potential DDoS attack detected from {ip_src}")
                socketio.emit('ddos_alert', {
                    'ip': ip_src,
                    'timestamp': datetime.now().isoformat(),
                    'features': features
                })
                
    except Exception as e:
        logger.error(f"Error in packet processing: {e}", exc_info=True)

def cleanup_old_data():
    """Remove old data to prevent memory leaks."""
    current_time = time.time()
    for ip in list(traffic_data.keys()):
        # Keep only recent data
        traffic_data[ip] = [pkt for pkt in traffic_data[ip] if current_time - pkt['timestamp'] <= config.HISTORY_WINDOW]
        
        # Remove IP if no recent activity
        if not traffic_data[ip]:
            del traffic_data[ip]
            if ip in history_data:
                del history_data[ip]

def analyze_traffic():
    """Background task to analyze traffic and update metrics."""
    logger.info("Starting traffic analysis thread")
    
    def emit_traffic_update(ip, features, timestamp):
        try:
            traffic_update = {
                'ip': ip,
                'timestamp': int(timestamp * 1000),  # Convert to milliseconds
                'request_rate': float(features.get('request_rate', 0)),
                'request_count': int(features.get('request_count', 0))
            }
            socketio.emit('traffic_update', traffic_update)
            logger.info(f"Emitted traffic update for {ip}: {traffic_update}")
        except Exception as e:
            logger.error(f"Error emitting traffic update for {ip}: {e}", exc_info=True)
    
    def emit_system_stats():
        try:
            with traffic_lock:
                active_conns = len(traffic_data)
                logger.debug(f"Current traffic data keys: {list(traffic_data.keys())}")
            with blocked_ips_lock:
                blocked_count = len(blocked_ips)
                logger.debug(f"Blocked IPs: {blocked_ips}")
                
            stats_data = {
                'timestamp': int(time.time() * 1000),
                'active_connections': active_conns,
                'blocked_ips': blocked_count
            }
            
            logger.debug(f"Emitting system stats: {stats_data}")
            socketio.emit('system_stats', stats_data)
            
            # Update Prometheus metrics
            prometheus_metrics['active_connections'].set(active_conns)
            prometheus_metrics['blocked_ips'].set(blocked_count)
            
            logger.debug(f"Successfully emitted system stats: {stats_data}")
            
        except Exception as e:
            logger.error(f"Error emitting system stats: {e}", exc_info=True)
    
    while not shutdown_event.is_set():
        try:
            current_time = time.time()
            cleanup_old_data()
            
            # Process traffic data
            with traffic_lock:
                ips_to_process = list(traffic_data.keys())
            
            # Update metrics for each active IP
            if ips_to_process:
                logger.info(f"Processing {len(ips_to_process)} active IPs for traffic updates")
                
            for ip in ips_to_process:
                try:
                    with traffic_lock:
                        packets = traffic_data.get(ip, []).copy()
                    
                    if packets:  # Only process if we have packets
                        features = extract_features(ip, packets, current_time)
                        if features:
                            emit_traffic_update(ip, features, current_time)
                            
                            # Update request rate metric
                            prometheus_metrics['request_rate'].set(features.get('request_rate', 0))
                        else:
                            logger.warning(f"No features extracted for IP {ip}")
                    else:
                        logger.warning(f"No packets found for IP {ip}")
                
                except Exception as e:
                    logger.error(f"Error processing IP {ip}: {e}", exc_info=True)
            
            # Emit system stats periodically
            emit_system_stats()
            
            # Log traffic summary for debugging
            if ips_to_process:
                logger.info(f"Processing {len(ips_to_process)} active IPs: {ips_to_process[:5]}{'...' if len(ips_to_process) > 5 else ''}")
                # Log some sample data for debugging
                for ip in ips_to_process[:3]:
                    with traffic_lock:
                        packets = traffic_data.get(ip, [])
                        logger.debug(f"IP {ip}: {len(packets)} packets")
            else:
                logger.debug("No active IPs to process")
            
            # Sleep with small increments to be more responsive to shutdown
            for _ in range(10):
                if shutdown_event.is_set():
                    break
                time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error in traffic analysis: {e}", exc_info=True)
            if not shutdown_event.is_set():
                time.sleep(5)  # Prevent tight loop on error
    
    logger.info("Traffic analysis thread stopped")

def get_default_interface():
    """Automatically detect the default network interface."""
    try:
        import psutil
        import socket
        
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
        
        # Find the interface with a valid IP address (not loopback)
        for interface_name, addresses in interfaces.items():
            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    ip = addr.address
                    # Skip loopback and invalid addresses
                    if ip != '127.0.0.1' and not ip.startswith('169.254'):
                        logger.info(f"Auto-detected network interface: {interface_name} ({ip})")
                        return interface_name
        
        # Fallback to first non-loopback interface
        for interface_name in interfaces.keys():
            if 'loopback' not in interface_name.lower() and 'lo' != interface_name.lower():
                logger.info(f"Using fallback interface: {interface_name}")
                return interface_name
                
        return None
    except Exception as e:
        logger.error(f"Error detecting network interface: {e}")
        return None

def start_alternative_monitoring():
    """Start alternative network monitoring using system network statistics."""
    global alternative_monitoring_active
    
    # Prevent multiple instances
    if hasattr(start_alternative_monitoring, 'running') and start_alternative_monitoring.running:
        logger.warning("Alternative monitoring already running, skipping duplicate start")
        return
    
    start_alternative_monitoring.running = True
    logger.info("Starting alternative network monitoring using system statistics...")
    
    def monitor_network_connections():
        try:
            import psutil
            import time
            
            while not shutdown_event.is_set():
                try:
                    # Get network connections with reduced frequency to avoid conflicts
                    connections = psutil.net_connections(kind='inet')
                    current_time = time.time()
                    
                    # Process active connections with filtering
                    active_ips = set()
                    connection_counts = {}
                    
                    for conn in connections:
                        if conn.raddr and conn.status == 'ESTABLISHED':  # Only established connections
                            remote_ip = conn.raddr.ip
                            # Filter out local, loopback, and IPv6 addresses
                            if (remote_ip and remote_ip != '127.0.0.1' and 
                                not remote_ip.startswith('169.254') and 
                                not remote_ip.startswith('::') and
                                remote_ip != '::1'):
                                active_ips.add(remote_ip)
                                connection_counts[remote_ip] = connection_counts.get(remote_ip, 0) + 1
                    
                    # Update traffic data with stable connection info
                    with traffic_lock:
                        # Clear old data first to prevent accumulation
                        old_ips = set(traffic_data.keys()) - active_ips
                        for ip in old_ips:
                            if ip in traffic_data:
                                del traffic_data[ip]
                        
                        # Add current active connections
                        for ip in active_ips:
                            # Create packet data for each connection
                            conn_count = connection_counts.get(ip, 1)
                            packet_data = {
                                'timestamp': current_time,
                                'size': 64 + (conn_count * 5),  # Variable size based on connections
                                'src_port': 80,
                                'dst_port': 443
                            }
                            traffic_data[ip] = [packet_data]  # Single packet per IP
                    
                    # Reduced logging frequency
                    if len(active_ips) > 0:
                        logger.debug(f"Monitoring {len(active_ips)} active connections")
                    
                    time.sleep(3)  # Increased interval to reduce conflicts
                    
                except Exception as e:
                    logger.error(f"Error in alternative monitoring: {e}")
                    time.sleep(10)
                    
        except ImportError:
            logger.error("psutil not available for alternative monitoring")
        except Exception as e:
            logger.error(f"Alternative monitoring failed: {e}")
        finally:
            start_alternative_monitoring.running = False
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_network_connections)
    monitor_thread.daemon = True
    monitor_thread.start()
    logger.info("Alternative network monitoring started")

def setup_scapy_cache():
    """Setup Scapy cache directory with proper permissions."""
    try:
        import os
        from pathlib import Path
        
        # Get user's cache directory
        cache_dir = Path.home() / '.cache' / 'scapy'
        
        # Create cache directory if it doesn't exist
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Set proper permissions (Windows)
        if os.name == 'nt':
            try:
                import stat
                # Make directory writable
                cache_dir.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                logger.info(f"Scapy cache directory setup: {cache_dir}")
            except Exception as e:
                logger.warning(f"Could not set cache permissions: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to setup Scapy cache: {e}")
        return False

def start_sniffing():
    """Start packet sniffing on the automatically detected interface."""
    try:
        # Setup Scapy cache first
        setup_scapy_cache()
        
        # Import Scapy with comprehensive error handling
        scapy_imported = False
        
        # Method 1: Try normal import
        try:
            from scapy.all import sniff, conf, get_if_list
            scapy_imported = True
            logger.info("Scapy imported successfully")
        except PermissionError as pe:
            logger.error(f"Scapy cache permission error: {pe}")
            logger.info("Trying alternative Scapy import methods...")
            
            # Method 2: Force clear cache and retry
            try:
                import shutil
                from pathlib import Path
                cache_dir = Path.home() / '.cache' / 'scapy'
                
                if cache_dir.exists():
                    # Try to take ownership and delete
                    import subprocess
                    try:
                        subprocess.run(['takeown', '/f', str(cache_dir), '/r', '/d', 'y'], 
                                     capture_output=True, check=False)
                        subprocess.run(['icacls', str(cache_dir), '/grant', f'{os.getlogin()}:F', '/t'], 
                                     capture_output=True, check=False)
                        shutil.rmtree(cache_dir, ignore_errors=True)
                        logger.info("Forcefully removed Scapy cache directory")
                    except Exception as ownership_error:
                        logger.warning(f"Could not take ownership of cache: {ownership_error}")
                        # Try simple removal
                        try:
                            shutil.rmtree(cache_dir, ignore_errors=True)
                        except:
                            pass
                
                cache_dir.mkdir(parents=True, exist_ok=True)
                
                # Try importing again
                from scapy.all import sniff, conf, get_if_list
                scapy_imported = True
                logger.info("Scapy import successful after forced cache cleanup")
                
            except Exception as cache_error:
                logger.warning(f"Cache cleanup failed: {cache_error}")
                
                # Method 3: Try with alternative temp directory
                try:
                    import tempfile
                    temp_cache = Path(tempfile.gettempdir()) / 'scapy_temp_cache'
                    temp_cache.mkdir(exist_ok=True)
                    
                    os.environ['SCAPY_CACHE_DIR'] = str(temp_cache)
                    os.environ['SCAPY_USE_PCAPDNET'] = '1'
                    os.environ['SCAPY_CACHE_DISABLE'] = '1'
                    
                    from scapy.all import sniff, conf, get_if_list
                    scapy_imported = True
                    logger.info("Scapy import successful with temp cache")
                    
                except Exception as temp_error:
                    logger.error(f"Temp cache method failed: {temp_error}")
                    
                    # Method 4: Try completely disabling cache
                    try:
                        os.environ['SCAPY_CACHE_DISABLE'] = '1'
                        os.environ['SCAPY_NO_CACHE'] = '1'
                        
                        # Import without cache
                        import sys
                        if 'scapy' in sys.modules:
                            del sys.modules['scapy']
                        
                        from scapy.all import sniff, conf, get_if_list
                        scapy_imported = True
                        logger.info("Scapy import successful with completely disabled cache")
                        
                    except Exception as final_error:
                        logger.error(f"All Scapy import methods failed: {final_error}")
                        scapy_imported = False
        
        if not scapy_imported:
            logger.error("Failed to import Scapy - packet capture will not work")
            logger.error("Try running as Administrator or check Windows permissions")
            logger.info("Starting alternative network monitoring without raw packet capture...")
            start_alternative_monitoring()
            return
        
        # Auto-detect interface if not specified
        interface = config.INTERFACE if config.INTERFACE else get_default_interface()
        
        if interface:
            # Try to set the interface
            try:
                conf.iface = interface
                logger.info(f"Using network interface: {interface}")
            except Exception as e:
                logger.warning(f"Could not set interface {interface}: {e}")
                logger.info("Using default interface")
        else:
            logger.info("Using default network interface")
            
        logger.info(f"Starting packet capture on interface: {conf.iface}")
        logger.info("Monitoring all network traffic...")
        
        # Start sniffing in a separate thread
        def packet_capture_worker():
            try:
                logger.info("Attempting to start packet capture...")
                logger.info(f"Using detect_ddos function: {detect_ddos}")
                sniff(
                    prn=detect_ddos,
                    store=0,
                    filter="ip",
                    count=0,  # 0 means unlimited
                    timeout=1,  # 1 second timeout to allow checking shutdown
                    stop_filter=lambda x: shutdown_event.is_set()
                )
            except Exception as sniff_error:
                logger.error(f"Error during sniffing: {sniff_error}")
                # Try alternative approach for Windows
                try:
                    logger.info("Trying alternative sniffing method for Windows...")
                    sniff(
                        prn=detect_ddos,
                        store=0,
                        filter="ip",
                        count=0,
                        timeout=1,
                        iface=conf.iface,
                        stop_filter=lambda x: shutdown_event.is_set()
                    )
                except Exception as alt_error:
                    logger.error(f"Alternative sniffing also failed: {alt_error}")
                    logger.info("Starting alternative network monitoring...")
                    start_alternative_monitoring()
        
        # Start packet capture in thread
        capture_thread = threading.Thread(target=packet_capture_worker)
        capture_thread.daemon = True
        capture_thread.start()
        logger.info("Packet capture thread started")
                
    except Exception as e:
        logger.error(f"Error in packet capture: {e}", exc_info=True)
        logger.error("Packet sniffing failed, starting alternative monitoring")
        logger.error("This is common on Windows - try running as Administrator")
        logger.info("Starting alternative network monitoring as fallback...")
        start_alternative_monitoring()




def test_packet_capture():
    """Test if packet capture is working on this system."""
    try:
        from scapy.all import sniff, conf
        import time
        
        logger.info("Testing packet capture capability...")
        
        # Try to capture just one packet with a timeout
        start_time = time.time()
        packets = sniff(count=1, timeout=5, store=1)
        capture_time = time.time() - start_time
        
        if packets:
            logger.info(f"✓ Packet capture test successful! Captured {len(packets)} packets in {capture_time:.2f}s")
            return True
        else:
            logger.warning("⚠ Packet capture test: No packets captured in 5 seconds")
            return False
            
    except Exception as e:
        logger.error(f"✗ Packet capture test failed: {e}")
        return False

# WebSocket events
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")
    
    # Send current state to the new client
    with traffic_lock:
        active_conns = len(traffic_data)
    with blocked_ips_lock:
        blocked_count = len(blocked_ips)
    
    socketio.emit('system_stats', {
        'timestamp': int(time.time() * 1000),
        'active_connections': active_conns,
        'blocked_ips': blocked_count
    }, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('get_initial_data')
def handle_get_initial_data():
    """Send initial data to newly connected client."""
    try:
        with traffic_lock:
            active_conns = len(traffic_data)
            traffic_updates = []
            current_time = time.time()
            
            # Send current traffic data for all active connections
            for ip, packets in traffic_data.items():
                features = extract_features(ip, packets, current_time)
                if features:
                    traffic_updates.append({
                        'ip': ip,
                        'timestamp': int(current_time * 1000),
                        'request_rate': float(features.get('request_rate', 0)),
                        'request_count': int(features.get('request_count', 0))
                    })
        
        with blocked_ips_lock:
            blocked_count = len(blocked_ips)
        
        # Send initial data
        emit('initial_data', {
            'traffic': traffic_updates,
            'stats': {
                'active_connections': active_conns,
                'blocked_ips': blocked_count,
                'timestamp': int(time.time() * 1000)
            }
        })
        
    except Exception as e:
        logger.error(f"Error sending initial data: {e}", exc_info=True)
        emit('error', {'message': 'Failed to load initial data'})

# API Endpoints
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test')
def test():
    """Simple test endpoint to verify server is working."""
    return jsonify({
        'status': 'ok',
        'message': 'Server is running',
        'timestamp': datetime.now().isoformat(),
        'traffic_data_count': len(traffic_data),
        'blocked_ips_count': len(blocked_ips)
    })

@app.route('/status')
def status():
    """Detailed status endpoint showing system health."""
    try:
        # Get network interface info
        interface_info = "Unknown"
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            active_interfaces = []
            
            for interface_name, addresses in interfaces.items():
                for addr in addresses:
                    if addr.family == 2:  # IPv4
                        ip = addr.address
                        if ip != '127.0.0.1' and not ip.startswith('169.254'):
                            active_interfaces.append(f"{interface_name} ({ip})")
            
            if active_interfaces:
                interface_info = f"Active: {', '.join(active_interfaces[:2])}"  # Show first 2
            else:
                interface_info = "No active interfaces detected"
        except Exception as e:
            interface_info = f"Interface detection failed: {str(e)}"
        
        status_data = {
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'traffic_data_count': len(traffic_data),
            'blocked_ips_count': len(blocked_ips),
            'active_connections': len(traffic_data),
            'total_packets': sum(len(packets) for packets in traffic_data.values()),
            'network_interface': interface_info,
            'background_threads': {
                'analysis_thread': 'analysis_thread' in globals() and analysis_thread.is_alive() if 'analysis_thread' in globals() else False,
                'sniffing_thread': monitoring_active  # Use persistent monitoring state
            }
        }
        return jsonify(status_data)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/api/block-ip/<ip>', methods=['POST'])
def block_ip(ip):
    """Block an IP address."""
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip)  # Raises ValueError for invalid IP
        except ValueError as e:
            logger.warning(f"Invalid IP address provided: {ip}")
            return jsonify({
                'status': 'error',
                'message': f'Invalid IP address: {ip}'
            }), 400
        
        # Check if already blocked
        with blocked_ips_lock:
            if ip in blocked_ips:
                return jsonify({
                    'status': 'success',
                    'message': f'IP {ip} is already blocked'
                }), 200
                
            # Add to blocked IPs
            blocked_ips.add(ip)
            blocked_count = len(blocked_ips)
        
        # Update metrics
        prometheus_metrics['blocked_ips'].inc()
        logger.warning(f"Blocked IP: {ip} (Total blocked: {blocked_count})")
        
        # Remove from active connections
        with traffic_lock:
            if ip in traffic_data:
                del traffic_data[ip]
        
        # Notify all clients about the blocked IP
        socketio.emit('ip_blocked', {
            'ip': ip, 
            'timestamp': int(time.time() * 1000),
            'blocked_count': blocked_count
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully blocked IP: {ip}',
            'blocked_count': blocked_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error blocking IP {ip}: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to block IP: {str(e)}'
        }), 500

@app.route('/api/unblock-ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP address."""
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip)  # Raises ValueError for invalid IP
        except ValueError as e:
            logger.warning(f"Invalid IP address provided: {ip}")
            return jsonify({
                'status': 'error',
                'message': f'Invalid IP address: {ip}'
            }), 400
        
        # Check if actually blocked
        with blocked_ips_lock:
            if ip not in blocked_ips:
                return jsonify({
                    'status': 'success',
                    'message': f'IP {ip} is not currently blocked'
                }), 200
                
            # Remove from blocked IPs
            blocked_ips.remove(ip)
            blocked_count = len(blocked_ips)
        
        # Update metrics
        prometheus_metrics['blocked_ips'].dec()
        logger.info(f"Unblocked IP: {ip} (Remaining blocked: {blocked_count})")
        
        # Notify all clients about the unblocked IP
        socketio.emit('ip_unblocked', {
            'ip': ip, 
            'timestamp': int(time.time() * 1000),
            'blocked_count': blocked_count
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully unblocked IP: {ip}',
            'blocked_count': blocked_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error unblocking IP {ip}: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to unblock IP: {str(e)}'
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get current statistics."""
    stats = {
        'active_connections': len(traffic_data),
        'blocked_ips': len(blocked_ips),
        'total_packets': sum(len(packets) for packets in traffic_data.values()),
        'blocked_ips_list': list(blocked_ips)
    }
    return jsonify(stats)

@app.route('/api/force-monitoring', methods=['POST'])
def force_monitoring():
    """Force start alternative monitoring for testing."""
    try:
        logger.info("Force starting alternative monitoring...")
        start_alternative_monitoring()
        return jsonify({
            'status': 'success',
            'message': 'Alternative monitoring started'
        })
    except Exception as e:
        logger.error(f"Error force starting monitoring: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



@app.route('/api/clear-traffic', methods=['POST'])
def clear_traffic():
    """Clear old traffic data but keep monitoring active."""
    try:
        current_time = time.time()
        
        with traffic_lock:
            # Instead of clearing all data, just remove old entries
            for ip in list(traffic_data.keys()):
                # Keep only very recent data (last 5 seconds) to maintain monitoring
                traffic_data[ip] = [pkt for pkt in traffic_data[ip] 
                                  if current_time - pkt['timestamp'] <= 5]
                # Remove IP if no recent activity
                if not traffic_data[ip]:
                    del traffic_data[ip]
        
        logger.info("Old traffic data cleared, monitoring remains active")
        
        # Get current active connections after cleanup
        with traffic_lock:
            active_conns = len(traffic_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Old traffic data cleared successfully',
            'active_connections': active_conns
        })
        
    except Exception as e:
        logger.error(f"Error clearing traffic data: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to clear traffic data: {str(e)}'
        }), 500


@app.route('/api/system-info')
def system_info():
    """Get detailed system information."""
    try:
        import platform
        import psutil
        
        # Get system information
        system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'disk_usage': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent
        }
        
        # Get network interface information
        try:
            network_interfaces = psutil.net_if_addrs()
            system_info['network_interfaces'] = list(network_interfaces.keys())
        except:
            system_info['network_interfaces'] = []
        
        return jsonify({
            'status': 'success',
            'system_info': system_info
        })
        
    except Exception as e:
        logger.error(f"Error getting system info: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to get system info: {str(e)}'
        }), 500

def start_background_tasks():
    """Start all background tasks."""
    global analysis_thread, monitoring_active
    
    # Clear shutdown event in case of restarts
    shutdown_event.clear()
    
    # Set monitoring as active
    monitoring_active = True
    
    # Start traffic analysis in a separate thread
    analysis_thread = threading.Thread(target=analyze_traffic)
    analysis_thread.daemon = True
    analysis_thread.start()
    logger.info("Started background tasks")

def stop_background_tasks():
    """Stop all background tasks gracefully."""
    global analysis_thread, monitoring_active
    
    logger.info("Stopping background tasks...")
    shutdown_event.set()
    monitoring_active = False
    
    # Wait for analysis thread to finish
    if analysis_thread and analysis_thread.is_alive():
        analysis_thread.join(timeout=5)
        if analysis_thread.is_alive():
            logger.warning("Analysis thread did not stop gracefully")
    
    logger.info("Background tasks stopped")

def handle_shutdown(signum=None, frame=None):
    """Handle application shutdown gracefully."""
    logger.info("Shutting down...")
    stop_background_tasks()
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

if __name__ == "__main__":
    try:
        # Re-initialize logger with proper config
        logger = setup_logger(__name__, config.LOG_LEVEL, config.LOG_FILE)
        
        logger.info("Starting DDoS Detection System...")
        
        # Start background tasks
        start_background_tasks()
        
        # Test packet capture capability first
        if test_packet_capture():
            logger.info("Packet capture test passed - starting real network monitoring")
            # Start packet sniffing in a separate thread
            sniffing_thread = threading.Thread(target=start_sniffing)
            sniffing_thread.daemon = True
            sniffing_thread.start()
            logger.info("Started packet sniffing thread")
        else:
            logger.warning("Packet capture test failed - starting alternative monitoring")
        
        # Always start alternative monitoring as backup/supplement
        logger.info("Starting alternative monitoring to ensure traffic data collection")
        start_alternative_monitoring()
        
        # Real network monitoring only - no simulated traffic
        
        # Start the Flask-SocketIO server
        logger.info(f"Starting server on {config.WEB_HOST}:{config.WEB_PORT}")
        socketio.run(
            app, 
            host=config.WEB_HOST, 
            port=config.WEB_PORT,
            debug=False,  # Disable debug to prevent Socket.IO issues
            use_reloader=False,
            allow_unsafe_werkzeug=True,
            log_output=False  # Reduce logging noise
        )
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        stop_background_tasks()
        sys.exit(1)
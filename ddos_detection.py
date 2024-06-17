import time
import threading
import logging
from collections import defaultdict, deque
from scapy.all import sniff
from flask import Flask, jsonify, render_template
import numpy as np

# Setup logging
logging.basicConfig(filename='ddos_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Parameters
TIME_WINDOW = 10  # Time window in seconds
HISTORY_WINDOW = 60  # Historical window in seconds for dynamic threshold
REQUEST_THRESHOLD_MULTIPLIER = 3  # Multiplier for threshold calculation

# Data storage
traffic_data = defaultdict(deque)
history_data = defaultdict(deque)

def detect_ddos(packet):
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        timestamp = time.time()
        
        # Store the packet data
        traffic_data[ip_src].append(timestamp)

def analyze_traffic():
    while True:
        current_time = time.time()
        for ip, timestamps in list(traffic_data.items()):
            # Filter out old entries
            recent_requests = [ts for ts in timestamps if current_time - ts <= TIME_WINDOW]
            traffic_data[ip] = deque(recent_requests)

            # Store historical data
            history_data[ip].append(len(recent_requests))
            if len(history_data[ip]) > HISTORY_WINDOW:
                history_data[ip].popleft()

            # Calculate dynamic threshold
            mean_requests = np.mean(history_data[ip])
            stddev_requests = np.std(history_data[ip])
            dynamic_threshold = mean_requests + REQUEST_THRESHOLD_MULTIPLIER * stddev_requests
            
            if len(recent_requests) > dynamic_threshold:
                logging.info(f"Potential DDoS attack detected from IP: {ip} - Requests: {len(recent_requests)} - Threshold: {dynamic_threshold:.2f}")

        time.sleep(1)

def start_sniffing():
    sniff(prn=detect_ddos, store=0, filter="ip", count=0, timeout=60)

# Start the analysis in a separate thread
analysis_thread = threading.Thread(target=analyze_traffic)
analysis_thread.daemon = True
analysis_thread.start()

# Flask web application for visualization
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/traffic_data')
def get_traffic_data():
    current_time = time.time()
    data = {ip: len([ts for ts in timestamps if current_time - ts <= TIME_WINDOW])
            for ip, timestamps in traffic_data.items()}
    return jsonify(data)

if __name__ == "__main__":
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    app.run(host='0.0.0.0', port=5000)

DDoS Detection Program
This repository contains a Python program for detecting potential DDoS (Distributed Denial of Service) attacks using network traffic analysis.

Features
Real-time Packet Sniffing: Utilizes Scapy library to capture and analyze network traffic in real-time.
Dynamic Thresholding: Uses statistical analysis (mean and standard deviation) to dynamically adjust detection thresholds.
Web Dashboard: Provides a web-based dashboard (built with Flask and Chart.js) for visualizing network traffic data.
Logging: Logs potential DDoS attack detections to a file for further analysis.

Getting Started
To get started with the DDoS detection program, follow these steps:

Prerequisites
Python 3.x installed on your system.
Install required Python packages:

pip install scapy numpy pandas flask

Installation

Clone the repository:
git clone https://github.com/Farenfv/DDoS-Detection.git
cd ddos-detection-python

Run the program:
python ddos_detection.py


Access the web dashboard:
Open your web browser and go to http://localhost:5000

Usage
The program starts sniffing network traffic upon execution.
It continuously analyzes incoming traffic and detects potential DDoS attacks based on predefined thresholds.
Detected events are logged in ddos_detection.log.
The web dashboard updates every 5 seconds to display real-time traffic statistics.


Contributing
Contributions are welcome! If you have suggestions, feature requests, or want to report issues, please open an issue or submit a pull request.

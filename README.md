
# DDoS Detection System

A comprehensive Python-based DDoS (Distributed Denial of Service) detection system with real-time network monitoring, machine learning-based anomaly detection, and a modern web dashboard.


# Features

- **Real-time Network Monitoring**: Advanced packet capture and analysis using Scapy
- **Machine Learning Detection**: Isolation Forest algorithm for anomaly detection
- **Dynamic Thresholding**: Adaptive detection based on network behavior patterns
- **Modern Web Dashboard**: Real-time updates with WebSocket communication
- **Traffic Visualization**: Interactive charts and real-time statistics
- **IP Blocking**: Manual and automatic IP blocking capabilities
- **Real Network Traffic Only**: Monitors actual network traffic without simulation
- **Comprehensive Logging**: Detailed logging with configurable levels
- **Prometheus Metrics**: Integration with monitoring systems
- **Cross-platform Support**: Works on Windows, Linux, and macOS


# Getting Started

## Prerequisites

- **Python 3.8+** installed on your system
- **Administrator/root privileges** (required for packet capture on Windows)
- **Network access** for traffic monitoring

## Quick Start

### Option 1: Windows (Recommended)
1. Right-click on `start.bat` and select "Run as Administrator"
2. Wait for dependencies to install
3. Open http://localhost:5000 in your browser

### Option 2: PowerShell
1. Right-click on `start.ps1` and select "Run as Administrator"
2. Follow the prompts to start the application

### Option 3: Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Start the application
python ddos_detection.py
```


## Installation

```bash
# Clone the repository
git clone https://github.com/Farenfv/DDoS-Detection.git

# Navigate to project directory
cd DDoS-Detection-main

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Starting the Application
```bash
# Run as Administrator (Windows) or with sudo (Linux/macOS)
python ddos_detection.py
```

### Web Dashboard
- Open http://localhost:5000 in your browser
- Real-time traffic monitoring and statistics
- Interactive charts and connection tables
- IP blocking and management

### Testing
```bash
# Test basic functionality and real network monitoring
python test_app.py

# Generate network activity to see real traffic:
# - Browse websites
# - Download files
# - Use network applications
```



## Features in Detail

### Real-time Monitoring
- **Packet Capture**: Monitors all network traffic in real-time
- **Traffic Analysis**: Processes packets and extracts features
- **Anomaly Detection**: ML-based detection of suspicious patterns
- **Live Updates**: WebSocket-based real-time dashboard updates

### Dashboard Features
- **Traffic Charts**: Real-time visualization of network activity
- **Connection Tables**: Active IP addresses and their statistics
- **Statistics Cards**: Overview of system status and metrics
- **IP Management**: Block/unblock suspicious IP addresses

### Testing & Development
- **Real Traffic Monitoring**: Captures and analyzes actual network activity
- **Debug Logging**: Comprehensive logging for troubleshooting
- **API Endpoints**: RESTful API for integration and testing
- **Prometheus Metrics**: Monitoring and alerting integration

## Troubleshooting

If you encounter issues:
1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Ensure you're running as Administrator (Windows)
3. Check the application logs in `ddos_detection.log`
4. Use the test script: `python test_app.py`

## Configuration

Edit `config.py` to customize:
- Network interface selection
- Detection thresholds
- Logging levels
- Web server settings



## Contributing

Contributions are welcome! If you have suggestions, feature requests, or want to report issues, please:

1. Open an issue describing the problem or feature request
2. Fork the repository and create a feature branch
3. Submit a pull request with your changes
4. Ensure all tests pass and code follows the project style

## License

This project is open source and available under the [MIT License](LICENSE).

## Support

For support and questions:
- Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
- Review the application logs
- Open an issue with detailed error information

# 🛡️ Professional DDoS Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A **production-ready**, enterprise-grade DDoS (Distributed Denial of Service) detection system with advanced machine learning capabilities, real-time monitoring, and professional web dashboard.

## 🚀 Key Features

### 🔍 **Advanced Detection Engine**
- **Machine Learning**: Isolation Forest algorithm with adaptive thresholding
- **Statistical Analysis**: Multi-layered anomaly detection with baseline learning
- **Real-time Processing**: Sub-second detection and response capabilities
- **Behavioral Analysis**: Traffic pattern recognition and burst detection

### 📊 **Professional Dashboard**
- **Real-time Updates**: WebSocket-powered live monitoring
- **Interactive Visualizations**: Dynamic charts with Chart.js
- **Comprehensive Metrics**: Traffic statistics, threat levels, and system health
- **Responsive Design**: Modern UI optimized for all devices

### 🔧 **Enterprise Features**
- **Multi-method Monitoring**: Raw packet capture + system connection fallback
- **Automatic IP Blocking**: Intelligent threat mitigation
- **Prometheus Integration**: Enterprise monitoring and alerting
- **Professional Logging**: Structured logging with rotation and levels
- **Configuration Management**: Environment-based configuration with validation
- **Security Hardening**: Input validation, rate limiting, and CORS protection


# Getting Started

## 📋 Prerequisites

- **Python 3.8+** with pip package manager
- **Administrator/root privileges** (required for network packet capture)
- **Network interface access** for traffic monitoring
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

## ⚡ Quick Start

### 🪟 **Windows (Recommended)**
```powershell
# Right-click PowerShell as Administrator
cd path\to\DDoS-Detection-main
.\start.ps1
```

### 🐧 **Linux/macOS**
```bash
# Run with sudo for packet capture
sudo python3 ddos_detection.py
```

### 🔧 **Manual Installation**
```bash
# Clone repository
git clone https://github.com/yourusername/ddos-detection-system.git
cd ddos-detection-system

# Install dependencies
pip install -r requirements.txt

# Configure environment (optional)
cp .env.example .env
# Edit .env with your settings

# Start application
python ddos_detection.py
```

### 🌐 **Access Dashboard**
Open [http://localhost:5000](http://localhost:5000) in your browser


## 🛠️ Installation & Configuration

### **Standard Installation**
```bash
# Clone repository
git clone https://github.com/yourusername/ddos-detection-system.git
cd ddos-detection-system

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### **Environment Configuration**
Create `.env` file for custom settings:
```bash
# Security
SECRET_KEY=your-secret-key-here
DEBUG=False

# Network
WEB_HOST=127.0.0.1
WEB_PORT=5000
INTERFACE=eth0

# Detection Parameters
TIME_WINDOW=10
HISTORY_WINDOW=60
REQUEST_THRESHOLD_MULTIPLIER=3.0
ANOMALY_THRESHOLD=0.1

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/ddos_detection.log
```

## 🚀 Usage

### **Starting the System**
```bash
# Production mode
python ddos_detection.py

# Development mode with debug
DEBUG=True python ddos_detection.py

# Custom configuration
CONFIG_FILE=custom.env python ddos_detection.py
```

### **Web Dashboard Features**
- 📈 **Real-time Traffic Monitoring**: Live network activity visualization
- 🎯 **Threat Detection**: ML-powered anomaly identification
- 🚫 **IP Management**: Block/unblock suspicious addresses
- 📊 **Analytics**: Comprehensive traffic statistics and trends
- ⚙️ **System Health**: Monitoring status and performance metrics

### **API Endpoints**
```bash
# System status
GET /api/status

# Traffic statistics
GET /api/stats

# Block IP address
POST /api/block-ip
{"ip": "192.168.1.100"}

# Unblock IP address
POST /api/unblock-ip
{"ip": "192.168.1.100"}

# Clear traffic data
POST /api/clear-traffic
```



## 🏗️ Architecture & Features

### **Core Components**

#### 🔍 **Detection Engine** (`src/core/detector.py`)
- **Machine Learning**: Isolation Forest with adaptive contamination
- **Statistical Analysis**: Baseline learning and deviation detection
- **Feature Extraction**: Multi-dimensional traffic analysis
- **Threat Classification**: 4-level threat assessment (low/medium/high/critical)

#### 📡 **Network Monitor** (`src/core/monitor.py`)
- **Dual-mode Operation**: Raw packet capture + connection monitoring
- **Cross-platform Support**: Windows/Linux/macOS compatibility
- **Automatic Fallback**: Graceful degradation when privileges unavailable
- **Performance Optimized**: Efficient packet processing and filtering

#### 🌐 **Web Interface** (`templates/`)
- **Real-time Dashboard**: WebSocket-powered live updates
- **Responsive Design**: Mobile-friendly interface
- **Interactive Charts**: Dynamic visualization with Chart.js
- **Professional UI**: Modern design with Bootstrap components

### **Advanced Features**

#### 🛡️ **Security Hardening**
- Input validation and sanitization
- Rate limiting for API endpoints
- CORS protection and secure headers
- Environment-based configuration

#### 📊 **Monitoring & Observability**
- Structured logging with rotation
- Prometheus metrics integration
- Health check endpoints
- Performance monitoring

#### ⚙️ **Configuration Management**
- Environment variable support
- Configuration validation
- Runtime parameter adjustment
- Production-ready defaults

## 🧪 Testing & Validation

### **Automated Testing**
```bash
# Run test suite
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/

# Integration tests
python test_app.py
```

### **Manual Testing**
```bash
# Generate network activity for testing:
# 1. Browse multiple websites simultaneously
# 2. Download large files
# 3. Run network-intensive applications
# 4. Use tools like curl or wget in loops

# Monitor logs for detection events
tail -f logs/ddos_detection.log
```

## 🔧 Configuration

### **Configuration Files**
- `config.py`: Core application settings
- `.env`: Environment-specific overrides
- `requirements.txt`: Python dependencies

### **Key Configuration Options**
```python
# Detection sensitivity
REQUEST_THRESHOLD_MULTIPLIER = 3.0  # Higher = less sensitive
ANOMALY_THRESHOLD = 0.1              # ML contamination rate

# Performance tuning
TIME_WINDOW = 10          # Analysis window (seconds)
HISTORY_WINDOW = 60       # Data retention (seconds)
MONITORING_INTERVAL = 1   # Update frequency (seconds)

# Security settings
MAX_REQUESTS_PER_MINUTE = 100  # Rate limiting
BLOCK_DURATION = 300           # IP block duration (seconds)
```

## 🐛 Troubleshooting

### **Common Issues**

| Issue | Solution |
|-------|----------|
| Permission denied | Run as Administrator/sudo |
| No network interface | Check INTERFACE setting in config |
| Dashboard not loading | Verify port 5000 is available |
| No traffic detected | Ensure network activity is present |

### **Debug Mode**
```bash
# Enable verbose logging
LOG_LEVEL=DEBUG python ddos_detection.py

# Check system compatibility
python -c "import scapy; print('Scapy available')"
python -c "import psutil; print('Psutil available')"
```

### **Log Analysis**
```bash
# View recent logs
tail -f logs/ddos_detection.log

# Search for errors
grep -i error logs/ddos_detection.log

# Monitor traffic detection
grep "traffic update" logs/ddos_detection.log
```



## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### **Development Setup**
```bash
# Fork and clone repository
git clone https://github.com/yourusername/ddos-detection-system.git
cd ddos-detection-system

# Create development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### **Code Standards**
- **Style**: Black code formatting
- **Linting**: Flake8 compliance
- **Type Hints**: Full type annotation
- **Documentation**: Comprehensive docstrings
- **Testing**: Unit tests for new features

### **Contribution Process**
1. 🍴 Fork the repository
2. 🌿 Create feature branch (`git checkout -b feature/amazing-feature`)
3. 💻 Make your changes with tests
4. ✅ Run test suite (`pytest`)
5. 📝 Update documentation
6. 🚀 Submit pull request

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### **Getting Help**
- 📖 **Documentation**: Check this README and code comments
- 🐛 **Bug Reports**: Open an issue with detailed information
- 💡 **Feature Requests**: Describe your use case and requirements
- 💬 **Discussions**: Use GitHub Discussions for questions

### **Professional Support**
For enterprise deployments and custom integrations, contact the maintainers.

---

**⭐ If this project helps you, please consider giving it a star!**

**🔗 Connect with us:**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)
- Email: your.email@domain.com

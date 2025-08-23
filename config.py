import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).parent.absolute()

# Application settings
class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Network
    INTERFACE = os.getenv('INTERFACE', '')
    PROMETHEUS_METRICS_PORT = int(os.getenv('PROMETHEUS_METRICS_PORT', 9090))
    
    # Detection
    TIME_WINDOW = int(os.getenv('TIME_WINDOW', 10))
    HISTORY_WINDOW = int(os.getenv('HISTORY_WINDOW', 60))
    REQUEST_THRESHOLD_MULTIPLIER = float(os.getenv('REQUEST_THRESHOLD_MULTIPLIER', 3.0))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = Path(os.getenv('LOG_FILE', 'logs/ddos_detection.log'))
    
    # Web Interface
    WEB_HOST = os.getenv('WEB_HOST', '0.0.0.0')
    WEB_PORT = int(os.getenv('WEB_PORT', 5000))

# Create logs directory if it doesn't exist
os.makedirs(BASE_DIR / 'logs', exist_ok=True)

# Export config
config = Config()

"""
DDoS Detection System Configuration

This module contains all configuration settings for the DDoS detection system.
Settings can be overridden using environment variables or a .env file.
"""

import os
import secrets
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv is optional
    pass

# Base directory
BASE_DIR = Path(__file__).parent.absolute()


class Config:
    """
    Application configuration class.
    
    All settings can be overridden using environment variables.
    For production deployment, ensure to set appropriate values.
    """
    
    # Application Security
    SECRET_KEY: str = os.getenv('SECRET_KEY', secrets.token_hex(32))
    DEBUG: bool = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Network Configuration
    INTERFACE: str = os.getenv('INTERFACE', '')
    PROMETHEUS_METRICS_PORT: int = int(os.getenv('PROMETHEUS_METRICS_PORT', '9090'))
    
    # Detection Parameters
    TIME_WINDOW: int = int(os.getenv('TIME_WINDOW', '10'))  # seconds
    HISTORY_WINDOW: int = int(os.getenv('HISTORY_WINDOW', '60'))  # seconds
    REQUEST_THRESHOLD_MULTIPLIER: float = float(os.getenv('REQUEST_THRESHOLD_MULTIPLIER', '3.0'))
    ANOMALY_THRESHOLD: float = float(os.getenv('ANOMALY_THRESHOLD', '0.1'))
    
    # Rate Limiting
    MAX_REQUESTS_PER_MINUTE: int = int(os.getenv('MAX_REQUESTS_PER_MINUTE', '100'))
    BLOCK_DURATION: int = int(os.getenv('BLOCK_DURATION', '300'))  # seconds
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: Path = Path(os.getenv('LOG_FILE', 'logs/ddos_detection.log'))
    LOG_MAX_SIZE: int = int(os.getenv('LOG_MAX_SIZE', '10485760'))  # 10MB
    LOG_BACKUP_COUNT: int = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Web Interface
    WEB_HOST: str = os.getenv('WEB_HOST', '127.0.0.1')
    WEB_PORT: int = int(os.getenv('WEB_PORT', '5000'))
    
    # Database (for future expansion)
    DATABASE_URL: Optional[str] = os.getenv('DATABASE_URL')
    
    # Monitoring
    ENABLE_PROMETHEUS: bool = os.getenv('ENABLE_PROMETHEUS', 'True').lower() == 'true'
    MONITORING_INTERVAL: int = int(os.getenv('MONITORING_INTERVAL', '1'))  # seconds
    
    # Security
    ALLOWED_HOSTS: list = os.getenv('ALLOWED_HOSTS', '').split(',') if os.getenv('ALLOWED_HOSTS') else []
    CORS_ORIGINS: list = os.getenv('CORS_ORIGINS', '').split(',') if os.getenv('CORS_ORIGINS') else ['*']
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate configuration settings.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        try:
            # Validate port ranges
            if not (1 <= cls.WEB_PORT <= 65535):
                raise ValueError(f"Invalid WEB_PORT: {cls.WEB_PORT}")
            if not (1 <= cls.PROMETHEUS_METRICS_PORT <= 65535):
                raise ValueError(f"Invalid PROMETHEUS_METRICS_PORT: {cls.PROMETHEUS_METRICS_PORT}")
            
            # Validate thresholds
            if cls.REQUEST_THRESHOLD_MULTIPLIER <= 0:
                raise ValueError(f"REQUEST_THRESHOLD_MULTIPLIER must be positive: {cls.REQUEST_THRESHOLD_MULTIPLIER}")
            if not (0 <= cls.ANOMALY_THRESHOLD <= 1):
                raise ValueError(f"ANOMALY_THRESHOLD must be between 0 and 1: {cls.ANOMALY_THRESHOLD}")
            
            # Validate time windows
            if cls.TIME_WINDOW <= 0:
                raise ValueError(f"TIME_WINDOW must be positive: {cls.TIME_WINDOW}")
            if cls.HISTORY_WINDOW <= 0:
                raise ValueError(f"HISTORY_WINDOW must be positive: {cls.HISTORY_WINDOW}")
            
            return True
        except ValueError as e:
            print(f"Configuration validation error: {e}")
            return False


# Create necessary directories
os.makedirs(BASE_DIR / 'logs', exist_ok=True)
os.makedirs(BASE_DIR / 'data', exist_ok=True)

# Export config instance
config = Config()

# Validate configuration on import
if not config.validate():
    raise RuntimeError("Invalid configuration detected. Please check your settings.")

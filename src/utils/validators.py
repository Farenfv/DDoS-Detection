"""
Input Validation and Security Utilities

Comprehensive validation functions for network data, user inputs,
and security-related operations.
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Union
from functools import wraps

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number
        
    Returns:
        bool: True if valid port (1-65535)
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_threshold(value: Union[float, str], min_val: float = 0.0, max_val: float = 1.0) -> bool:
    """
    Validate threshold value.
    
    Args:
        value: Threshold value
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        bool: True if valid threshold
    """
    try:
        threshold = float(value)
        return min_val <= threshold <= max_val
    except (ValueError, TypeError):
        return False


def sanitize_string(input_str: str, max_length: int = 255) -> str:
    """
    Sanitize string input for security.
    
    Args:
        input_str: Input string
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized string
    """
    if not isinstance(input_str, str):
        raise ValidationError("Input must be a string")
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';\\]', '', input_str)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_api_request(required_fields: List[str]):
    """
    Decorator to validate API request data.
    
    Args:
        required_fields: List of required field names
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract request data (assumes Flask request)
            try:
                from flask import request
                data = request.get_json() or {}
            except ImportError:
                # Fallback for non-Flask contexts
                data = kwargs.get('data', {})
            
            # Validate required fields
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                raise ValidationError(f"Missing required fields: {missing_fields}")
            
            # Add validated data to kwargs
            kwargs['validated_data'] = data
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_traffic_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate traffic data structure.
    
    Args:
        data: Traffic data dictionary
        
    Returns:
        Dict: Validated traffic data
        
    Raises:
        ValidationError: If data is invalid
    """
    required_fields = ['timestamp', 'size', 'src_port', 'dst_port']
    
    for field in required_fields:
        if field not in data:
            raise ValidationError(f"Missing required field: {field}")
    
    # Validate timestamp
    try:
        timestamp = float(data['timestamp'])
        if timestamp < 0:
            raise ValidationError("Timestamp must be positive")
    except (ValueError, TypeError):
        raise ValidationError("Invalid timestamp format")
    
    # Validate size
    try:
        size = int(data['size'])
        if size < 0 or size > 65535:
            raise ValidationError("Invalid packet size")
    except (ValueError, TypeError):
        raise ValidationError("Invalid size format")
    
    # Validate ports
    if not validate_port(data['src_port']):
        raise ValidationError("Invalid source port")
    if not validate_port(data['dst_port']):
        raise ValidationError("Invalid destination port")
    
    return {
        'timestamp': timestamp,
        'size': size,
        'src_port': int(data['src_port']),
        'dst_port': int(data['dst_port']),
        'protocol': sanitize_string(data.get('protocol', 'TCP'), 10)
    }


def validate_config_value(key: str, value: Any) -> Any:
    """
    Validate configuration values.
    
    Args:
        key: Configuration key
        value: Configuration value
        
    Returns:
        Any: Validated value
        
    Raises:
        ValidationError: If value is invalid
    """
    validators = {
        'WEB_PORT': lambda v: validate_port(v),
        'PROMETHEUS_METRICS_PORT': lambda v: validate_port(v),
        'TIME_WINDOW': lambda v: isinstance(v, (int, float)) and v > 0,
        'HISTORY_WINDOW': lambda v: isinstance(v, (int, float)) and v > 0,
        'REQUEST_THRESHOLD_MULTIPLIER': lambda v: isinstance(v, (int, float)) and v > 0,
        'ANOMALY_THRESHOLD': lambda v: validate_threshold(v),
        'LOG_LEVEL': lambda v: v.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    }
    
    validator = validators.get(key)
    if validator and not validator(value):
        raise ValidationError(f"Invalid value for {key}: {value}")
    
    return value


class RateLimiter:
    """Simple rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed for identifier.
        
        Args:
            identifier: Unique identifier (e.g., IP address)
            
        Returns:
            bool: True if request is allowed
        """
        import time
        
        current_time = time.time()
        
        # Clean old entries
        self.requests = {
            k: v for k, v in self.requests.items()
            if current_time - v['first_request'] < self.window_seconds
        }
        
        if identifier not in self.requests:
            self.requests[identifier] = {
                'count': 1,
                'first_request': current_time
            }
            return True
        
        request_data = self.requests[identifier]
        
        # Reset if window expired
        if current_time - request_data['first_request'] >= self.window_seconds:
            self.requests[identifier] = {
                'count': 1,
                'first_request': current_time
            }
            return True
        
        # Check if under limit
        if request_data['count'] < self.max_requests:
            request_data['count'] += 1
            return True
        
        return False

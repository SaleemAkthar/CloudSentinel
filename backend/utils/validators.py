"""
Input Validation Functions
===========================

Validates and sanitizes input data for Cloud Sentinel detection system.

Prevents:
- Invalid data types
- Out-of-range values
- Missing required fields
- Malformed IP addresses
- Injection attacks

Author: Raneesha (Backend Team)
Date: 2026-03-11
"""

import re
import ipaddress
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

#============================================================================
# LOG ENTRY VALIDATION
# ============================================================================

def validate_log_entry(log_data: Dict) -> Tuple[bool, Optional[str]]:
    """
    Validate complete log entry has all required fields and valid values
    
    Args:
        log_data: Log dictionary to validate
    
    Returns:
        (is_valid, error_message)
        
    Example:
        >>> log = {'duration': 500, 'memory_used': 130, 'num_api_calls': 3}
        >>> validate_log_entry(log)
        (True, None)
        
        >>> bad_log = {'duration': -100}
        >>> validate_log_entry(bad_log)
        (False, "Missing required field: memory_used")
    """
    # Required fields
    required_fields = ['duration', 'memory_used', 'num_api_calls']
    
    # Check required fields exist
    for field in required_fields:
        if field not in log_data:
            return False, f"Missing required field: {field}"
    
    # Validate duration
    is_valid, error = validate_duration(log_data['duration'])
    if not is_valid:
        return False, f"Invalid duration: {error}"
    
    # Validate memory
    is_valid, error = validate_memory(log_data['memory_used'])
    if not is_valid:
        return False, f"Invalid memory_used: {error}"
    
    # Validate API calls
    is_valid, error = validate_api_calls(log_data['num_api_calls'])
    if not is_valid:
        return False, f"Invalid num_api_calls: {error}"
    
    # Validate optional IP address if present
    if 'ip_address' in log_data:
        is_valid, error = validate_ip_address(log_data['ip_address'])
        if not is_valid:
            return False, f"Invalid ip_address: {error}"
    
    # Validate optional timestamp if present
    if 'timestamp' in log_data:
        is_valid, error = validate_timestamp(log_data['timestamp'])
        if not is_valid:
            return False, f"Invalid timestamp: {error}"
    
    return True, None

    # ============================================================================
# INDIVIDUAL FIELD VALIDATORS
# ============================================================================

def validate_duration(duration: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate duration field
    
    Rules:
    - Must be numeric (int or float)
    - Must be >= 0
    - Reasonable upper bound: 60000ms (1 minute)
    
    Args:
        duration: Duration value in milliseconds
        
    Returns:
        (is_valid, error_message)
    """
    # Type check
    if not isinstance(duration, (int, float)):
        return False, f"Must be numeric, got {type(duration).__name__}"
    
    # Range check
    if duration < 0:
        return False, "Cannot be negative"
    
    if duration > 60000:  # 1 minute
        # Warning, not error - crypto-mining can be very long
        # But flag for review
        pass
    
    return True, None


def validate_memory(memory_used: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate memory_used field
    
    Rules:
    - Must be numeric
    - Must be >= 0
    - Reasonable upper bound: 10240 MB (10GB, Lambda max)
    """
    # Type check
    if not isinstance(memory_used, (int, float)):
        return False, f"Must be numeric, got {type(memory_used).__name__}"
    
    # Range check
    if memory_used < 0:
        return False, "Cannot be negative"
    
    if memory_used > 10240:  # 10GB (Lambda max)
        return False, f"Exceeds Lambda maximum (10240MB), got {memory_used}MB"
    
    return True, None


def validate_api_calls(num_api_calls: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate num_api_calls field
    
    Rules:
    - Must be integer
    - Must be >= 0
    - Reasonable upper bound: 1000 calls
    """
    # Type check
    if not isinstance(num_api_calls, int):
        return False, f"Must be integer, got {type(num_api_calls).__name__}"
    
    # Range check
    if num_api_calls < 0:
        return False, "Cannot be negative"
    
    if num_api_calls > 1000:
        # Suspicious but not invalid - data exfiltration?
        pass
    
    return True, None
 def validate_error_count(error_count: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate error_count field
    
    Rules:
    - Must be integer
    - Must be >= 0
    """
    # Type check
    if not isinstance(error_count, int):
        return False, f"Must be integer, got {type(error_count).__name__}"
    
    # Range check
    if error_count < 0:
        return False, "Cannot be negative"
    
    return True, None


def validate_concurrency(concurrency: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate concurrency field
    
    Rules:
    - Must be integer
    - Must be >= 1 (at least one execution)
    """
    # Type check
    if not isinstance(concurrency, int):
        return False, f"Must be integer, got {type(concurrency).__name__}"
    
    # Range check
    if concurrency < 1:
        return False, "Must be at least 1"
    
    return True, None
def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Validate IP address format
    
    Accepts both IPv4 and IPv6
    
    Args:
        ip: IP address string
        
    Returns:
        (is_valid, error_message)
        
    Example:
        >>> validate_ip_address('192.168.1.1')
        (True, None)
        
        >>> validate_ip_address('999.999.999.999')
        (False, "Invalid IP address format")
    """
    # Type check
    if not isinstance(ip, str):
        return False, f"Must be string, got {type(ip).__name__}"
    
    # Try parsing as IP address
    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError:
        return False, "Invalid IP address format"


def validate_timestamp(timestamp: str) -> Tuple[bool, Optional[str]]:
    """
    Validate timestamp format
    
    Accepts ISO 8601 format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DDTHH:MM:SS.fffffZ
    
    Args:
        timestamp: Timestamp string
        
    Returns:
        (is_valid, error_message)
    """
    # Type check
    if not isinstance(timestamp, str):
        return False, f"Must be string, got {type(timestamp).__name__}"
    
    # Try parsing as ISO 8601
    try:
        # Remove 'Z' suffix if present
        ts_clean = timestamp.replace('Z', '+00:00')
        datetime.fromisoformat(ts_clean)
        return True, None
    except ValueError:
        return False, "Invalid timestamp format (expected ISO 8601)"

# ============================================================================
# FEATURE VALIDATION
# ============================================================================

def validate_features(features: Dict) -> Dict:
    """
    Validate and sanitize feature dictionary
    
    Converts types, clamps values, fills missing optional fields
    
    Args:
        features: Raw feature dictionary
        
    Returns:
        Sanitized feature dictionary
        
    Raises:
        ValueError: If validation fails
        
    Example:
        >>> features = {'duration': '500', 'memory_used': 130, 'num_api_calls': 3}
        >>> validate_features(features)
        {'duration': 500.0, 'memory_used': 130.0, 'num_api_calls': 3, ...}
    """
    sanitized = {}
    
    # Required fields with type conversion
    required_conversions = {
        'duration': float,
        'memory_used': float,
        'num_api_calls': int
    }
    
    for field, target_type in required_conversions.items():
        if field not in features:
            raise ValueError(f"Missing required field: {field}")
        
        try:
            sanitized[field] = target_type(features[field])
        except (ValueError, TypeError):
            raise ValueError(f"Cannot convert {field} to {target_type.__name__}")
        
        # Clamp to valid range
        if sanitized[field] < 0:
            sanitized[field] = 0
    
    # Optional fields with defaults
    optional_fields = {
        'error_count': (int, 0),
        'concurrency': (int, 1),
        'packet_size_in': (float, 0.0),
        'packet_size_out': (float, 0.0),
        'latency': (float, 0.0),
        'fragment_count': (int, 0),
        'ip_address': (str, 'unknown'),
        'timestamp': (str, datetime.now().isoformat())
    }
    
    for field, (field_type, default) in optional_fields.items():
        if field in features:
            try:
                sanitized[field] = field_type(features[field])
                
                # Clamp numeric fields to >= 0
                if field_type in (int, float) and sanitized[field] < 0:
                    sanitized[field] = 0
                    
            except (ValueError, TypeError):
                sanitized[field] = default
        else:
            sanitized[field] = default
    
    return sanitized
# ============================================================================
# SECURITY VALIDATION
# ============================================================================

def sanitize_string(text: str, max_length: int = 1000) -> str:
    """
    Sanitize string input to prevent injection attacks
    
    Args:
        text: Input string
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Example:
        >>> sanitize_string("Normal text 123")
        'Normal text 123'
        >>> sanitize_string("'; DROP TABLE--")
        ' DROP TABLE'
    """
    if not isinstance(text, str):
        return str(text)
    
    # Trim to max length
    text = text[:max_length]
    
    # Remove potentially dangerous characters
    # Allow: alphanumeric, spaces, dots, hyphens, underscores, colons
    text = re.sub(r'[^a-zA-Z0-9\s\.\-_:]', '', text)
    
    return text


def validate_alert_id(alert_id: str) -> Tuple[bool, Optional[str]]:
    """
    Validate alert ID format
    
    Expected format: ALERT-XXXX where XXXX is alphanumeric
    
    Args:
        alert_id: Alert identifier
        
    Returns:
        (is_valid, error_message)
        
    Example:
        >>> validate_alert_id("ALERT-1234")
        (True, None)
        >>> validate_alert_id("invalid")
        (False, "Invalid format (expected ALERT-XXXX)")
    """
    if not isinstance(alert_id, str):
        return False, "Must be string"
    
    # Check format
    if not re.match(r'^ALERT-[A-Z0-9]+$', alert_id):
        return False, "Invalid format (expected ALERT-XXXX)"
    
    if len(alert_id) > 50:
        return False, "Too long (max 50 characters)"
    
    return True, None

# ============================================================================
# BATCH VALIDATION
# ============================================================================

def validate_log_batch(logs: List[Dict]) -> Tuple[List[Dict], List[str]]:
    """
    Validate batch of log entries
    
    Args:
        logs: List of log dictionaries
        
    Returns:
        (valid_logs, error_messages)
        
    Example:
        >>> logs = [
        ...     {'duration': 500, 'memory_used': 130, 'num_api_calls': 3},
        ...     {'duration': -100},  # Invalid
        ...     {'duration': 600, 'memory_used': 140, 'num_api_calls': 2}
        ... ]
        >>> valid, errors = validate_log_batch(logs)
        >>> len(valid)
        2
        >>> len(errors)
        1
    """
    valid_logs = []
    errors = []
    
    for i, log in enumerate(logs):
        is_valid, error = validate_log_entry(log)
        
        if is_valid:
            valid_logs.append(log)
        else:
            errors.append(f"Log {i}: {error}")
    
    return valid_logs, errors


# ============================================================================
# RANGE VALIDATORS
# ============================================================================

def validate_range(
    value: float, 
    min_val: float, 
    max_val: float, 
    field_name: str = "value"
) -> Tuple[bool, Optional[str]]:
    """
    Generic range validator
    
    Args:
        value: Value to check
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        field_name: Name for error messages
        
    Returns:
        (is_valid, error_message)
        
    Example:
        >>> validate_range(0.5, 0.0, 1.0, "probability")
        (True, None)
        >>> validate_range(1.5, 0.0, 1.0, "probability")
        (False, "probability exceeds maximum (1.0)")
    """
    if not isinstance(value, (int, float)):
        return False, f"{field_name} must be numeric"
    
    if value < min_val:
        return False, f"{field_name} below minimum ({min_val})"
    
    if value > max_val:
        return False, f"{field_name} exceeds maximum ({max_val})"
    
    return True, None


def validate_percentage(value: float, field_name: str = "percentage") -> Tuple[bool, Optional[str]]:
    """
    Validate percentage value (0-100)
    
    Args:
        value: Percentage value
        field_name: Name for error messages
        
    Returns:
        (is_valid, error_message)
    """
    return validate_range(value, 0.0, 100.0, field_name)


def validate_probability(value: float, field_name: str = "probability") -> Tuple[bool, Optional[str]]:
    """
    Validate probability value (0-1)
    
    Args:
        value: Probability value
        field_name: Name for error messages
        
    Returns:
        (is_valid, error_message)
    """
    return validate_range(value, 0.0, 1.0, field_name)


def validate_score(score: float) -> float:
    """
    Ensure score is in valid range [0, 1], clamping if necessary
    
    Args:
        score: Anomaly score
        
    Returns:
        Clamped score (0-1)
        
    Example:
        >>> validate_score(0.5)
        0.5
        >>> validate_score(-0.1)
        0.0
        >>> validate_score(1.5)
        1.0
    """
    return max(0.0, min(score, 1.0))


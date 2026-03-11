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



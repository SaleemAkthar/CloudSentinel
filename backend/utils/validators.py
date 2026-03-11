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



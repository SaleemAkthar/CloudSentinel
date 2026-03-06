"""
General Helper Utilities — Cloud Sentinel
==========================================
Shared utility functions used across the backend, primarily by the
Layer 2 Investigator and Network Analyzer.

Author: Okitha (Backend Team)
"""

import math
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter


# ============================================================================
# SECTION 1: TIMESTAMP UTILITIES
# ============================================================================

def format_timestamp(timestamp) -> Optional[datetime]:
    """
    Parse a timestamp from multiple possible formats into a datetime object.
    Supports ISO 8601 strings, Unix epoch floats/ints, or datetime objects.
    Returns None if parsing fails.
    """
    if isinstance(timestamp, datetime):
        return timestamp
    if isinstance(timestamp, (int, float)):
        try:
            return datetime.utcfromtimestamp(timestamp)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(timestamp, str):
        ts = timestamp.rstrip("Z")
        for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
    return None


def time_diff_seconds(ts1, ts2) -> float:
    """Return the absolute difference in seconds between two timestamps."""
    dt1 = format_timestamp(ts1)
    dt2 = format_timestamp(ts2)
    if dt1 is None or dt2 is None:
        return 0.0
    return abs((dt2 - dt1).total_seconds())


# ============================================================================
# SECTION 2: GEOLOCATION UTILITIES
# ============================================================================

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate great-circle distance between two coordinates (km) using Haversine.

    Example:
        >>> calculate_distance(51.5074, -0.1278, 40.7128, -74.0060)
        5570.2  # London to New York (approx)
    """
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (math.sin(d_phi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def is_geolocation_jump_suspicious(distance_km: float, time_diff_sec: float,
                                   max_speed_kmh: float = 900.0) -> bool:
    """
    Return True if movement between two locations is faster than max_speed_kmh.
    Default 900 km/h (commercial aircraft) — anything faster is flagged.
    """
    if time_diff_sec <= 0:
        return distance_km > 0
    return (distance_km / (time_diff_sec / 3600.0)) > max_speed_kmh


# ============================================================================
# SECTION 3: IP ADDRESS UTILITIES
# ============================================================================

def parse_ip_address(ip_str: str) -> Dict:
    """
    Parse and classify an IP address string.
    Returns dict with: valid, version, is_private, is_loopback, is_multicast, address.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return {
            "valid": True,
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
            "address": str(ip_obj),
        }
    except ValueError:
        return {"valid": False, "version": None, "is_private": False,
                "is_loopback": False, "is_multicast": False, "address": ip_str}


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP falls in an RFC-1918 private range."""
    return parse_ip_address(ip_str).get("is_private", False)


# ============================================================================
# SECTION 4: ENTROPY
# ============================================================================

def calculate_entropy(data: List) -> float:
    """
    Calculate Shannon entropy of a list of values (in bits).
    Higher = more diverse (normal). Lower = repetitive (DDoS indicator).

    Formula: H = -sum(p_i * log2(p_i))
    """
    if not data or len(data) < 2:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


# ============================================================================
# SECTION 5: SAFE ARITHMETIC
# ============================================================================

def safe_divide(a: float, b: float, default: float = 0.0) -> float:
    """Divide a by b, returning default when b is zero or near-zero."""
    return a / b if abs(b) >= 1e-10 else default


def clamp(value: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Clamp a value to [min_val, max_val]."""
    return max(min_val, min(max_val, value))


# ============================================================================
# SECTION 6: MISC
# ============================================================================

def truncate(text: str, max_len: int = 100) -> str:
    """Truncate a string to max_len characters, appending ellipsis if cut."""
    return text if len(text) <= max_len else text[:max_len - 1] + "…"


def is_valid_user_agent(ua: str) -> bool:
    """Flag empty or suspiciously short User-Agent strings (bot indicator)."""
    return bool(ua and len(ua.strip()) >= 10)
"""
Network Analyzer Models — Cloud Sentinel
==========================================
Pydantic models for representing network topology and routing analysis
returned by the Layer 2 network topology module.
"""
 
from pydantic import BaseModel
from typing import Optional, List
 
 
class NetworkHop(BaseModel):
    """Represents a single hop in the network routing path."""
    hop_number: int              # Position in the routing path (1 = first hop)
    ip_address: str              # IP address of this hop
    provider: Optional[str]      # Network provider name, e.g. "Amazon AWS"
    country: Optional[str]       # Country code, e.g. "US"
    latency_ms: Optional[float]  # Estimated latency contribution at this hop

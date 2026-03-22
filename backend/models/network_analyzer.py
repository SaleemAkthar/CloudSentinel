"""
Network Analyzer Models — Cloud Sentinel

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
 
 
class NetworkAnalysis(BaseModel):
    """
    Full network topology analysis for a single Lambda execution event.
    Produced by network_topology.py and stored inside an alert's layer2_report.
    """
    source_ip: str                           # Originating IP address
    destination_region: str                  # AWS region receiving the request
    hop_count: int                           # Total number of hops in the path
    hops: List[NetworkHop]                   # Ordered list of routing hops
    transit_providers: List[str]             # Distinct ISPs/providers in the path

 
    # Risk signals derived from routing behaviour
    crosses_high_risk_country: bool          # True if path routes through a flagged country
    uses_tor_or_vpn: bool                    # True if a Tor exit node or known VPN detected
    asymmetric_routing: bool                 # True if return path differs significantly
    routing_anomaly_score: float             # 0.0 – 1.0; higher = more suspicious routing
 
    # Summary
    risk_level: str                          # "low", "medium", "high", "critical"
    notes: Optional[str] = None             # Free-text explanation of any anomalies found

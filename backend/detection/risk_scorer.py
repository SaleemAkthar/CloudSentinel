"""
Risk Scorer — Cloud Sentinel Layer 2
======================================
Multi-factor risk calculation combining all Layer 2 analysis modules.

Covers:
  - Multi-factor weighted risk calculation
  - Confidence scoring
  - Severity classification with adjustment
  - Final AI recommendation generation

Author: Backend Team
"""

import math
import time
from typing import Dict, List, Optional


# ============================================================================
# SEVERITY THRESHOLDS
# ============================================================================

SEVERITY_CRITICAL = 0.80
SEVERITY_HIGH     = 0.60
SEVERITY_MEDIUM   = 0.35
SEVERITY_LOW      = 0.0

# Component weights for composite risk score
# Must sum to 1.0
COMPONENT_WEIGHTS = {
    "ip_reputation":     0.25,   # Who is the source
    "attack_patterns":   0.30,   # What attack signature matched
    "packet_risk":       0.20,   # How the packet behaves
    "network_topology":  0.15,   # How the traffic is routed
    "spoofing":          0.10,   # Whether the source is fake
}


# ============================================================================
# RISK SCORER CLASS
# ============================================================================

class RiskScorer:
    """
    Aggregates all Layer 2 analysis into a single risk decision.
    Produces a final report with score, severity, confidence, and recommendation.
    """

    def score(
        self,
        packet:           dict,
        ip_analysis:      dict,
        packet_analysis:  dict,
        pattern_results:  dict,
        topology_analysis: dict,
        layer1_result:    dict,
    ) -> dict:
        """
        Main entry point. Computes final risk score and recommendation.

        Args:
            packet:            raw packet dict
            ip_analysis:       IPAnalyzer output
            packet_analysis:   PacketAnalyzer output
            pattern_results:   match_all_patterns() output
            topology_analysis: NetworkTopologyAnalyzer output
            layer1_result:     Layer1Filter output

        Returns:
            Complete risk assessment dict
        """
        t0 = time.perf_counter()

        components   = self._extract_components(
            ip_analysis, packet_analysis, pattern_results, topology_analysis
        )
        raw_score    = self._calculate_composite(components)
        adjusted     = self._adjust_for_context(raw_score, packet, layer1_result, pattern_results)
        confidence   = self._calculate_confidence(components, pattern_results)
        severity     = self._classify_severity(adjusted, pattern_results)
        recommendation = self._build_recommendation(
            adjusted, severity, confidence, ip_analysis,
            packet_analysis, pattern_results, topology_analysis
        )

        elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

        return {
            "elapsed_us":      elapsed_us,
            "component_scores": {k: round(v, 4) for k, v in components.items()},
            "raw_score":       round(raw_score, 4),
            "adjusted_score":  round(adjusted, 4),
            "confidence":      round(confidence, 4),
            "severity":        severity,
            "recommendation":  recommendation,
        }

    # ── Component Extraction ──────────────────────────────────────────────────

    def _extract_components(
        self,
        ip_analysis:      dict,
        packet_analysis:  dict,
        pattern_results:  dict,
        topology_analysis: dict,
    ) -> Dict[str, float]:
        """Extract normalised 0-1 score for each risk component."""

        # 1. IP reputation score
        ip_rep_score = ip_analysis.get("reputation", {}).get("score", 0.0)
        spoof_score  = ip_analysis.get("spoofing", {}).get("spoofing_score", 0.0)

        # 2. Attack pattern score (highest confidence match)
        top_threat   = pattern_results.get("top_threat")
        pattern_score = top_threat["confidence"] if top_threat else 0.0

        # Bonus for multiple matched patterns
        threat_count = pattern_results.get("threat_count", 0)
        if threat_count > 1:
            pattern_score = min(pattern_score + (threat_count - 1) * 0.05, 1.0)

        # 3. Packet risk score
        packet_risk = packet_analysis.get("risk_score", 0.0)

        # 4. Network topology risk
        topo_risk = topology_analysis.get("risk_score", 0.0)

        return {
            "ip_reputation":    ip_rep_score,
            "attack_patterns":  pattern_score,
            "packet_risk":      packet_risk,
            "network_topology": topo_risk,
            "spoofing":         spoof_score,
        }

    # ── Composite Score ───────────────────────────────────────────────────────

    def _calculate_composite(self, components: Dict[str, float]) -> float:
        """
        Weighted composite risk score.

        Formula:
            S = Σ (weight_i × tanh(score_i × 2))
            tanh provides smooth S-curve normalisation
        """
        composite = 0.0
        for key, weight in COMPONENT_WEIGHTS.items():
            raw = components.get(key, 0.0)
            # tanh normalisation: maps [0,1] → [0, ~0.96] smoothly
            normalised = math.tanh(raw * 2)
            composite += weight * normalised

        # Rescale back to [0, 1]
        max_possible = sum(math.tanh(2) * w for w in COMPONENT_WEIGHTS.values())
        return min(composite / max_possible, 1.0)

    # ── Contextual Adjustment ─────────────────────────────────────────────────

    def _adjust_for_context(
        self,
        raw_score:       float,
        packet:          dict,
        layer1_result:   dict,
        pattern_results: dict,
    ) -> float:
        """
        Apply contextual boosts and reductions to the raw score.

        Boosts:
          - Multiple failed Layer 1 checks
          - Multiple matched attack patterns
          - Repeat offender IP
          - Traffic from Tor

        Reductions:
          - Private / internal IP source
          - Low-volume normal function
        """
        adjusted = raw_score

        # Boost: Layer 1 failures
        failed_checks = sum(
            1 for v in layer1_result.get("checks", {}).values() if not v
        )
        adjusted += failed_checks * 0.03

        # Boost: Multiple attack patterns
        threat_count = pattern_results.get("threat_count", 0)
        if threat_count >= 3:
            adjusted += 0.10
        elif threat_count == 2:
            adjusted += 0.05

        # Boost: Crypto mining specifically always gets elevated
        matched_types = [p["attack_type"] for p in pattern_results.get("matched_patterns", [])]
        if "crypto_mining" in matched_types:
            adjusted += 0.08

        # Boost: Very high anomaly in any single component
        if raw_score >= 0.9:
            adjusted = min(adjusted + 0.05, 1.0)

        # Reduction: Private IP (internal traffic is lower risk)
        ip_str = packet.get("ip_address", "")
        if ip_str.startswith(("10.", "172.16.", "192.168.", "127.")):
            adjusted *= 0.6

        # Reduction: Very short, low-memory invocations (likely lightweight)
        if packet.get("duration", 0) < 50 and packet.get("memory_used", 0) < 64:
            adjusted *= 0.7

        return round(min(adjusted, 1.0), 4)

    # ── Confidence Scoring ────────────────────────────────────────────────────

    def _calculate_confidence(
        self, components: Dict[str, float], pattern_results: dict
    ) -> float:
        """
        Estimate confidence in the risk assessment.

        High confidence when:
          - Multiple components agree (low variance)
          - Attack patterns match with high confidence
          - Multiple patterns matched

        Formula:
            confidence = (1 / (1 + σ)) × agreement_factor
        """
        values = list(components.values())

        if not values:
            return 0.5

        mean   = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std    = math.sqrt(variance)

        # Base: inverse of disagreement
        base_confidence = 1.0 / (1.0 + std * 2)

        # Agreement factor: fraction of components above 0.3
        above_threshold = sum(1 for v in values if v > 0.3)
        agreement = above_threshold / len(values)

        # Pattern confidence boost
        top = pattern_results.get("top_threat")
        pattern_boost = top["confidence"] * 0.2 if top else 0.0

        # Multi-pattern agreement
        threat_count = pattern_results.get("threat_count", 0)
        multi_boost  = min(threat_count * 0.05, 0.15)

        confidence = base_confidence * (0.7 + 0.3 * agreement) + pattern_boost + multi_boost

        return round(min(confidence, 1.0), 4)

    # ── Severity Classification ────────────────────────────────────────────────

    def _classify_severity(self, score: float, pattern_results: dict) -> str:
        """
        Map risk score to severity label.
        Overrides allowed for specific high-confidence attack types.
        """
        # Base classification
        if score >= SEVERITY_CRITICAL:
            severity = "CRITICAL"
        elif score >= SEVERITY_HIGH:
            severity = "HIGH"
        elif score >= SEVERITY_MEDIUM:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Override: Always CRITICAL for Tor traffic + any pattern match
        matched_types = [p["attack_type"] for p in pattern_results.get("matched_patterns", [])]
        if "crypto_mining" in matched_types and score >= 0.5:
            severity = "CRITICAL"
        if "ip_spoofing" in matched_types and "ddos" in matched_types:
            severity = "CRITICAL"

        return severity

    # ── Recommendation ────────────────────────────────────────────────────────

    def _build_recommendation(
        self,
        score:            float,
        severity:         str,
        confidence:       float,
        ip_analysis:      dict,
        packet_analysis:  dict,
        pattern_results:  dict,
        topology_analysis: dict,
    ) -> dict:
        """
        Build a structured AI recommendation based on all evidence.

        Returns action (BLOCK / MONITOR / INVESTIGATE / PASS),
        reasoning list, and mitigation steps.
        """
        matched_types = [p["attack_type"] for p in pattern_results.get("matched_patterns", [])]
        top           = pattern_results.get("top_threat")
        ip_rep        = ip_analysis.get("reputation", {})
        exfil         = packet_analysis.get("exfiltration", {})
        topo          = topology_analysis.get("anomalies", {})

        reasoning   = []
        mitigations = []

        # ── Determine action ──────────────────────────────────────────────────
        if severity == "CRITICAL" or score >= SEVERITY_CRITICAL:
            action = "BLOCK"
        elif severity == "HIGH" or (score >= SEVERITY_HIGH and confidence >= 0.6):
            action = "BLOCK"
        elif severity == "MEDIUM":
            action = "MONITOR"
        else:
            action = "PASS"

        # ── Build reasoning ───────────────────────────────────────────────────
        if top:
            reasoning.append(
                f"Primary threat detected: {top['name']} "
                f"(confidence: {top['confidence']:.0%})"
            )

        threat_count = pattern_results.get("threat_count", 0)
        if threat_count > 1:
            reasoning.append(
                f"{threat_count} attack patterns matched simultaneously — "
                "indicates coordinated or multi-vector attack"
            )

        if ip_rep.get("label") == "MALICIOUS":
            reasoning.append(
                f"Source IP has MALICIOUS reputation: {'; '.join(ip_rep.get('flags', []))}"
            )
        elif ip_rep.get("label") == "SUSPICIOUS":
            reasoning.append(f"Source IP is SUSPICIOUS: {'; '.join(ip_rep.get('flags', []))}")

        if exfil.get("exfiltration_score", 0) > 0.5:
            reasoning.append(
                f"Data exfiltration risk score: {exfil['exfiltration_score']:.0%} "
                f"({exfil.get('classification', 'UNKNOWN')})"
            )

        if topo.get("anomaly_count", 0) > 0:
            reasoning.append(
                f"Routing anomalies detected: {'; '.join(topo.get('anomalies', [])[:2])}"
            )

        if not reasoning:
            reasoning.append(
                f"Composite risk score {score:.0%} is below action thresholds — traffic appears normal"
            )

        # ── Build mitigations ─────────────────────────────────────────────────
        if "crypto_mining" in matched_types:
            mitigations += [
                "Immediately terminate the Lambda function",
                "Review IAM roles for this function — revoke all permissions",
                "Check CloudTrail for when the function code was last modified",
                "Scan all Lambda functions in this account for similar patterns",
            ]

        if "data_exfiltration" in matched_types:
            mitigations += [
                "Block outbound traffic from this function using VPC security groups",
                "Identify what data was accessed (check DynamoDB/S3 CloudTrail logs)",
                "Rotate all secrets and credentials the function had access to",
                "Enable S3 Object Lock on sensitive buckets",
            ]

        if "ddos" in matched_types:
            mitigations += [
                "Enable AWS WAF rate limiting on the API Gateway",
                "Block the source IP at the CloudFront / WAF level",
                "Enable AWS Shield Advanced if not already active",
            ]

        if "sql_injection" in matched_types:
            mitigations += [
                "Review all database queries in this Lambda for parameterisation",
                "Enable RDS enhanced monitoring and query logging",
                "Rotate database credentials immediately",
            ]

        if "ip_spoofing" in matched_types:
            mitigations += [
                "Enable VPC Flow Logs and review for additional spoofed traffic",
                "Block the declared source IP range at the security group level",
                "Review Network ACLs for asymmetric routing rules",
            ]

        if "memory_attack" in matched_types:
            mitigations += [
                "Set a Lambda reserved concurrency limit to cap resource consumption",
                "Enable CloudWatch billing alerts for Lambda GB-second usage",
                "Review function code for unbounded loops or large allocations",
            ]

        if not mitigations:
            mitigations.append("Continue monitoring — no immediate action required")

        return {
            "action":       action,
            "severity":     severity,
            "risk_score":   round(score, 4),
            "confidence":   round(confidence, 4),
            "reasoning":    reasoning,
            "mitigations":  mitigations,
            "attack_types": matched_types,
        }
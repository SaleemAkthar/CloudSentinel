"""
Cloud Sentinel — Unified Detection Pipeline
=============================================
Single entry point that runs every stage in the correct order:

  1. SARIMA        — get dynamic thresholds + temporal context
  2. Layer 1       — fast gate using SARIMA-adjusted thresholds
  3. Layer 2       — deep forensic scan (only if Layer 1 fails)
  4. AI Model      — final anomaly decision using all evidence

Output:  ALLOW / INVESTIGATE / BLOCK  + full evidence report

Author: Backend Team
"""

import time
import uuid
import datetime
from typing import Optional, Tuple

from backend.detection.layer1_filter    import Layer1Filter
from backend.detection.layer2_scanner  import Layer2Scanner
from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.detection.layer1_scorer   import Layer1Scorer


# ============================================================================
# SARIMA THRESHOLD ADAPTER
# Converts SARIMA predictions into dynamic Layer 1 thresholds
# ============================================================================

class SARIMAThresholdAdapter:
    """
    Converts SARIMA time-series predictions into dynamic thresholds
    for Layer 1 and temporal context for Layer 2.

    Peak hours  → relaxed thresholds (traffic is naturally higher)
    Off-peak    → tighter thresholds (any spike is more suspicious)
    """

    # Base thresholds (same as Layer1Filter defaults)
    BASE_DURATION_MAX   = 3000    # ms
    BASE_SIZE_MAX       = 65535   # bytes
    BASE_TTL_MIN        = 30
    BASE_TTL_MAX        = 128

    # How much to relax thresholds during peak hours (multipliers)
    PEAK_DURATION_MULT  = 1.8     # allow up to 1.8x longer during peak
    PEAK_SIZE_MULT      = 1.5
    OFFPEAK_DURATION_MULT = 0.7   # tighten to 0.7x during off-peak

    def get_layer1_thresholds(self, sarima: SARIMAForecaster) -> dict:
        """
        Return dynamic Layer 1 thresholds adjusted for current time window.
        """
        now          = datetime.datetime.utcnow()
        hour         = now.hour
        is_peak      = self._is_peak_hour(hour)
        prediction   = sarima.predict()

        predicted_duration = prediction["value"]
        pred_std           = prediction["std"]

        # If SARIMA is trained, use predicted duration to set threshold
        # threshold = predicted_mean + 3*std (covers 99.7% of normal traffic)
        if sarima._trained and predicted_duration > 0:
            dynamic_duration = predicted_duration + (3 * pred_std)
            # Apply peak/off-peak multiplier on top
            mult = self.PEAK_DURATION_MULT if is_peak else self.OFFPEAK_DURATION_MULT
            duration_max = max(dynamic_duration * mult, self.BASE_DURATION_MAX)
        else:
            # Not trained yet — use base with peak multiplier only
            mult = self.PEAK_DURATION_MULT if is_peak else 1.0
            duration_max = self.BASE_DURATION_MAX * mult

        return {
            "ttl_min":      self.BASE_TTL_MIN,
            "ttl_max":      self.BASE_TTL_MAX,
            "size_max":     int(self.BASE_SIZE_MAX * (self.PEAK_SIZE_MULT if is_peak else 1.0)),
            "duration_max": round(duration_max, 1),
            "is_peak_hour": is_peak,
            "hour":         hour,
            "sarima_trained": sarima._trained,
            "predicted_duration": round(predicted_duration, 2),
            "predicted_std":      round(pred_std, 2),
        }

    def get_temporal_context(
        self,
        sarima: SARIMAForecaster,
        actual_duration: float,
    ) -> dict:
        """
        Return temporal context for Layer 2 risk scorer.
        Shows how anomalous this packet is relative to the current time window.
        """
        temporal_score = sarima.detect_temporal_anomaly(actual_duration)
        prediction     = sarima.predict()
        now            = datetime.datetime.utcnow()
        is_peak        = self._is_peak_hour(now.hour)

        expected = prediction["value"] if prediction["value"] > 0 else actual_duration
        ratio    = actual_duration / max(expected, 1.0)

        # Off-peak attacks get a risk boost — more suspicious at quiet times
        offpeak_boost = 0.15 if (not is_peak and temporal_score > 0.5) else 0.0

        return {
            "temporal_anomaly_score":  round(temporal_score, 4),
            "temporal_risk_adjustment": round(
                min(temporal_score * 0.25 + offpeak_boost, 0.40), 4
            ),
            "expected_duration":       round(expected, 2),
            "actual_duration":         actual_duration,
            "actual_vs_expected_ratio": round(ratio, 2),
            "is_peak_hour":            is_peak,
            "is_off_peak_attack":      not is_peak and temporal_score > 0.5,
            "time_window":             self._get_time_window(now.hour),
        }

    def _is_peak_hour(self, hour: int) -> bool:
        """Peak hours: weekday 8am–8pm UTC."""
        return 8 <= hour <= 20

    def _get_time_window(self, hour: int) -> str:
        if   0  <= hour < 6:  return "night"
        elif 6  <= hour < 8:  return "early_morning"
        elif 8  <= hour < 12: return "morning_peak"
        elif 12 <= hour < 14: return "midday_peak"
        elif 14 <= hour < 18: return "afternoon_peak"
        elif 18 <= hour < 20: return "evening_peak"
        elif 20 <= hour < 22: return "evening"
        else:                  return "late_night"


# ============================================================================
# PIPELINE
# ============================================================================

# Module-level singletons — instantiated once, reused across all requests
_layer1_filter   = Layer1Filter()
_layer2_scanner  = Layer2Scanner()
_sarima          = SARIMAForecaster()
_ai_model        = Layer1Scorer(learning_window=100)
_threshold_adapter = SARIMAThresholdAdapter()


class CloudSentinelPipeline:
    """
    Unified detection pipeline.

    Usage:
        pipeline = CloudSentinelPipeline()
        result   = pipeline.process(packet)
        # result["decision"] → "ALLOW" | "INVESTIGATE" | "BLOCK"
    """

    def process(self, packet: dict) -> dict:
        """
        Run the full pipeline on a single packet.

        Pipeline stages:
          1. SARIMA    → dynamic thresholds + temporal context
          2. Layer 1   → fast gate with SARIMA-adjusted thresholds
          3. Layer 2   → deep scan (only if Layer 1 fails)
          4. AI Model  → final ALLOW / INVESTIGATE / BLOCK decision

        Args:
            packet: Lambda execution metadata dict

        Returns:
            Full pipeline result with decision + evidence
        """
        t0          = time.perf_counter()
        pipeline_id = f"CS-{uuid.uuid4().hex[:10].upper()}"
        timestamp   = datetime.datetime.utcnow().isoformat() + "Z"

        stages = {}

        # ── STAGE 1: SARIMA ───────────────────────────────────────────────────
        sarima_thresholds = _threshold_adapter.get_layer1_thresholds(_sarima)
        temporal_context  = _threshold_adapter.get_temporal_context(
            _sarima, packet.get("duration", 0)
        )
        _sarima.add_data_point(
            packet.get("duration", 0),
            timestamp,
        )

        stages["sarima"] = {
            "thresholds":       sarima_thresholds,
            "temporal_context": temporal_context,
        }

        # ── STAGE 2A: LAYER 1 SCORER (AI scoring — runs first) ──────────────
        # Feeds every packet into the AI model to keep baseline updated.
        # During learning phase: just collects data, no anomaly decision.
        # After learning:        calculates Z-scores + weighted composite.
        scorer_features  = self._extract_scorer_features(packet)
        l1_score, l1_score_details = _ai_model.process_log(scorer_features)
        stages["layer1_scorer"] = {
            "score":   round(l1_score, 4),
            "details": l1_score_details,
        }

        scorer_is_anomaly = (
            l1_score_details.get("phase") != "learning"
            and l1_score_details.get("is_anomaly", False)
        )
        scorer_learning = l1_score_details.get("phase") == "learning"

        # ── STAGE 2B: LAYER 1 FILTER (hard rules — runs after scorer) ────────
        # Always runs regardless of scorer result.
        # Specifically catches DDoS (API call rate), IP spoofing,
        # data exfiltration (outbound ratio), and fragmentation attacks.
        # SARIMA provides dynamic duration threshold.
        dynamic_l1 = Layer1Filter(
            ttl_min         = sarima_thresholds["ttl_min"],
            ttl_max         = sarima_thresholds["ttl_max"],
            size_max        = sarima_thresholds["size_max"],
            duration_max_ms = sarima_thresholds["duration_max"],
        )
        l1_filter_result = dynamic_l1.check(packet)
        stages["layer1_filter"] = l1_filter_result

        filter_has_violations = not l1_filter_result["pass"]

        # Combined Layer 1 result
        # ALLOW only if: filter clean AND (scorer says normal OR still learning)
        # FAIL  if:      filter has violations OR scorer found anomaly
        l1_pass = (not filter_has_violations) and (not scorer_is_anomaly)

        l1_result = {
            "pass":              l1_pass,
            "scorer_anomaly":    scorer_is_anomaly,
            "scorer_learning":   scorer_learning,
            "filter_violations": l1_filter_result["violations"],
            "filter_passed":     l1_filter_result["pass"],
            "l1_score":          round(l1_score, 4),
            "filter_result":     l1_filter_result,
            "scorer_result":     l1_score_details,
        }
        stages["layer1"] = l1_result

        # ALLOW immediately if Layer 1 passes
        if l1_pass:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
            return self._build_result(
                pipeline_id = pipeline_id,
                timestamp   = timestamp,
                decision    = "ALLOW",
                confidence  = 0.95,
                severity    = "MEDIUM",
                stages      = stages,
                elapsed_ms  = elapsed_ms,
                stopped_at  = "layer1",
                reason      = "Passed Layer 1 scorer and filter — normal traffic",
            )

        # ── STAGE 3: LAYER 2 ─────────────────────────────────────────────────
        # Inject temporal context so risk scorer can use it
        packet["_temporal_context"] = temporal_context

        l2_result = _layer2_scanner.scan(packet, l1_result)
        stages["layer2"] = l2_result

        # ── STAGE 4: AI MODEL ─────────────────────────────────────────────────
        ai_features = self._extract_ai_features(packet, l1_result, l2_result, temporal_context)
        ai_score, ai_details = _ai_model.process_log(ai_features)
        stages["ai_model"] = {
            "score":    round(ai_score, 4),
            "details":  ai_details,
        }

        # ── FINAL DECISION ───────────────────────────────────────────────────
        decision, confidence = self._make_final_decision(
            ai_score     = ai_score,
            ai_details   = ai_details,
            l2_result    = l2_result,
            temporal     = temporal_context,
        )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return self._build_result(
            pipeline_id = pipeline_id,
            timestamp   = timestamp,
            decision    = decision,
            confidence  = confidence,
            severity    = l2_result.get("severity", "MEDIUM"),
            stages      = stages,
            elapsed_ms  = elapsed_ms,
            stopped_at  = "ai_model",
            reason      = self._build_reason(decision, ai_details, l2_result),
        )

    # ── Feed AI model (learning only, no decision) ────────────────────────────

    # ── Extract features for Layer 1 Scorer ───────────────────────────

    def _extract_scorer_features(self, packet: dict) -> dict:
        """Minimal features for Layer1Scorer baseline learning."""
        return {
            "duration":        packet.get("duration", 0),
            "memory_used":     packet.get("memory_used", 0),
            "num_api_calls":   packet.get("num_api_calls", 0),
            "error_count":     packet.get("error_count", 0),
            "concurrency":     1,
            "packet_size_in":  packet.get("packet_size_in", 512),
            "packet_size_out": packet.get("packet_size_out", 0),
            "latency":         packet.get("network_latency", 0),
            "fragment_count":  packet.get("fragment_count", 0),
            "ip_address":      packet.get("ip_address", ""),
            "timestamp":       datetime.datetime.utcnow().isoformat(),
        }

    def _feed_ai_model(self, packet: dict, is_training_only: bool = False):
        """Feed normal packets into the AI model to keep the baseline updated."""
        features = {
            "duration":       packet.get("duration", 0),
            "memory_used":    packet.get("memory_used", 0),
            "num_api_calls":  packet.get("num_api_calls", 0),
            "error_count":    packet.get("error_count", 0),
            "concurrency":    1,
            "packet_size_in": packet.get("packet_size_in", 512),
            "packet_size_out":packet.get("packet_size_out", 0),
            "latency":        packet.get("network_latency", 0),
            "fragment_count": packet.get("fragment_count", 0),
            "ip_address":     packet.get("ip_address", ""),
            "timestamp":      datetime.datetime.utcnow().isoformat(),
        }
        _ai_model.process_log(features)

    # ── Extract features for AI model ─────────────────────────────────────────

    def _extract_ai_features(
        self,
        packet: dict,
        l1_result: dict,
        l2_result: dict,
        temporal: dict,
    ) -> dict:
        """
        Build the feature dict for the AI model.
        Combines raw packet fields with Layer 2 risk scores
        so the AI model has the full picture.
        """
        risk = l2_result.get("risk", {})
        return {
            # Raw execution metrics
            "duration":        packet.get("duration", 0),
            "memory_used":     packet.get("memory_used", 0),
            "num_api_calls":   packet.get("num_api_calls", 0),
            "error_count":     packet.get("error_count", 0),
            "concurrency":     1,
            # Packet-level
            "packet_size_in":  packet.get("packet_size_in", 512),
            "packet_size_out": packet.get("packet_size_out", 0),
            "latency":         packet.get("network_latency", 0),
            "fragment_count":  packet.get("fragment_count", 0),
            # Layer 2 enrichment
            "l2_risk_score":   risk.get("adjusted_score", 0),
            "l2_confidence":   risk.get("confidence", 0),
            "threat_count":    l2_result.get("patterns", {}).get("threat_count", 0),
            # SARIMA temporal
            "temporal_score":  temporal.get("temporal_anomaly_score", 0),
            # Meta
            "ip_address":      packet.get("ip_address", ""),
            "timestamp":       datetime.datetime.utcnow().isoformat(),
        }

    # ── Final decision logic ──────────────────────────────────────────────────

    def _make_final_decision(
        self,
        ai_score:   float,
        ai_details: dict,
        l2_result:  dict,
        temporal:   dict,
    ) -> Tuple[str, float]:
        """
        Combine AI model score + Layer 2 severity + temporal context
        into a final ALLOW / INVESTIGATE / BLOCK decision.

        Decision rules:
          BLOCK       -> CRITICAL or combined >= 0.75 or HIGH
          INVESTIGATE -> everything else that reached Layer 2
          ALLOW       -> only returned by Layer 1 fast-pass
        """
        l2_severity      = l2_result.get("severity", "MEDIUM")
        l2_risk          = l2_result.get("risk", {}).get("adjusted_score", 0)
        ai_phase         = ai_details.get("phase")

        # During AI learning phase — rely purely on Layer 2
        if ai_phase == "learning":
            if l2_severity == "CRITICAL":
                return "BLOCK", 0.85
            elif l2_severity == "HIGH":
                return "BLOCK", 0.72
            else:
                return "INVESTIGATE", 0.60

        # Full decision with AI score
        combined = (ai_score * 0.5) + (l2_risk * 0.5)

        if l2_severity == "CRITICAL" or combined >= 0.75:
            decision   = "BLOCK"
            confidence = min(0.70 + combined * 0.25, 0.99)

        elif combined >= 0.50 or l2_severity == "HIGH":
            decision   = "BLOCK"
            confidence = min(0.60 + combined * 0.20, 0.95)

        else:
            # Anything reaching Layer 2 is at minimum INVESTIGATE
            decision   = "INVESTIGATE"
            confidence = min(0.50 + combined * 0.20, 0.90)

        return decision, round(confidence, 4)

    # ── Build reason string ───────────────────────────────────────────────────

    def _build_reason(self, decision: str, ai_details: dict, l2_result: dict) -> str:
        severity = l2_result.get("severity", "MEDIUM")
        patterns = l2_result.get("patterns", {})
        top      = patterns.get("top_threat")
        phase    = ai_details.get("phase", "detection")

        if phase == "learning":
            base = f"AI model still learning baseline ({ai_details.get('learning_progress','')}). "
            base += f"Decision based on Layer 2 severity: {severity}."
            return base

        parts = []
        if top:
            parts.append(f"Primary threat: {top['name']} (confidence {top['confidence']:.0%})")
        if patterns.get("threat_count", 0) > 1:
            parts.append(f"{patterns['threat_count']} attack patterns matched")
        if ai_details.get("is_anomaly"):
            parts.append(f"AI anomaly score: {ai_details.get('anomaly_score', 0):.2f}")

        if not parts:
            parts.append(f"Layer 2 severity: {severity}")

        return " | ".join(parts)

    # ── Build final result dict ───────────────────────────────────────────────

    def _build_result(
        self,
        pipeline_id: str,
        timestamp:   str,
        decision:    str,
        confidence:  float,
        severity:    str,
        stages:      dict,
        elapsed_ms:  float,
        stopped_at:  str,
        reason:      str,
    ) -> dict:
        return {
            "pipeline_id": pipeline_id,
            "timestamp":   timestamp,
            "elapsed_ms":  elapsed_ms,
            "stopped_at":  stopped_at,

            # Final verdict
            "decision":    decision,       # ALLOW / INVESTIGATE / BLOCK
            "confidence":  confidence,
            "severity":    severity,
            "reason":      reason,

            # Full stage evidence
            "stages":      stages,
        }


# ── Module-level convenience function ─────────────────────────────────────────
_pipeline = CloudSentinelPipeline()

def process(packet: dict) -> dict:
    """Single function call for the entire pipeline."""
    return _pipeline.process(packet)

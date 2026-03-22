"""
Cloud Sentinel — Unified Detection Pipeline
=============================================
Single entry point that runs every stage in the correct order:

  1. SARIMA        — get dynamic thresholds + temporal context
  2. Layer 1       — fast gate using SARIMA-adjusted thresholds
                     (Layer1Scorer AI scoring + Layer1Filter hard rules)
  3. STOP          — if Layer 1 flags the packet, return INVESTIGATE
                     with raw_packet stored for on-demand Layer 2

Layer 2 is NOT run here. It only runs when the analyst clicks
"Investigate" in the frontend → POST /api/alerts/{id}/investigate

Output:  ALLOW / INVESTIGATE  + full Layer 1 evidence + raw_packet

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
from backend.detection.ai_model import EnsembleAnomalyDetector


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
    PEAK_DURATION_MULT    = 1.8   # allow up to 1.8x longer during peak
    PEAK_SIZE_MULT        = 1.5
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
            "ttl_min":            self.BASE_TTL_MIN,
            "ttl_max":            self.BASE_TTL_MAX,
            "size_max":           int(self.BASE_SIZE_MAX * (self.PEAK_SIZE_MULT if is_peak else 1.0)),
            "duration_max":       round(duration_max, 1),
            "is_peak_hour":       is_peak,
            "hour":               hour,
            "sarima_trained":     sarima._trained,
            "predicted_duration": round(predicted_duration, 2),
            "predicted_std":      round(pred_std, 2),
        }

    def get_temporal_context(
        self,
        sarima: SARIMAForecaster,
        actual_duration: float,
    ) -> dict:
        """
        Return temporal context for later use by Layer 2 risk scorer.
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
            "temporal_anomaly_score":   round(temporal_score, 4),
            "temporal_risk_adjustment": round(
                min(temporal_score * 0.25 + offpeak_boost, 0.40), 4
            ),
            "expected_duration":        round(expected, 2),
            "actual_duration":          actual_duration,
            "actual_vs_expected_ratio": round(ratio, 2),
            "is_peak_hour":             is_peak,
            "is_off_peak_attack":       not is_peak and temporal_score > 0.5,
            "time_window":              self._get_time_window(now.hour),
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
# MODULE-LEVEL SINGLETONS
# Instantiated once at import time, shared across all requests
# ============================================================================

_layer1_filter     = Layer1Filter()
_layer2_scanner    = Layer2Scanner()   # kept for reference; pipeline no longer calls it
_sarima            = SARIMAForecaster()
_ai_model          = EnsembleAnomalyDetector(learning_window=200)
_threshold_adapter = SARIMAThresholdAdapter()


# ============================================================================
# PIPELINE
# ============================================================================

class CloudSentinelPipeline:
    """
    Unified detection pipeline.

    Usage:
        pipeline = CloudSentinelPipeline()
        result   = pipeline.process(packet)
        # result["decision"] → "ALLOW" | "INVESTIGATE"
        # result["raw_packet"] → stored for on-demand Layer 2
    """

    def process(self, packet: dict) -> dict:
        """
        Run the detection pipeline on a single packet.

        Pipeline stages:
          1. SARIMA    → dynamic thresholds + temporal context
          2. Layer1Scorer → AI scoring, Z-scores, Welford baseline
          3. Layer1Filter → hard rule confirmation gate
              PASS → ALLOW
              FAIL → INVESTIGATE (raw_packet stored for on-demand L2)

        Layer 2 is intentionally NOT run here.
        It runs on-demand via POST /api/alerts/{id}/investigate.

        Args:
            packet: Lambda execution metadata dict

        Returns:
            Full pipeline result with decision + evidence + raw_packet
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
        scorer_features         = self._extract_scorer_features(packet)
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

        # ── ALLOW: Layer 1 passed ─────────────────────────────────────────────
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
                raw_packet  = None,   # not stored for ALLOW decisions
            )

        # ── INVESTIGATE: Layer 1 flagged this packet ──────────────────────────
        # Layer 2 is NOT run here. It only runs when the analyst clicks
        # "Investigate" in the frontend → POST /api/alerts/{id}/investigate
        #
        # We store raw_packet in the result so api.py can attach it to the
        # alert. When investigate_alert() is called later, it reads
        # alert["_raw_packet"] and passes it to Layer2Scanner.scan().
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        # Determine initial severity from Layer 1 scorer result
        l1_severity = l1_score_details.get("severity") or "MEDIUM"

        return self._build_result(
            pipeline_id = pipeline_id,
            timestamp   = timestamp,
            decision    = "INVESTIGATE",
            confidence  = 0.60,
            severity    = l1_severity,
            stages      = stages,
            elapsed_ms  = elapsed_ms,
            stopped_at  = "layer1",
            reason      = self._build_reason_l1_only(l1_score_details, l1_result),
            raw_packet  = packet,   # stored so Layer 2 can use it on-demand
        )

    # ── Extract features for Layer 1 Scorer ──────────────────────────────────

    def _extract_scorer_features(self, packet: dict) -> dict:
        """Build feature dict for Layer1Scorer baseline learning and scoring."""
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

    # ── Build reason string from Layer 1 data only ───────────────────────────

    def _build_reason_l1_only(self, ai_details: dict, l1_result: dict) -> str:
        """
        Build a human-readable reason string using only Layer 1 data.
        Layer 2 has not run yet so we cannot reference L2 findings here.
        """
        violations = l1_result.get("filter_violations", [])
        phase      = ai_details.get("phase", "detection")
        score      = ai_details.get("anomaly_score", 0)

        parts = []

        if phase == "learning":
            parts.append(
                f"AI model still learning baseline "
                f"({ai_details.get('learning_progress', '')})"
            )
        elif score > 0:
            parts.append(f"AI anomaly score: {score:.2f}")

        if violations:
            # Show up to 2 violations to keep it readable
            for v in violations[:2]:
                parts.append(v)

        if not parts:
            parts.append("Flagged by Layer 1 — awaiting Layer 2 investigation")

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
        raw_packet:  dict = None,
    ) -> dict:
        """
        Assemble the pipeline result dict.

        raw_packet is included when decision == INVESTIGATE so that
        api.py can attach it to the alert as _raw_packet for later
        on-demand Layer 2 investigation.
        """
        result = {
            "pipeline_id": pipeline_id,
            "timestamp":   timestamp,
            "elapsed_ms":  elapsed_ms,
            "stopped_at":  stopped_at,
            "decision":    decision,
            "confidence":  confidence,
            "severity":    severity,
            "reason":      reason,
            "stages":      stages,
        }
        if raw_packet is not None:
            result["raw_packet"] = raw_packet
        return result


# ============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# ============================================================================

_pipeline = CloudSentinelPipeline()

def process(packet: dict) -> dict:
    """Single function call for the entire pipeline."""
    return _pipeline.process(packet)
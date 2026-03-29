"""
Cloud Sentinel — Unified Detection Pipeline
=============================================
Single entry point that runs every stage in the correct order:

  1. SARIMA             — get dynamic thresholds + temporal context
  2. EnsembleAnomalyDetector — ML scoring (Isolation Forest + Random Forest)
  3. Layer1Filter       — hard rule confirmation gate
      PASS → ALLOW
      FAIL → INVESTIGATE (raw_packet stored for on-demand L2)

Layer 2 is NOT run here. It only runs when the analyst clicks
"Investigate" in the frontend → POST /api/alerts/{id}/investigate

Output:  ALLOW / INVESTIGATE  + full evidence + raw_packet

Author: Saleem Akthar
"""

import time
import uuid
import datetime
from typing import Optional, Tuple

from backend.detection.layer1_filter     import Layer1Filter
from backend.detection.layer2_scanner    import Layer2Scanner
from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.detection.ai_model          import EnsembleAnomalyDetector


# ============================================================================
# SARIMA THRESHOLD ADAPTER
# ============================================================================

class SARIMAThresholdAdapter:
    """
    Converts SARIMA time-series predictions into dynamic Layer 1 thresholds.

    Peak hours  → relaxed thresholds (traffic is naturally higher)
    Off-peak    → tighter thresholds (any spike is more suspicious)
    """

    BASE_DURATION_MAX     = 3000
    BASE_SIZE_MAX         = 65535
    BASE_TTL_MIN          = 30
    BASE_TTL_MAX          = 128

    PEAK_DURATION_MULT    = 1.8
    PEAK_SIZE_MULT        = 1.5
    OFFPEAK_DURATION_MULT = 0.7

    def get_layer1_thresholds(self, sarima: SARIMAForecaster) -> dict:
        now  = datetime.datetime.utcnow()
        hour = now.hour
        is_peak = 8 <= hour <= 20

        if is_peak:
            duration_max = self.BASE_DURATION_MAX * self.PEAK_DURATION_MULT
            size_max     = int(self.BASE_SIZE_MAX * self.PEAK_SIZE_MULT)
        else:
            duration_max = self.BASE_DURATION_MAX * self.OFFPEAK_DURATION_MULT
            size_max     = self.BASE_SIZE_MAX

        return {
            "ttl_min":      self.BASE_TTL_MIN,
            "ttl_max":      self.BASE_TTL_MAX,
            "size_max":     size_max,
            "duration_max": duration_max,
            "is_peak":      is_peak,
            "hour":         hour,
        }

    def get_temporal_context(self, sarima: SARIMAForecaster, actual_duration: float) -> dict:
        temporal_score = sarima.detect_temporal_anomaly(actual_duration)
        prediction     = sarima.predict()
        now            = datetime.datetime.utcnow()
        is_peak        = self._is_peak_hour(now.hour)

        expected = prediction["value"] if prediction["value"] > 0 else actual_duration
        ratio    = actual_duration / max(expected, 1.0)

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
# Instantiated once at import time, shared across all requests.
# api.py imports these directly so there is ONE instance of each.
# ============================================================================

_layer1_filter     = Layer1Filter()
_layer2_scanner    = Layer2Scanner()    # used by api.py for on-demand L2
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
          1. SARIMA                  → dynamic thresholds + temporal context
          2. EnsembleAnomalyDetector → ML scoring (IF + RF ensemble)
          3. Layer1Filter            → hard rule confirmation gate
              PASS  → ALLOW
              FAIL  → INVESTIGATE (raw_packet stored for on-demand L2)

        Layer 2 is intentionally NOT run here.
        It runs on-demand via POST /api/alerts/{id}/investigate.

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

        # ── STAGE 2: ML ENSEMBLE (Isolation Forest + Random Forest) ──────────
        # .predict() handles all phases internally:
        #   - Learning: collects features, returns ALLOW
        #   - Isolation Forest only: scores with single model
        #   - Full ensemble: both models vote, BLOCK only on consensus
        ensemble_result = _ai_model.predict(packet)

        stages["ai_model"] = {
            "phase":        ensemble_result.get("phase"),
            "score":        ensemble_result.get("anomaly_score", 0),
            "decision":     ensemble_result.get("decision"),
            "is_anomaly":   ensemble_result.get("is_anomaly", False),
            "attack_type":  ensemble_result.get("attack_type"),
            "model_votes":  ensemble_result.get("model_votes"),
            "confidence":   ensemble_result.get("confidence", 0),
        }

        ensemble_is_anomaly = ensemble_result.get("is_anomaly", False)
        ensemble_phase      = ensemble_result.get("phase", "learning")

        # Also feed as labeled data for continuous learning:
        # Normal traffic that passes → labeled as normal
        # (Anomaly labels come later from Layer 2 investigate results)
        if not ensemble_is_anomaly:
            _ai_model.add_labeled_example(packet, is_anomaly=False, attack_type="normal")

        # ── STAGE 3: LAYER 1 FILTER (hard rules — always runs) ───────────────
        dynamic_l1 = Layer1Filter(
            ttl_min         = sarima_thresholds["ttl_min"],
            ttl_max         = sarima_thresholds["ttl_max"],
            size_max        = sarima_thresholds["size_max"],
            duration_max_ms = sarima_thresholds["duration_max"],
        )
        l1_filter_result = dynamic_l1.check(packet)
        stages["layer1_filter"] = l1_filter_result

        filter_has_violations = not l1_filter_result["pass"]

        # ── COMBINED DECISION ─────────────────────────────────────────────────
        # ALLOW only if: filter clean AND ensemble says normal (or learning)
        # INVESTIGATE if: filter has violations OR ensemble flagged anomaly
        l1_pass = (not filter_has_violations) and (not ensemble_is_anomaly)

        l1_result = {
            "pass":              l1_pass,
            "ensemble_anomaly":  ensemble_is_anomaly,
            "ensemble_phase":    ensemble_phase,
            "filter_violations": l1_filter_result["violations"],
            "filter_passed":     l1_filter_result["pass"],
            "ensemble_score":    round(ensemble_result.get("anomaly_score", 0), 4),
            "filter_result":     l1_filter_result,
            "ensemble_result":   ensemble_result,
        }
        stages["layer1"] = l1_result

        # ── ALLOW: everything clean ───────────────────────────────────────────
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
                reason      = "Passed ML ensemble and Layer 1 filter — normal traffic",
                raw_packet  = None,
            )

        # ── INVESTIGATE: flagged by ensemble and/or filter ────────────────────
        # Determine severity from ensemble + filter evidence
        severity = self._determine_severity(ensemble_result, l1_filter_result)

        # Confidence from ensemble if available, otherwise default
        confidence = ensemble_result.get("confidence", 0.60)
        if ensemble_phase == "learning":
            confidence = 0.60  # lower confidence during learning

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return self._build_result(
            pipeline_id = pipeline_id,
            timestamp   = timestamp,
            decision    = "INVESTIGATE",
            confidence  = confidence,
            severity    = severity,
            stages      = stages,
            elapsed_ms  = elapsed_ms,
            stopped_at  = "layer1",
            reason      = self._build_reason(ensemble_result, l1_result),
            raw_packet  = packet,
        )

    # ── Severity determination ────────────────────────────────────────────────

    def _determine_severity(self, ensemble_result: dict, filter_result: dict) -> str:
        """
        Determine alert severity from ensemble score + filter violations.

        CRITICAL: ensemble score >= 0.80 OR 3+ filter violations
        HIGH:     ensemble score >= 0.60 OR 2+ filter violations
        MEDIUM:   everything else that reached INVESTIGATE
        """
        score      = ensemble_result.get("anomaly_score", 0)
        violations = filter_result.get("violations", [])
        n_violations = len(violations)

        if score >= 0.80 or n_violations >= 3:
            return "CRITICAL"
        elif score >= 0.60 or n_violations >= 2:
            return "HIGH"
        else:
            return "MEDIUM"

    # ── Build reason string ───────────────────────────────────────────────────

    def _build_reason(self, ensemble_result: dict, l1_result: dict) -> str:
        """Build a human-readable reason string from ensemble + filter data."""
        violations = l1_result.get("filter_violations", [])
        phase      = ensemble_result.get("phase", "learning")
        score      = ensemble_result.get("anomaly_score", 0)
        attack     = ensemble_result.get("attack_type")

        parts = []

        if phase == "learning":
            progress = ensemble_result.get("learning_progress", "")
            parts.append(f"ML model learning baseline ({progress})")
        elif score > 0:
            parts.append(f"ML ensemble score: {score:.2f}")

        if attack:
            parts.append(f"Suspected: {attack}")

        # Show model votes if available
        votes = ensemble_result.get("model_votes", {})
        if votes:
            if_vote = votes.get("isolation_forest", {})
            rf_vote = votes.get("random_forest")
            if if_vote.get("is_anomaly"):
                parts.append(f"Isolation Forest: anomaly ({if_vote.get('score', 0):.2f})")
            if rf_vote and rf_vote.get("is_anomaly"):
                parts.append(f"Random Forest: anomaly ({rf_vote.get('score', 0):.2f})")

        if violations:
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
# MODULE-LEVEL CONVENIENCE
# ============================================================================

_pipeline = CloudSentinelPipeline()

def process(packet: dict) -> dict:
    """Single function call for the entire pipeline."""
    return _pipeline.process(packet)
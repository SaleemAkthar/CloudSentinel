"""
AI Model — Cloud Sentinel Ensemble Anomaly Detector
Two-model ensemble for final anomaly decision with low false positives.

Models:
    1. Isolation Forest   (unsupervised) — learns what "normal" looks like
    2. Random Forest       (supervised)  — learns attack signatures from
                                           accumulated labeled data

Consensus strategy (why false positives are low):
    - BLOCK only when BOTH models agree the packet is anomalous
    - INVESTIGATE when only ONE model flags it (human reviews)
    - ALLOW when NEITHER model flags it

Training phases:
    Phase 1 — Learning (first N requests):
        Collect normal traffic features. No decisions made.
        At the end: train Isolation Forest on normal baseline.

    Phase 2 — Isolation Forest Only:
        IF scores every packet. Accumulates labeled examples
        from Layer 2 decisions for the Random Forest.

    Phase 3 — Full Ensemble:
        Once enough labeled data exists (≥50 anomalies + ≥50 normal),
        train Random Forest. Both models now vote on every packet.

Feature vector (10 features):
    duration, memory_used, num_api_calls, error_count,
    packet_size_in, packet_size_out, outbound_ratio,
    network_latency, fragment_count, ttl

Author: Backend Team
"""

import numpy as np
import logging
from typing import Dict, Tuple, Optional, List
from datetime import datetime
from collections import deque

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("cloud_sentinel.ai_model")



# FEATURE EXTRACTION

# The 10 features the model uses — order matters, must be consistent
FEATURE_NAMES = [
    "duration",
    "memory_used",
    "num_api_calls",
    "error_count",
    "packet_size_in",
    "packet_size_out",
    "outbound_ratio",
    "network_latency",
    "fragment_count",
    "ttl",
]


def extract_features(packet: dict) -> np.ndarray:
    """
    Extract a fixed-length feature vector from a packet dict.

    Returns:
        1D numpy array of shape (10,)
    """
    size_in  = max(packet.get("packet_size_in", 512), 1)
    size_out = packet.get("packet_size_out", 0)

    return np.array([
        packet.get("duration", 0),
        packet.get("memory_used", 0),
        packet.get("num_api_calls", 0),
        packet.get("error_count", 0),
        size_in,
        size_out,
        size_out / size_in,                   # outbound ratio
        packet.get("network_latency", 0),
        packet.get("fragment_count", 0),
        packet.get("ttl", 64),
    ], dtype=np.float64)



# ENSEMBLE MODEL

class EnsembleAnomalyDetector:
    """
    Two-model ensemble for anomaly detection with low false positives.

    Usage:
        model = EnsembleAnomalyDetector(learning_window=200)

        # During learning phase:
        result = model.predict(packet)
        # result["phase"] == "learning"

        # After learning:
        result = model.predict(packet)
        # result["decision"] in ("ALLOW", "INVESTIGATE", "BLOCK")

        # Feed labeled data from Layer 2 to improve the supervised model:
        model.add_labeled_example(packet, is_anomaly=True, attack_type="crypto_mining")
    """

    def __init__(self, learning_window: int = 200):
        """
        Args:
            learning_window: Number of normal requests to collect before
                             training the Isolation Forest.
        """
        self.learning_window = learning_window

        # Phase tracking
        self.phase = "learning"       # "learning" → "isolation_only" → "full_ensemble"
        self.n_requests = 0
        self.n_anomalies = 0

        # Feature scaling
        self.scaler = StandardScaler()
        self._scaler_fitted = False

        # Learning phase buffer
        self._learning_buffer: List[np.ndarray] = []

        # Model 1: Isolation Forest (unsupervised)
        # contamination=0.02 means "expect ~2% of training data to be anomalous"
        # This is conservative — lower = fewer false positives
        self.isolation_forest = IsolationForest(
            n_estimators=150,
            contamination=0.02,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._if_trained = False

        # ── Model 2: Random Forest Classifier (supervised)
        # Trained on labeled data accumulated from Layer 2 decisions.
        # class_weight="balanced" handles the imbalanced dataset
        # (more normal than anomaly examples).
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._rf_trained = False

        # Labeled data buffer for supervised training
        # Accumulated from Layer 2 decisions over time
        self._labeled_X: List[np.ndarray] = []
        self._labeled_y: List[int] = []           # 0 = normal, 1 = anomaly
        self._labeled_attacks: List[str] = []     # attack type strings
        self._rf_min_anomalies = 50               # need at least 50 anomaly examples
        self._rf_min_normal    = 50               # and 50 normal examples
        self._rf_retrain_interval = 100           # retrain every 100 new labels
        self._labels_since_retrain = 0

        # Attack type classifier
        # Separate RF that classifies attack TYPE (not just anomaly/normal)
        self.attack_classifier = RandomForestClassifier(
            n_estimators=80,
            max_depth=8,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._attack_clf_trained = False

        # Performance tracking
        self._recent_predictions = deque(maxlen=500)

   
    # PUBLIC API

    def predict(self, packet: dict, l2_risk_score: float = 0.0) -> dict:
        """
        Score a packet through the ensemble.

        Args:
            packet:        dict with execution metrics + packet fields
            l2_risk_score: Layer 2 risk score (0-1) if available

        Returns:
            {
                "phase":         "learning" | "isolation_only" | "full_ensemble",
                "decision":      "ALLOW" | "INVESTIGATE" | "BLOCK",
                "anomaly_score": float (0-1),
                "confidence":    float (0-1),
                "is_anomaly":    bool,
                "attack_type":   str or None,
                "model_votes": {
                    "isolation_forest": {"score": float, "is_anomaly": bool},
                    "random_forest":    {"score": float, "is_anomaly": bool} or None,
                },
                "learning_progress": str  (during learning only),
            }
        """
        self.n_requests += 1
        features = extract_features(packet)

        #LEARNING PHASE
        if self.phase == "learning":
            return self._handle_learning(features)

        # DETECTION PHASE
        return self._handle_detection(features, l2_risk_score)

    def add_labeled_example(self, packet: dict, is_anomaly: bool,
                            attack_type: str = "normal"):
        """
        Feed a labeled example to improve the supervised model.

        Call this after Layer 2 makes a decision, so the Random Forest
        accumulates real-world labeled data over time.

        Args:
            packet:      the packet dict
            is_anomaly:  True if Layer 2 flagged this as anomalous
            attack_type: the attack type string (e.g. "crypto_mining", "ddos")
        """
        features = extract_features(packet)

        if self._scaler_fitted:
            features = self.scaler.transform(features.reshape(1, -1))[0]

        self._labeled_X.append(features)
        self._labeled_y.append(1 if is_anomaly else 0)
        self._labeled_attacks.append(attack_type if is_anomaly else "normal")
        self._labels_since_retrain += 1

        # Check if we should train/retrain the Random Forest
        n_anomalies = sum(self._labeled_y)
        n_normal    = len(self._labeled_y) - n_anomalies

        if not self._rf_trained:
            # First training — need minimum examples
            if n_anomalies >= self._rf_min_anomalies and n_normal >= self._rf_min_normal:
                self._train_random_forest()
        else:
            # Periodic retraining with accumulated data
            if self._labels_since_retrain >= self._rf_retrain_interval:
                self._train_random_forest()

    def get_status(self) -> dict:
        """Return model status for the /status endpoint."""
        n_labels   = len(self._labeled_y)
        n_anom_lab = sum(self._labeled_y) if self._labeled_y else 0

        return {
            "phase":                self.phase,
            "requests_processed":   self.n_requests,
            "anomalies_detected":   self.n_anomalies,
            "isolation_forest_trained": self._if_trained,
            "random_forest_trained":    self._rf_trained,
            "attack_classifier_trained": self._attack_clf_trained,
            "labeled_examples":     n_labels,
            "labeled_anomalies":    n_anom_lab,
            "labeled_normal":       n_labels - n_anom_lab,
            "learning_progress":    f"{min(len(self._learning_buffer), self.learning_window)}"
                                    f"/{self.learning_window}",
        }

    def get_performance_metrics(self) -> dict:
        """Compute accuracy/precision/recall from recent predictions."""
        if not self._recent_predictions:
            return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}

        preds = list(self._recent_predictions)
        tp = sum(1 for p in preds if p["true_label"] == 1 and p["predicted"] == 1)
        tn = sum(1 for p in preds if p["true_label"] == 0 and p["predicted"] == 0)
        fp = sum(1 for p in preds if p["true_label"] == 0 and p["predicted"] == 1)
        fn = sum(1 for p in preds if p["true_label"] == 1 and p["predicted"] == 0)

        total     = tp + tn + fp + fn
        accuracy  = (tp + tn) / max(total, 1)
        precision = tp / max(tp + fp, 1)
        recall    = tp / max(tp + fn, 1)
        f1        = 2 * precision * recall / max(precision + recall, 1e-10)

        return {
            "accuracy":  round(accuracy * 100, 1),
            "precision": round(precision * 100, 1),
            "recall":    round(recall * 100, 1),
            "f1":        round(f1 * 100, 1),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "total_tracked": total,
        }

    # ======================================================================
    # LEARNING PHASE
    # ======================================================================

    def _handle_learning(self, features: np.ndarray) -> dict:
        """Collect normal traffic features. No decisions made."""
        self._learning_buffer.append(features)

        progress = len(self._learning_buffer) / self.learning_window

        if len(self._learning_buffer) >= self.learning_window:
            self._train_isolation_forest()
            self.phase = "isolation_only"
            logger.info(
                "Learning complete. Isolation Forest trained on %d samples. "
                "Entering detection phase.",
                len(self._learning_buffer),
            )

        return {
            "phase":             "learning",
            "decision":          "ALLOW",
            "anomaly_score":     0.0,
            "confidence":        0.0,
            "is_anomaly":        False,
            "attack_type":       None,
            "model_votes":       None,
            "learning_progress": f"{len(self._learning_buffer)}/{self.learning_window}",
            "progress_pct":      round(progress * 100, 1),
        }

    
    # DETECTION PHASE
    

    def _handle_detection(self, features: np.ndarray, l2_risk: float) -> dict:
        """Run the ensemble and return a decision."""

        # Scale features
        scaled = self.scaler.transform(features.reshape(1, -1))

        # ── Model 1: Isolation Forest ─────────────────────────────────────
        if_raw_score   = self.isolation_forest.decision_function(scaled)[0]
        # IF returns negative = anomaly, positive = normal
        # Convert to 0-1 where 1 = most anomalous
        if_anomaly_score = max(0.0, min(1.0, -if_raw_score / 0.5))
        if_is_anomaly    = self.isolation_forest.predict(scaled)[0] == -1

        if_vote = {
            "score":      round(float(if_anomaly_score), 4),
            "is_anomaly": bool(if_is_anomaly),
            "raw_score":  round(float(if_raw_score), 4),
        }

        # ── Model 2: Random Forest (if trained) ──────────────────────────
        rf_vote = None
        rf_anomaly_score = 0.0
        rf_is_anomaly    = False

        if self._rf_trained:
            rf_proba = self.random_forest.predict_proba(scaled)[0]
            # proba[1] = probability of being anomalous
            rf_anomaly_score = float(rf_proba[1]) if len(rf_proba) > 1 else 0.0
            rf_is_anomaly    = rf_anomaly_score >= 0.6  # conservative threshold

            rf_vote = {
                "score":      round(rf_anomaly_score, 4),
                "is_anomaly": bool(rf_is_anomaly),
                "probabilities": {
                    "normal":  round(float(rf_proba[0]), 4),
                    "anomaly": round(float(rf_proba[1]) if len(rf_proba) > 1 else 0.0, 4),
                },
            }

            # Update phase if not already full ensemble
            if self.phase != "full_ensemble":
                self.phase = "full_ensemble"
                logger.info("Random Forest trained. Entering full ensemble mode.")

        # ── Attack type classification ────────────────────────────────────
        attack_type = None
        if self._attack_clf_trained:
            try:
                attack_pred = self.attack_classifier.predict(scaled)[0]
                if attack_pred != "normal":
                    attack_type = attack_pred
            except Exception:
                pass

        # ── Ensemble decision ─────────────────────────────────────────────
        decision, anomaly_score, confidence = self._ensemble_vote(
            if_score=if_anomaly_score,
            if_anomaly=if_is_anomaly,
            rf_score=rf_anomaly_score,
            rf_anomaly=rf_is_anomaly,
            rf_trained=self._rf_trained,
            l2_risk=l2_risk,
        )

        is_anomaly = decision in ("INVESTIGATE", "BLOCK")
        if is_anomaly:
            self.n_anomalies += 1

        return {
            "phase":         self.phase,
            "decision":      decision,
            "anomaly_score": round(anomaly_score, 4),
            "confidence":    round(confidence, 4),
            "is_anomaly":    is_anomaly,
            "attack_type":   attack_type,
            "model_votes": {
                "isolation_forest": if_vote,
                "random_forest":    rf_vote,
            },
        }

    
    # ENSEMBLE VOTING — the core logic for low false positives

    def _ensemble_vote(
        self,
        if_score:   float,
        if_anomaly: bool,
        rf_score:   float,
        rf_anomaly: bool,
        rf_trained: bool,
        l2_risk:    float,
    ) -> Tuple[str, float, float]:
        """
        Consensus-based decision.

        Rules (designed for LOW false positives):
            BLOCK:
                - Both IF and RF agree it's anomalous (full ensemble)
                - OR single model score > 0.90 (overwhelming evidence)
                - OR L2 risk > 0.85 (Layer 2 very confident)

            INVESTIGATE:
                - Only ONE model flags it (needs human review)
                - OR scores are in the uncertain zone (0.5-0.7)

            ALLOW:
                - Neither model flags it
                - Scores below threshold

        Returns:
            (decision, anomaly_score, confidence)
        """

        # ── Full ensemble (both models trained) ───────────────────────────
        if rf_trained:
            # Combined score: weighted average
            combined = (if_score * 0.4) + (rf_score * 0.4) + (l2_risk * 0.2)

            both_agree   = if_anomaly and rf_anomaly
            either_flags = if_anomaly or rf_anomaly
            neither      = not if_anomaly and not rf_anomaly

            # BLOCK: both models agree OR overwhelming single-model evidence
            if both_agree and combined >= 0.60:
                confidence = min(0.80 + combined * 0.15, 0.99)
                return "BLOCK", combined, confidence

            if combined >= 0.90:
                # Single model is extremely confident
                confidence = min(0.75 + combined * 0.20, 0.99)
                return "BLOCK", combined, confidence

            if l2_risk >= 0.85 and either_flags:
                # Layer 2 very confident + at least one model agrees
                confidence = min(0.70 + l2_risk * 0.20, 0.95)
                return "BLOCK", combined, confidence

            # INVESTIGATE: one model flags, the other doesn't
            if either_flags:
                confidence = min(0.50 + combined * 0.20, 0.85)
                return "INVESTIGATE", combined, confidence

            # Borderline scores (both models unsure but scores elevated)
            if combined >= 0.45:
                confidence = min(0.40 + combined * 0.15, 0.70)
                return "INVESTIGATE", combined, confidence

            # ALLOW: neither model flags, scores low
            confidence = min(0.85 + (1 - combined) * 0.10, 0.99)
            return "ALLOW", combined, confidence

        # Isolation Forest only (RF not yet trained)
        else:
            combined = (if_score * 0.6) + (l2_risk * 0.4)

            # Very conservative with single model — higher threshold for BLOCK
            if if_anomaly and combined >= 0.80:
                confidence = min(0.60 + combined * 0.20, 0.90)
                return "BLOCK", combined, confidence

            if l2_risk >= 0.85:
                confidence = min(0.60 + l2_risk * 0.20, 0.90)
                return "BLOCK", combined, confidence

            if if_anomaly or combined >= 0.55:
                confidence = min(0.40 + combined * 0.20, 0.75)
                return "INVESTIGATE", combined, confidence

            confidence = min(0.80 + (1 - combined) * 0.15, 0.99)
            return "ALLOW", combined, confidence


    # TRAINING


    def _train_isolation_forest(self):
        """Train Isolation Forest on collected normal traffic."""
        X = np.array(self._learning_buffer)

        # Fit the scaler on normal data
        self.scaler.fit(X)
        self._scaler_fitted = True
        X_scaled = self.scaler.transform(X)

        # Train Isolation Forest
        self.isolation_forest.fit(X_scaled)
        self._if_trained = True

        # Also add these as labeled normal examples for future RF training
        for features in self._learning_buffer:
            scaled = self.scaler.transform(features.reshape(1, -1))[0]
            self._labeled_X.append(scaled)
            self._labeled_y.append(0)  # normal
            self._labeled_attacks.append("normal")

        # Free the learning buffer
        self._learning_buffer = []

        logger.info("Isolation Forest trained on %d normal samples.", len(X))

    def _train_random_forest(self):
        """Train Random Forest on accumulated labeled data."""
        X = np.array(self._labeled_X)
        y = np.array(self._labeled_y)

        n_anomalies = sum(y)
        n_normal    = len(y) - n_anomalies

        logger.info(
            "Training Random Forest on %d samples (%d normal, %d anomaly)",
            len(y), n_normal, n_anomalies,
        )

        # Train anomaly/normal classifier
        self.random_forest.fit(X, y)
        self._rf_trained = True

        # Train attack type classifier (only on anomaly examples)
        attack_labels = np.array(self._labeled_attacks)
        unique_attacks = set(attack_labels) - {"normal"}

        if len(unique_attacks) >= 2:
            # Need at least 2 classes to train a classifier
            try:
                self.attack_classifier.fit(X, attack_labels)
                self._attack_clf_trained = True
                logger.info(
                    "Attack classifier trained on %d classes: %s",
                    len(unique_attacks), unique_attacks,
                )
            except Exception as e:
                logger.warning("Attack classifier training failed: %s", e)

        self._labels_since_retrain = 0


    # FEEDBACK (for tracking real performance)

    def record_outcome(self, predicted_anomaly: bool, true_anomaly: bool):
        """
        Record a prediction outcome for performance tracking.

        Call this when the ground truth becomes known (e.g., analyst
        allows or blocks an alert).
        """
        self._recent_predictions.append({
            "predicted":  1 if predicted_anomaly else 0,
            "true_label": 1 if true_anomaly else 0,
            "timestamp":  datetime.utcnow().isoformat(),
        })


# TESTING

if __name__ == "__main__":
    print("=" * 70)
    print("ENSEMBLE ANOMALY DETECTOR — UNIT TEST")
    print("=" * 70)

    model = EnsembleAnomalyDetector(learning_window=50)

    # Phase 1: Learning
    print("\n[1] Learning phase — 50 normal packets")
    for i in range(50):
        packet = {
            "duration":        np.random.randint(300, 600),
            "memory_used":     np.random.randint(100, 160),
            "num_api_calls":   np.random.randint(1, 8),
            "error_count":     0,
            "packet_size_in":  np.random.randint(200, 1500),
            "packet_size_out": np.random.randint(100, 800),
            "network_latency": np.random.uniform(5, 50),
            "fragment_count":  0,
            "ttl":             64,
        }
        result = model.predict(packet)
        if i == 49:
            print(f"   Phase after 50: {result['phase']}")

    # Phase 2: Detection — normal traffic
    print("\n[2] Detection — 10 normal packets")
    for i in range(10):
        packet = {
            "duration":        np.random.randint(300, 600),
            "memory_used":     np.random.randint(100, 160),
            "num_api_calls":   np.random.randint(1, 8),
            "error_count":     0,
            "packet_size_in":  np.random.randint(200, 1500),
            "packet_size_out": np.random.randint(100, 800),
            "network_latency": np.random.uniform(5, 50),
            "fragment_count":  0,
            "ttl":             64,
        }
        result = model.predict(packet)
        print(f"   Normal #{i+1}: {result['decision']} "
              f"(score={result['anomaly_score']:.3f})")

    # Phase 3: Detection — attack traffic
    print("\n[3] Detection — 5 crypto mining packets")
    for i in range(5):
        attack = {
            "duration":        np.random.randint(8000, 15000),
            "memory_used":     np.random.randint(400, 500),
            "num_api_calls":   np.random.randint(1, 3),
            "error_count":     0,
            "packet_size_in":  128,
            "packet_size_out": 64,
            "network_latency": 10.0,
            "fragment_count":  0,
            "ttl":             44,
        }
        result = model.predict(attack, l2_risk_score=0.85)
        print(f"   Attack #{i+1}: {result['decision']} "
              f"(score={result['anomaly_score']:.3f}, "
              f"IF={result['model_votes']['isolation_forest']['score']:.3f})")

    # Feed labeled data
    print("\n[4] Adding labeled examples for Random Forest training...")
    for i in range(60):
        model.add_labeled_example(
            {"duration": np.random.randint(8000, 15000), "memory_used": 450,
             "num_api_calls": 2, "error_count": 0, "packet_size_in": 128,
             "packet_size_out": 64, "network_latency": 10, "fragment_count": 0, "ttl": 44},
            is_anomaly=True, attack_type="crypto_mining"
        )

    status = model.get_status()
    print(f"   Phase: {status['phase']}")
    print(f"   RF trained: {status['random_forest_trained']}")
    print(f"   Labeled: {status['labeled_examples']} "
          f"({status['labeled_anomalies']} anomaly, {status['labeled_normal']} normal)")

    # Phase 4: Full ensemble
    if model._rf_trained:
        print("\n[5] Full ensemble — attack packets")
        for i in range(5):
            attack = {
                "duration":        np.random.randint(8000, 15000),
                "memory_used":     np.random.randint(400, 500),
                "num_api_calls":   2,
                "error_count":     0,
                "packet_size_in":  128,
                "packet_size_out": 64,
                "network_latency": 10.0,
                "fragment_count":  0,
                "ttl":             44,
            }
            result = model.predict(attack, l2_risk_score=0.85)
            rf = result["model_votes"].get("random_forest", {})
            print(f"   Attack #{i+1}: {result['decision']} "
                  f"(score={result['anomaly_score']:.3f}, "
                  f"IF={result['model_votes']['isolation_forest']['score']:.3f}, "
                  f"RF={rf.get('score', 'N/A')})")

    print(f"\n   Final status: {model.get_status()}")
    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)

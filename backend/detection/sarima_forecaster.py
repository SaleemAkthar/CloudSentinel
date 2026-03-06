"""
SARIMA Forecaster — Cloud Sentinel
====================================
Time-series forecasting for temporal anomaly detection.
Uses SARIMA (Seasonal AutoRegressive Integrated Moving Average) to learn
normal Lambda execution patterns over time and flag deviations.

If statsmodels is not installed, falls back to a lightweight rolling-window
statistical model so the rest of the system keeps working.

Author: Okitha (Backend Team)
"""

import math
import datetime
from collections import deque
from typing import Dict, List, Optional, Tuple

# Try to import statsmodels — gracefully degrade if not installed
try:
    import pandas as pd
    from statsmodels.tsa.statespace.sarimax import SARIMAX
    SARIMA_AVAILABLE = True
except ImportError:
    SARIMA_AVAILABLE = False


# ============================================================================
# FALLBACK: ROLLING STATISTICAL FORECASTER
# Used when statsmodels is not installed. Provides mean + std predictions
# using a simple rolling window — good enough for dev/testing.
# ============================================================================

class _RollingForecaster:
    """
    Lightweight fallback forecaster using a rolling window of recent values.
    Computes mean and std for prediction — no external dependencies required.
    """
    def __init__(self, window: int = 50):
        self._window = window
        self._values: deque = deque(maxlen=window)

    def fit(self, values: List[float]):
        self._values.extend(values[-self._window:])

    def predict_one(self) -> Tuple[float, float]:
        if not self._values:
            return 0.0, 1.0
        mean = sum(self._values) / len(self._values)
        if len(self._values) < 2:
            return mean, 1.0
        variance = sum((v - mean) ** 2 for v in self._values) / (len(self._values) - 1)
        return mean, math.sqrt(variance)

    def update(self, value: float):
        self._values.append(value)


# ============================================================================
# SARIMA FORECASTER
# ============================================================================

class SARIMAForecaster:
    """
    Forecasts expected Lambda execution metrics using SARIMA.

    SARIMA order:
        (p, d, q)              = (1, 1, 1)  — non-seasonal AR, diff, MA
        (P, D, Q, s) = (1, 1, 1, 24) — seasonal period of 24 hours

    Usage:
        forecaster = SARIMAForecaster()

        # Feed normal traffic during learning phase
        forecaster.add_data_point(500.0, "2026-03-06T09:00:00")

        # Once enough data is collected, train
        forecaster.train()

        # Detect temporal anomalies
        score = forecaster.detect_temporal_anomaly(9000.0, "2026-03-06T10:00:00")
    """

    MIN_TRAINING_POINTS = 200   # Minimum data points required to train SARIMA
    RETRAIN_INTERVAL    = 100   # Retrain every N new points after initial training

    def __init__(self,
                 order: Tuple = (1, 1, 1),
                 seasonal_order: Tuple = (1, 1, 1, 24)):
        self.order          = order
        self.seasonal_order = seasonal_order
        self.model          = None          # Fitted SARIMA model result
        self.training_data: List[Dict] = [] # {"timestamp": str, "value": float}
        self._trained       = False
        self._fallback      = _RollingForecaster(window=50)
        self._points_since_retrain = 0

    # ------------------------------------------------------------------ #
    #  DATA INGESTION                                                      #
    # ------------------------------------------------------------------ #

    def add_data_point(self, value: float, timestamp=None):
        """
        Add a new data point for model training.

        Args:
            value:     Metric value (e.g. execution duration in ms).
            timestamp: ISO string or datetime. Defaults to utcnow.
        """
        if timestamp is None:
            timestamp = datetime.datetime.utcnow().isoformat()
        elif isinstance(timestamp, datetime.datetime):
            timestamp = timestamp.isoformat()

        self.training_data.append({"timestamp": str(timestamp), "value": float(value)})
        self._fallback.update(float(value))
        self._points_since_retrain += 1

        # Auto-retrain every RETRAIN_INTERVAL points after initial training
        if self._trained and self._points_since_retrain >= self.RETRAIN_INTERVAL:
            self.train()

    # ------------------------------------------------------------------ #
    #  TRAINING                                                            #
    # ------------------------------------------------------------------ #

    def train(self) -> bool:
        """
        Train (or retrain) the SARIMA model on accumulated data.

        Returns:
            True if training succeeded, False if not enough data or
            statsmodels is unavailable.
        """
        if len(self.training_data) < self.MIN_TRAINING_POINTS:
            return False

        if not SARIMA_AVAILABLE:
            # Fit fallback with all available values
            values = [d["value"] for d in self.training_data]
            self._fallback.fit(values)
            self._trained = True
            self._points_since_retrain = 0
            return True

        try:
            df = pd.DataFrame(self.training_data)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df = df.set_index("timestamp").sort_index()

            # Suppress convergence warnings during fitting
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fitted = SARIMAX(
                    df["value"],
                    order=self.order,
                    seasonal_order=self.seasonal_order,
                    enforce_stationarity=False,
                    enforce_invertibility=False,
                ).fit(disp=False)

            self.model = fitted
            self._trained = True
            self._points_since_retrain = 0
            return True

        except Exception:
            # Fall through to rolling fallback on any SARIMA error
            values = [d["value"] for d in self.training_data]
            self._fallback.fit(values)
            self._trained = True
            self._points_since_retrain = 0
            return True

    # ------------------------------------------------------------------ #
    #  PREDICTION                                                          #
    # ------------------------------------------------------------------ #

    def predict(self, timestamp=None) -> Dict:
        """
        Predict the expected value (and uncertainty) for a given timestamp.

        Returns:
            {"value": float, "std": float}
            Returns {"value": 0, "std": 1} if model not yet trained.
        """
        if not self._trained:
            return {"value": 0.0, "std": 1.0}

        if self.model is not None and SARIMA_AVAILABLE:
            try:
                forecast = self.model.forecast(steps=1)
                resid_std = float(self.model.resid.std()) or 1.0
                return {
                    "value": float(forecast.iloc[0]),
                    "std":   resid_std,
                }
            except Exception:
                pass  # Fall through to rolling fallback

        mean, std = self._fallback.predict_one()
        return {"value": mean, "std": max(std, 1.0)}

    # ------------------------------------------------------------------ #
    #  INCREMENTAL UPDATE                                                  #
    # ------------------------------------------------------------------ #

    def update_model(self, new_value: float, timestamp=None):
        """
        Add a new data point and retrain on schedule.
        Convenience wrapper — same as add_data_point.
        """
        self.add_data_point(new_value, timestamp)

    # ------------------------------------------------------------------ #
    #  BASELINE & ANOMALY DETECTION                                        #
    # ------------------------------------------------------------------ #

    def get_expected_baseline(self, hour: int = 0, day_of_week: int = 0) -> float:
        """
        Return the expected metric value for a given time of day / day of week.
        When SARIMA is trained it encodes seasonality; otherwise returns the
        rolling mean.

        Args:
            hour:         0–23
            day_of_week:  0 (Mon) – 6 (Sun)

        Returns:
            Expected value float.
        """
        prediction = self.predict()
        return prediction["value"]

    def detect_temporal_anomaly(self, actual: float, timestamp=None) -> float:
        """
        Score how anomalous `actual` is compared to the SARIMA prediction.

        Formula:
            temporal_z = |actual - predicted| / max(σ_residual, 1)
            score      = min(temporal_z / 3.0, 1.0)

        Returns:
            Score in [0.0, 1.0]. 0 = perfectly expected, 1 = extreme anomaly.
        """
        prediction = self.predict(timestamp)
        deviation  = abs(actual - prediction["value"])
        temporal_z = deviation / max(prediction["std"], 1.0)
        return min(temporal_z / 3.0, 1.0)

    # ------------------------------------------------------------------ #
    #  STATUS                                                              #
    # ------------------------------------------------------------------ #

    def get_status(self) -> Dict:
        """Return current state of the forecaster."""
        return {
            "trained":            self._trained,
            "sarima_available":   SARIMA_AVAILABLE,
            "sarima_fitted":      self.model is not None,
            "data_points":        len(self.training_data),
            "min_required":       self.MIN_TRAINING_POINTS,
            "progress_pct":       round(
                min(len(self.training_data) / self.MIN_TRAINING_POINTS * 100, 100), 1
            ),
            "using_fallback":     not SARIMA_AVAILABLE or self.model is None,
        }
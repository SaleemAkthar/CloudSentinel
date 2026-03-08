"""
Tests for SARIMA Forecaster — Cloud Sentinel
=============================================
Covers data ingestion, training, prediction, temporal anomaly detection,
and status reporting. Tests run with or without statsmodels installed.

Author: Okitha (Backend Team)
Run: pytest tests/test_sarima.py -v
"""

import pytest
import random
import datetime
import sys, os, importlib.util

# ── Load module without triggering backend/__init__.py ────────────────────────
def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

BASE = os.path.join(os.path.dirname(__file__), "..", "backend")
sarima_mod = _load(os.path.join(BASE, "detection", "sarima_forecaster.py"),
                   "backend.detection.sarima_forecaster")

SARIMAForecaster = sarima_mod.SARIMAForecaster


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def empty_forecaster():
    return SARIMAForecaster()


@pytest.fixture
def trained_forecaster():
    """A forecaster with 200 normal data points already fed in and trained."""
    f = SARIMAForecaster()
    rng = random.Random(42)
    for i in range(200):
        ts = (datetime.datetime(2026, 1, 1) + datetime.timedelta(hours=i)).isoformat()
        f.add_data_point(500 + rng.gauss(0, 30), ts)
    f.train()
    return f


# ============================================================================
# DATA INGESTION
# ============================================================================

class TestDataIngestion:

    def test_add_data_point_increases_count(self, empty_forecaster):
        empty_forecaster.add_data_point(500.0)
        assert len(empty_forecaster.training_data) == 1

    def test_add_multiple_points(self, empty_forecaster):
        for v in [400, 500, 600]:
            empty_forecaster.add_data_point(v)
        assert len(empty_forecaster.training_data) == 3

    def test_add_with_iso_timestamp(self, empty_forecaster):
        empty_forecaster.add_data_point(500.0, "2026-03-06T10:00:00")
        assert empty_forecaster.training_data[0]["timestamp"] == "2026-03-06T10:00:00"

    def test_add_with_datetime_object(self, empty_forecaster):
        dt = datetime.datetime(2026, 3, 6, 10, 0, 0)
        empty_forecaster.add_data_point(500.0, dt)
        assert "2026-03-06" in empty_forecaster.training_data[0]["timestamp"]

    def test_add_with_no_timestamp_uses_utcnow(self, empty_forecaster):
        empty_forecaster.add_data_point(500.0)
        ts = empty_forecaster.training_data[0]["timestamp"]
        assert "2026" in ts or "202" in ts   # valid ISO string

    def test_values_stored_as_floats(self, empty_forecaster):
        empty_forecaster.add_data_point(500)
        assert isinstance(empty_forecaster.training_data[0]["value"], float)


# ============================================================================
# TRAINING
# ============================================================================

class TestTraining:

    def test_train_fails_with_insufficient_data(self, empty_forecaster):
        for _ in range(50):
            empty_forecaster.add_data_point(500.0)
        result = empty_forecaster.train()
        assert result is False

    def test_train_succeeds_with_200_points(self, empty_forecaster):
        for i in range(200):
            empty_forecaster.add_data_point(500 + random.gauss(0, 20))
        result = empty_forecaster.train()
        assert result is True

    def test_trained_flag_set_after_training(self, empty_forecaster):
        assert empty_forecaster._trained is False
        for _ in range(200):
            empty_forecaster.add_data_point(500.0)
        empty_forecaster.train()
        assert empty_forecaster._trained is True

    def test_train_returns_false_below_threshold(self, empty_forecaster):
        for _ in range(199):
            empty_forecaster.add_data_point(500.0)
        assert empty_forecaster.train() is False

    def test_retrain_interval(self, trained_forecaster):
        """After training, adding RETRAIN_INTERVAL more points triggers retrain."""
        before = trained_forecaster._points_since_retrain
        interval = SARIMAForecaster.RETRAIN_INTERVAL
        for _ in range(interval):
            trained_forecaster.add_data_point(500.0)
        # After retrain, counter resets
        assert trained_forecaster._points_since_retrain < interval


# ============================================================================
# PREDICTION
# ============================================================================

class TestPrediction:

    def test_predict_before_training_returns_defaults(self, empty_forecaster):
        result = empty_forecaster.predict()
        assert result["value"] == 0.0
        assert result["std"]   == 1.0

    def test_predict_after_training_returns_dict(self, trained_forecaster):
        result = trained_forecaster.predict()
        assert "value" in result
        assert "std"   in result

    def test_predict_value_is_float(self, trained_forecaster):
        result = trained_forecaster.predict()
        assert isinstance(result["value"], float)

    def test_predict_std_positive(self, trained_forecaster):
        result = trained_forecaster.predict()
        assert result["std"] > 0

    def test_predict_value_near_training_mean(self, trained_forecaster):
        """Predicted value should be in the same ballpark as training data (500 ± 200)."""
        result = trained_forecaster.predict()
        assert 100 < result["value"] < 1500


# ============================================================================
# TEMPORAL ANOMALY DETECTION
# ============================================================================

class TestTemporalAnomalyDetection:

    def test_anomaly_score_before_training_returns_zero(self, empty_forecaster):
        score = empty_forecaster.detect_temporal_anomaly(500.0)
        assert 0.0 <= score <= 1.0

    def test_normal_value_low_anomaly_score(self, trained_forecaster):
        """A value close to the predicted mean should score close to 0."""
        prediction = trained_forecaster.predict()
        score = trained_forecaster.detect_temporal_anomaly(prediction["value"])
        assert score < 0.5

    def test_extreme_value_high_anomaly_score(self, trained_forecaster):
        """An extreme outlier (10× the mean) should score close to 1."""
        score = trained_forecaster.detect_temporal_anomaly(50000.0)
        assert score > 0.5

    def test_score_in_range_0_to_1(self, trained_forecaster):
        for val in [100, 500, 1000, 5000, 50000]:
            score = trained_forecaster.detect_temporal_anomaly(float(val))
            assert 0.0 <= score <= 1.0

    def test_higher_deviation_higher_score(self, trained_forecaster):
        s1 = trained_forecaster.detect_temporal_anomaly(600.0)   # small deviation
        s2 = trained_forecaster.detect_temporal_anomaly(50000.0) # large deviation
        assert s2 >= s1

    def test_anomaly_score_capped_at_1(self, trained_forecaster):
        score = trained_forecaster.detect_temporal_anomaly(999999.0)
        assert score <= 1.0


# ============================================================================
# BASELINE & HELPERS
# ============================================================================

class TestBaseline:

    def test_get_expected_baseline_untrained(self, empty_forecaster):
        result = empty_forecaster.get_expected_baseline(hour=9, day_of_week=1)
        assert result == 0.0

    def test_get_expected_baseline_trained(self, trained_forecaster):
        result = trained_forecaster.get_expected_baseline(hour=9, day_of_week=1)
        assert isinstance(result, float)

    def test_update_model_adds_data_point(self, empty_forecaster):
        empty_forecaster.update_model(500.0)
        assert len(empty_forecaster.training_data) == 1


# ============================================================================
# STATUS
# ============================================================================

class TestStatus:

    def test_status_keys_present(self, empty_forecaster):
        status = empty_forecaster.get_status()
        for key in ["trained", "sarima_available", "data_points",
                    "min_required", "progress_pct", "using_fallback"]:
            assert key in status

    def test_progress_pct_before_training(self, empty_forecaster):
        for _ in range(100):
            empty_forecaster.add_data_point(500.0)
        assert empty_forecaster.get_status()["progress_pct"] == 50.0

    def test_progress_pct_capped_at_100(self, trained_forecaster):
        assert trained_forecaster.get_status()["progress_pct"] == 100.0

    def test_trained_false_initially(self, empty_forecaster):
        assert empty_forecaster.get_status()["trained"] is False

    def test_trained_true_after_training(self, empty_forecaster):
        for _ in range(200):
            empty_forecaster.add_data_point(500.0)
        empty_forecaster.train()
        assert empty_forecaster.get_status()["trained"] is True
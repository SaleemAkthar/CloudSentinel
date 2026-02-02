# sentinel.py

from telemetry import TelemetryCollector
from feature_extractor import FeatureExtractor
from ml_model import AnomalyDetector

def cloud_sentinel_wrapper(func, event, context):
    telemetry = TelemetryCollector()
    extractor = FeatureExtractor()
    detector = AnomalyDetector()

    telemetry.start()

    try:
        result = func(event, context)
    except Exception:
        telemetry.record_error()
        raise
    finally:
        telemetry.stop()

    raw_telemetry = telemetry.get_telemetry()
    features = extractor.extract(raw_telemetry)
    inference = detector.infer(features)

    if inference["anomalous"]:
        print("⚠️ Cloud Sentinel Alert:", inference)

    return result

"""
Detection Package
=================

Multi-layer anomaly detection system.

Modules:
- layer1_scorer: Fast real-time weighted anomaly scoring
- layer2_investigator: Deep forensic analysis (Okitha)
- sarima_forecaster: Time-series forecasting for temporal analysis (Saleem)
- online_detector: River-based online ML detector
"""

from .layer1_scorer import Layer1Scorer

# Layer 2 and SARIMA will be imported when ready
# from .layer2_investigator import Layer2Investigator
# from .sarima_forecaster import SARIMAForecaster

__all__ = [
    'Layer1Scorer',
    # 'Layer2Investigator',  # Uncomment when Saleem completes
    # 'SARIMAForecaster',    # Uncomment when Okitha completes
]
"""
Detection Package

Multi-layer anomaly detection system.

Modules:
- layer1_scorer:       Fast real-time weighted anomaly scoring (Raneesha)
- layer2_investigator: Deep forensic analysis (Saleem)
- sarima_forecaster:   Time-series forecasting for temporal analysis (Okitha)
- online_detector:     Legacy statistical detector (deprecated)
"""

from .layer1_scorer import Layer1Scorer

# Uncomment these once Saleem's layer2_investigator.py is complete
# from .layer2_investigator import Layer2Investigator
# from .sarima_forecaster import SARIMAForecaster

__all__ = [
    'Layer1Scorer',
    # 'Layer2Investigator',
    # 'SARIMAForecaster',
]

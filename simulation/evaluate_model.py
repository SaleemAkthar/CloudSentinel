"""
evaluate_model.py
------------------
Run the synthetic dataset through Layer1Scorer and calculate
precision, recall, F1 score, and confusion matrix.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.layer1_scorer import Layer1Scorer
from backend.data_generator import EnhancedLogGenerator
from datetime import datetime
from collections import defaultdict


"""
ml/predict.py — Real-time attack classifier.

Loads the trained model and classifies incoming events.
Used by the honeypot services and dashboard.

Usage:
    from ml.predict import classify
    result = classify(event_dict)
    print(result)  # {"label": 1, "name": "Brute Force", "confidence": 0.97}
"""

import joblib
import numpy as np
from pathlib import Path

try:
    from capture.feature_extractor import extract
except ImportError:
    def extract(e): return [0]*14

MODEL_DIR   = Path("ml/model")
MODEL_PATH  = MODEL_DIR / "classifier.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"

ATTACK_LABELS = {
    0: "Normal",
    1: "Brute Force",
    2: "Port Scan",
    3: "DoS / Flood",
    4: "SQL Injection",
    5: "Command Injection",
    6: "Credential Stuffing",
}

# Severity mapping for dashboard colouring
SEVERITY = {
    0: "low",
    1: "high",
    2: "medium",
    3: "critical",
    4: "critical",
    5: "critical",
    6: "high",
}

_model  = None
_scaler = None


def _load():
    global _model, _scaler
    if _model is None:
        if not MODEL_PATH.exists():
            return False
        _model  = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
    return True


def classify(event: dict) -> dict:
    """
    Classify a honeypot event.

    Args:
        event: raw event dict from log_event()

    Returns:
        dict with keys: label, name, confidence, severity
        Returns None if model not trained yet.
    """
    if not _load():
        return None

    features = extract(event)
    X = np.array(features).reshape(1, -1)
    X_scaled = _scaler.transform(X)

    label      = int(_model.predict(X_scaled)[0])
    proba      = _model.predict_proba(X_scaled)[0]
    confidence = round(float(proba[label]), 4)

    return {
        "label"     : label,
        "name"      : ATTACK_LABELS.get(label, "Unknown"),
        "confidence": confidence,
        "severity"  : SEVERITY.get(label, "medium"),
    }


def classify_batch(events: list) -> list:
    """Classify a list of events. Returns list of result dicts."""
    if not _load():
        return [None] * len(events)

    from capture.feature_extractor import extract_batch
    X = np.array(extract_batch(events))
    X_scaled = _scaler.transform(X)

    labels     = _model.predict(X_scaled)
    probas     = _model.predict_proba(X_scaled)

    results = []
    for i, label in enumerate(labels):
        label = int(label)
        confidence = round(float(probas[i][label]), 4)
        results.append({
            "label"     : label,
            "name"      : ATTACK_LABELS.get(label, "Unknown"),
            "confidence": confidence,
            "severity"  : SEVERITY.get(label, "medium"),
        })
    return results
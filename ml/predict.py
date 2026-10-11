"""
ml/predict.py — Real-time attack classifier.
Returns label, name, real confidence and severity for each event.
"""
import joblib
import numpy as np
from pathlib import Path

try:
    from capture.feature_extractor import extract
except ImportError:
    def extract(e): return [0]*17

MODEL_DIR    = Path("ml/model")
MODEL_PATH   = MODEL_DIR / "classifier.joblib"
SCALER_PATH  = MODEL_DIR / "scaler.joblib"
ATTACK_LABELS = {
    0: "Normal",
    1: "Brute Force",
    2: "Port Scan",
    3: "DoS / Flood",
    4: "SQL Injection",
    5: "Command Injection",
    6: "Credential Stuffing",
}

SEVERITY = {
    0: "low",
    1: "high",
    2: "medium",
    3: "critical",
    4: "critical",
    5: "critical",
    6: "high",
}

_model = _scaler = None


def _load():
    global _model, _scaler
    if _model is None:
        if not MODEL_PATH.exists():
            return False
        _model  = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
    return True


def classify(event: dict) -> dict:
    if not _load():
        return None
    try:
        import json as _json
        details = event.get("details", {})
        if isinstance(details, str):
            try: details = _json.loads(details)
            except: details = {}
        ev2 = dict(event)
        ev2["details"] = details
        features = extract(ev2)
        X = np.array(features).reshape(1, -1)
        X_scaled = _scaler.transform(X)
        label = int(_model.predict(X_scaled)[0])
        try:
            proba = _model.predict_proba(X_scaled)[0]
            classes = [int(value) for value in _model.classes_]
            class_index = classes.index(label)
            confidence = round(float(proba[class_index]), 4)
        except Exception:
            confidence = 0.0
        return {
            "label"     : label,
            "name"      : ATTACK_LABELS.get(label, "Unknown"),
            "confidence": confidence,
            "severity"  : SEVERITY.get(label, "medium"),
        }
    except Exception as e:
        print(f"classify error: {e}")
        return None


def classify_batch(events: list) -> list:
    return [classify(e) for e in events]

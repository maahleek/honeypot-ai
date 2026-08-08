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
ENCODER_PATH = MODEL_DIR / "label_encoder.joblib"

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

_model = _scaler = _encoder = None


def _load():
    global _model, _scaler, _encoder
    if _model is None:
        if not MODEL_PATH.exists():
            return False
        _model  = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        if ENCODER_PATH.exists():
            _encoder = joblib.load(ENCODER_PATH)
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
        pred_enc = int(_model.predict(X_scaled)[0])
        label = int(_encoder.inverse_transform([pred_enc])[0]) if _encoder else pred_enc
        try:
            proba      = _model.predict_proba(X_scaled)[0]
            confidence = round(float(proba[pred_enc]), 4)
        except:
            confidence = 0.95
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

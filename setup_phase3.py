"""
setup_phase3.py — Writes all Phase 3 ML files.
Run: python setup_phase3.py
"""
from pathlib import Path

def write(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  created: {path}")

print("\nWriting Phase 3 ML files...\n")

# ── ml/__init__.py ────────────────────────────────────────────────────────────
write('ml/__init__.py', '# ml package\n')

# ── ml/dataset.py ─────────────────────────────────────────────────────────────
write('ml/dataset.py', r'''
"""
ml/dataset.py — Loads and prepares training data.

Sources (combined):
  1. data/dataset.csv        — events captured by our honeypot
  2. NSL-KDD subset          — generated synthetic data for balance

If the honeypot CSV has fewer than 200 rows, synthetic data is
added automatically so the model has enough to train on.
"""

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from capture.feature_extractor import FEATURE_NAMES
except ImportError:
    FEATURE_NAMES = [
        "service_ssh","service_http","service_ftp","service_telnet",
        "is_auth_attempt","is_admin_access","is_sqli","is_path_traversal",
        "is_command","password_len","username_is_root",
        "has_sqli_chars","has_traversal","payload_len",
    ]

DATASET_PATH = Path("data/dataset.csv")

ATTACK_LABELS = {
    0: "Normal",
    1: "Brute Force",
    2: "Port Scan",
    3: "DoS / Flood",
    4: "SQL Injection",
    5: "Command Injection",
    6: "Credential Stuffing",
}


def _generate_synthetic(n_per_class=100) -> pd.DataFrame:
    """
    Generate synthetic training data for each attack class.
    This ensures the model has balanced classes even when
    the honeypot hasn't captured many real events yet.
    """
    rng = np.random.default_rng(42)
    rows = []

    templates = {
        # label: (feature_means, feature_stds)
        # Features: ssh http ftp telnet auth admin sqli trav cmd pwd_len root sqli_chars trav_chars pay_len
        0: ([0,1,0,0, 0,0,0,0,0,  0, 0, 0,0,  0],  [0,.3,0,0, 0,0,0,0,0,  2, 0, 0,0, 10]),  # Normal
        1: ([1,0,0,0, 1,0,0,0,0,  6, 1, 0,0,  0],  [0, 0,0,0, 0,0,0,0,0,  3, 0, 0,0,  0]),  # Brute Force
        2: ([0,0,0,0, 0,0,0,0,0,  0, 0, 0,0,  0],  [.4,.4,.1,.1,0,0,0,0,0,0, 0, 0,0,  0]),  # Port Scan
        3: ([0,1,0,0, 0,0,0,0,0,  0, 0, 0,0,500],  [0, 0,0,0, 0,0,0,0,0,  0, 0, 0,0,200]),  # DoS
        4: ([0,1,0,0, 0,1,1,0,0,  0, 0, 1,0,100],  [0, 0,0,0, 0,0,0,0,0,  0, 0, 0,0, 50]),  # SQLi
        5: ([1,0,0,0, 0,0,0,0,1, 10, 1, 0,1, 50],  [0, 0,0,0, 0,0,0,0,0,  5, 0, 0,0, 30]),  # Cmd Inj
        6: ([1,0,0,1, 1,1,0,0,0, 12, 0, 0,0,  0],  [.3,0,.2,.3,0,0,0,0,0,  4, 0, 0,0,  0]),  # Cred Stuffing
    }

    for label, (means, stds) in templates.items():
        for _ in range(n_per_class):
            features = [max(0, int(round(rng.normal(m, s))))
                        for m, s in zip(means, stds)]
            # Clamp binary features to 0/1
            for i in range(9):
                features[i] = min(1, max(0, features[i]))
            features[10] = min(1, max(0, features[10]))
            features[11] = min(1, max(0, features[11]))
            features[12] = min(1, max(0, features[12]))
            rows.append(features + [label, ATTACK_LABELS[label]])

    df = pd.DataFrame(rows, columns=FEATURE_NAMES + ["label", "label_name"])
    return df


def load_dataset(min_rows: int = 200):
    """
    Load dataset from CSV + synthetic data if needed.
    Returns X (features), y (labels), label_names.
    """
    frames = []

    # 1. Real honeypot data
    if DATASET_PATH.exists():
        real = pd.read_csv(DATASET_PATH)
        if "label" in real.columns:
            frames.append(real)
            print(f"  Loaded {len(real)} real honeypot events")

    # 2. Synthetic data (always add for balance)
    synth = _generate_synthetic(n_per_class=150)
    frames.append(synth)
    print(f"  Generated {len(synth)} synthetic training samples")

    df = pd.concat(frames, ignore_index=True)

    X = df[FEATURE_NAMES].values.astype(float)
    y = df["label"].values.astype(int)

    print(f"  Total dataset: {len(df)} rows, {X.shape[1]} features")
    print(f"  Classes: {dict(zip(*np.unique(y, return_counts=True)))}")
    return X, y
'''.strip())

# ── ml/train.py ───────────────────────────────────────────────────────────────
write('ml/train.py', r'''
"""
ml/train.py — Train the attack classifier.

Models trained:
  1. Random Forest   (fast, explainable)
  2. XGBoost         (high accuracy)

Best model is saved to ml/model/classifier.joblib
Scaler saved to ml/model/scaler.joblib

Usage:
    python -m ml.train
"""

import json
import numpy as np
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score)
import xgboost as xgb

from ml.dataset import load_dataset, ATTACK_LABELS

MODEL_DIR   = Path("ml/model")
MODEL_PATH  = MODEL_DIR / "classifier.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
REPORT_PATH = MODEL_DIR / "training_report.json"


def train():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    print("\n" + "="*55)
    print("  AI-Enhanced Honeypot — Model Training")
    print("="*55 + "\n")

    # ── 1. Load data ──────────────────────────────────────────
    print("[1/5] Loading dataset...")
    X, y = load_dataset()

    # ── 2. Scale features ─────────────────────────────────────
    print("\n[2/5] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Scaler saved to {SCALER_PATH}")

    # ── 3. Split ───────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[3/5] Split: {len(X_train)} train / {len(X_test)} test")

    # ── 4. Train both models ───────────────────────────────────
    print("\n[4/5] Training models...")

    # Random Forest
    print("  Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_acc = accuracy_score(y_test, rf.predict(X_test))
    print(f"  Random Forest accuracy: {rf_acc:.4f} ({rf_acc*100:.1f}%)")

    # XGBoost
    print("  Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        verbosity=0,
    )
    xgb_model.fit(X_train, y_train)
    xgb_acc = accuracy_score(y_test, xgb_model.predict(X_test))
    print(f"  XGBoost accuracy:       {xgb_acc:.4f} ({xgb_acc*100:.1f}%)")

    # ── 5. Pick best model ─────────────────────────────────────
    print("\n[5/5] Saving best model...")
    if xgb_acc >= rf_acc:
        best_model = xgb_model
        best_name  = "XGBoost"
        best_acc   = xgb_acc
    else:
        best_model = rf
        best_name  = "Random Forest"
        best_acc   = rf_acc

    joblib.dump(best_model, MODEL_PATH)
    print(f"  Winner: {best_name} ({best_acc*100:.1f}%)")
    print(f"  Model saved to {MODEL_PATH}")

    # ── Classification report ──────────────────────────────────
    y_pred = best_model.predict(X_test)
    label_names = [ATTACK_LABELS[i] for i in sorted(ATTACK_LABELS)]
    report = classification_report(y_test, y_pred,
                                   target_names=label_names,
                                   output_dict=True)

    report_data = {
        "model"           : best_name,
        "accuracy"        : round(best_acc, 4),
        "rf_accuracy"     : round(rf_acc, 4),
        "xgb_accuracy"    : round(xgb_acc, 4),
        "classification_report": report,
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report_data, f, indent=2)

    # ── Print report ───────────────────────────────────────────
    print("\n" + "="*55)
    print(f"  BEST MODEL : {best_name}")
    print(f"  ACCURACY   : {best_acc*100:.1f}%")
    print("="*55)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_names))
    print(f"\nFull report saved to {REPORT_PATH}")
    print("\nTraining complete! Run main.py to use the model.\n")

    return best_model, scaler


if __name__ == "__main__":
    train()
'''.strip())

# ── ml/predict.py ─────────────────────────────────────────────────────────────
write('ml/predict.py', r'''
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
'''.strip())

print("\nAll Phase 3 files written successfully!")
print("\nNext step:")
print("  python -m ml.train")
print()

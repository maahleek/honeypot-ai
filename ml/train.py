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
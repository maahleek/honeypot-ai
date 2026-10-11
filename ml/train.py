"""
ml/train.py — Train and evaluate the honeypot attack classifier.

Both Random Forest and XGBoost are trained on:
  genuine training partition + synthetic training-only examples

Final reported metrics are calculated only on the untouched genuine
honeypot test partition.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler

from ml.dataset import ATTACK_LABELS, load_training_split

MODEL_DIR = Path("ml/model")
MODEL_PATH = MODEL_DIR / "classifier.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
REPORT_PATH = MODEL_DIR / "training_report.json"


def _evaluate(model, X_test, y_test):
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    labels = sorted(int(x) for x in np.unique(y_test))
    names = [ATTACK_LABELS[label] for label in labels]
    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        target_names=names,
        output_dict=True,
        zero_division=0,
    )
    return float(accuracy), predictions, report


def train():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 60)
    print("  AI-Enhanced Honeypot — Reproducible Model Training")
    print("=" * 60)

    X_train, X_test, y_train, y_test, metadata = load_training_split()

    print(
        f"\nGenuine data: {metadata['genuine_total']} rows "
        f"({metadata['genuine_train']} train / {metadata['genuine_test']} test)"
    )
    print(f"Synthetic rows added to training only: {metadata['synthetic_train']}")
    print(f"Features: {metadata['feature_count']}")

    # Fit preprocessing on training data only to prevent test-set leakage.
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train_scaled, y_train)
    rf_acc, rf_pred, rf_report = _evaluate(rf, X_test_scaled, y_test)

    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="mlogloss",
        random_state=42,
        verbosity=0,
    )
    xgb_model.fit(X_train_scaled, y_train)
    xgb_acc, xgb_pred, xgb_report = _evaluate(
        xgb_model,
        X_test_scaled,
        y_test,
    )

    # Prefer Random Forest on an exact tie because it is easier to explain
    # during an academic defense and cheaper to run at inference time.
    if rf_acc >= xgb_acc:
        best_model = rf
        best_name = "Random Forest"
        best_acc = rf_acc
        best_pred = rf_pred
        best_report = rf_report
    else:
        best_model = xgb_model
        best_name = "XGBoost"
        best_acc = xgb_acc
        best_pred = xgb_pred
        best_report = xgb_report

    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    report_data = {
        "evaluation_protocol": {
            **metadata,
            "synthetic_in_test_set": False,
            "scaler_fit_on_training_only": True,
        },
        "selected_model": best_name,
        "selected_accuracy": round(best_acc, 6),
        "random_forest_accuracy": round(rf_acc, 6),
        "xgboost_accuracy": round(xgb_acc, 6),
        "classification_report": best_report,
    }
    REPORT_PATH.write_text(
        json.dumps(report_data, indent=2),
        encoding="utf-8",
    )

    labels = sorted(int(x) for x in np.unique(y_test))
    names = [ATTACK_LABELS[label] for label in labels]

    print("\n" + "=" * 60)
    print(f"  SELECTED MODEL : {best_name}")
    print(f"  GENUINE TEST ACCURACY : {best_acc * 100:.2f}%")
    print("=" * 60)
    print(
        classification_report(
            y_test,
            best_pred,
            labels=labels,
            target_names=names,
            zero_division=0,
        )
    )
    print(f"Model saved to {MODEL_PATH}")
    print(f"Scaler saved to {SCALER_PATH}")
    print(f"Evaluation report saved to {REPORT_PATH}\n")

    return best_model, scaler


if __name__ == "__main__":
    train()

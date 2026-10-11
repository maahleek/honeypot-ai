"""
ml/dataset.py — Dataset preparation for the honeypot classifier.

The important evaluation rule is simple:
- genuine honeypot events are split into train/test first;
- synthetic rows are added to the TRAINING partition only;
- the held-out test partition contains genuine captured events only.

This keeps synthetic examples from inflating the final real-world evaluation.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from capture.feature_extractor import FEATURE_NAMES

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

_EVENT_FLAG_COLUMNS = {
    "is_connection": "CONNECTION",
    "is_disconnection": "DISCONNECTION",
    "is_request": "REQUEST",
}


def _upgrade_legacy_features(df: pd.DataFrame) -> pd.DataFrame:
    """Backfill the three event-type features missing from older CSV exports."""
    upgraded = df.copy()
    event_type = upgraded.get("event_type")
    for column, expected in _EVENT_FLAG_COLUMNS.items():
        if column not in upgraded.columns:
            if event_type is None:
                upgraded[column] = 0
            else:
                upgraded[column] = (
                    event_type.astype(str).str.upper().eq(expected).astype(int)
                )

    missing = [name for name in FEATURE_NAMES if name not in upgraded.columns]
    if missing:
        raise ValueError(
            "Dataset is missing required feature column(s): "
            + ", ".join(missing)
        )

    for name in FEATURE_NAMES:
        upgraded[name] = pd.to_numeric(upgraded[name], errors="coerce").fillna(0)

    upgraded["label"] = pd.to_numeric(
        upgraded.get("label"),
        errors="coerce",
    )
    upgraded = upgraded.dropna(subset=["label"]).copy()
    upgraded["label"] = upgraded["label"].astype(int)
    return upgraded


def load_real_dataframe(path: Path = DATASET_PATH) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing. Capture/export honeypot events before training."
        )

    real = pd.read_csv(path)
    if real.empty:
        raise ValueError(f"{path} contains no training rows.")

    real = _upgrade_legacy_features(real)
    unknown = sorted(set(real["label"]) - set(ATTACK_LABELS))
    if unknown:
        raise ValueError(f"Dataset contains unsupported labels: {unknown}")

    return real


def _sample_nonnegative_int(rng: np.random.Generator, mean: float, std: float) -> int:
    return max(0, int(round(rng.normal(mean, std))))


def _generate_synthetic(n_per_class: int = 150) -> pd.DataFrame:
    """Generate training-only examples for sparse/absent classes."""
    rng = np.random.default_rng(42)
    rows: list[dict[str, int | str]] = []

    for label in ATTACK_LABELS:
        for _ in range(n_per_class):
            row = {name: 0 for name in FEATURE_NAMES}

            if label == 0:  # normal request
                row["service_http"] = 1
                row["is_request"] = 1
                row["payload_len"] = _sample_nonnegative_int(rng, 20, 15)

            elif label == 1:  # brute force
                row["service_ssh"] = 1
                row["is_auth_attempt"] = 1
                row["password_len"] = _sample_nonnegative_int(rng, 6, 3)
                row["username_is_root"] = int(rng.random() < 0.7)

            elif label == 2:  # port scan
                service = rng.choice(
                    ["service_ssh", "service_http", "service_ftp", "service_telnet"]
                )
                row[str(service)] = 1
                row["is_connection"] = 1

            elif label == 3:  # DoS/flood
                row["service_http"] = 1
                row["is_request"] = 1
                row["payload_len"] = _sample_nonnegative_int(rng, 500, 200)

            elif label == 4:  # SQL injection
                row["service_http"] = 1
                row["is_sqli"] = 1
                row["is_request"] = 1
                row["has_sqli_chars"] = 1
                row["payload_len"] = _sample_nonnegative_int(rng, 100, 50)

            elif label == 5:  # command injection
                row["service_ssh"] = 1
                row["is_command"] = 1
                row["has_traversal"] = int(rng.random() < 0.3)
                row["payload_len"] = _sample_nonnegative_int(rng, 50, 30)

            elif label == 6:  # credential stuffing
                if rng.random() < 0.7:
                    row["service_ssh"] = 1
                else:
                    row["service_telnet"] = 1
                row["is_auth_attempt"] = 1
                row["password_len"] = _sample_nonnegative_int(rng, 12, 4)
                row["username_is_root"] = int(rng.random() < 0.2)

            row["label"] = label
            row["label_name"] = ATTACK_LABELS[label]
            row["source"] = "synthetic"
            rows.append(row)

    return pd.DataFrame(rows)


def load_training_split(
    *,
    test_size: float = 0.20,
    synthetic_per_class: int = 150,
    random_state: int = 42,
):
    """Return train/test arrays with a genuine-only held-out test partition."""
    real = load_real_dataframe().copy()
    real["source"] = "genuine"

    counts = real["label"].value_counts()
    stratify = real["label"] if len(counts) > 1 and int(counts.min()) >= 2 else None

    real_train, real_test = train_test_split(
        real,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    synthetic = _generate_synthetic(n_per_class=synthetic_per_class)
    train_df = pd.concat([real_train, synthetic], ignore_index=True)

    X_train = train_df[FEATURE_NAMES].to_numpy(dtype=float)
    y_train = train_df["label"].to_numpy(dtype=int)
    X_test = real_test[FEATURE_NAMES].to_numpy(dtype=float)
    y_test = real_test["label"].to_numpy(dtype=int)

    metadata = {
        "feature_count": len(FEATURE_NAMES),
        "genuine_total": int(len(real)),
        "genuine_train": int(len(real_train)),
        "genuine_test": int(len(real_test)),
        "synthetic_train": int(len(synthetic)),
        "training_total": int(len(train_df)),
        "test_is_genuine_only": True,
        "test_labels": sorted(int(x) for x in np.unique(y_test)),
    }
    return X_train, X_test, y_train, y_test, metadata


def load_dataset():
    """Backward-compatible combined dataset helper for notebooks/tools."""
    real = load_real_dataframe().copy()
    synthetic = _generate_synthetic(n_per_class=150)
    combined = pd.concat([real, synthetic], ignore_index=True)
    return (
        combined[FEATURE_NAMES].to_numpy(dtype=float),
        combined["label"].to_numpy(dtype=int),
    )

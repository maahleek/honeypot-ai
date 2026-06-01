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
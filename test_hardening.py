from pathlib import Path

import pandas as pd

from capture.feature_extractor import FEATURE_NAMES, extract
from capture.logger import _sanitize_details
from config import FTP_ROOT
from ml.dataset import DATASET_PATH, load_training_split


def test_feature_vector_handles_redacted_passwords():
    raw = {
        "service": "SSH",
        "event_type": "AUTH_ATTEMPT",
        "details": {"username": "root", "password": "secret"},
    }
    redacted = {
        "service": "SSH",
        "event_type": "AUTH_ATTEMPT",
        "details": {"username": "root", "password_len": 6},
    }
    assert len(extract(raw)) == 17
    assert extract(raw) == extract(redacted)


def test_passwords_are_redacted_before_persistence():
    details = _sanitize_details({"username": "root", "password": "secret"})
    assert "password" not in details
    assert details["password_len"] == 6


def test_published_dataset_has_no_attacker_ip_column():
    frame = pd.read_csv(DATASET_PATH, nrows=5)
    assert "attacker_ip" not in frame.columns


def test_training_split_uses_genuine_only_test_partition():
    X_train, X_test, y_train, y_test, metadata = load_training_split()
    assert X_train.shape[1] == len(FEATURE_NAMES) == 17
    assert X_test.shape[1] == 17
    assert metadata["genuine_total"] == 13616
    assert metadata["genuine_test"] == 2724
    assert metadata["synthetic_train"] == 1050
    assert metadata["test_is_genuine_only"] is True
    assert len(X_test) == len(y_test) == 2724
    assert len(X_train) == len(y_train)


def test_ftp_root_is_isolated_under_project_data():
    parts = [part.casefold() for part in Path(FTP_ROOT).parts]
    assert "data" in parts
    assert Path(FTP_ROOT).name == "ftp_root"


if __name__ == "__main__":
    test_feature_vector_handles_redacted_passwords()
    test_passwords_are_redacted_before_persistence()
    test_published_dataset_has_no_attacker_ip_column()
    test_training_split_uses_genuine_only_test_partition()
    test_ftp_root_is_isolated_under_project_data()
    print("Honeypot hardening tests passed.")

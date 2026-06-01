"""
capture/exporter.py — Export honeypot database to CSV for ML training.

Usage:
    python capture/exporter.py

Produces:
    data/dataset.csv   — feature matrix, one row per event
"""

import csv
import json
from pathlib import Path

from capture.database import Session, AttackEvent
from capture.feature_extractor import extract, FEATURE_NAMES

try:
    from config import ATTACK_LABELS
except ImportError:
    ATTACK_LABELS = {
        0: "Normal",
        1: "Brute Force",
        2: "Port Scan",
        3: "DoS / Flood",
        4: "SQL Injection",
        5: "Command Injection",
        6: "Credential Stuffing",
    }

OUTPUT_PATH = Path("data/dataset.csv")


def _auto_label(event_type: str, details: dict) -> int:
    """
    Automatically assign an attack label based on event type.
    This gives us labelled training data from the honeypot itself.
    """
    et = event_type.upper()
    if et == "SQLI_ATTEMPT":                           return 4
    if et == "COMMAND":                                return 5
    if et == "PATH_TRAVERSAL":                         return 5
    if et in ("AUTH_ATTEMPT", "CREDENTIAL_ATTEMPT"):
        pwd = details.get("password", "")
        if len(str(pwd)) <= 4: return 1   # very short = brute-force default
        return 6                           # longer = credential stuffing
    if et == "ADMIN_ACCESS":                           return 6
    if et == "CONNECTION":                             return 2
    return 0


def export_csv(output_path: Path = OUTPUT_PATH) -> int:
    """
    Read all events from the DB, extract features, auto-label,
    and write to CSV. Returns number of rows written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    session = Session()
    try:
        rows = session.query(AttackEvent).order_by(AttackEvent.id).all()
    finally:
        session.close()

    if not rows:
        print("No events in database yet. Run the honeypot first.")
        return 0

    headers = FEATURE_NAMES + ["label", "label_name",
                                "event_type", "service", "attacker_ip"]

    count = 0
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for row in rows:
            try:
                details = json.loads(row.details) if row.details else {}
            except Exception:
                details = {}

            event = {
                "service"   : row.service,
                "event_type": row.event_type,
                "details"   : details,
            }
            features   = extract(event)
            label      = _auto_label(row.event_type, details)
            label_name = ATTACK_LABELS.get(label, "Unknown")

            writer.writerow(
                features + [label, label_name, row.event_type,
                             row.service, row.attacker_ip]
            )
            count += 1

    print(f"Exported {count} events to {output_path}")
    return count


if __name__ == "__main__":
    export_csv()
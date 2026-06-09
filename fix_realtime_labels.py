"""
fix_realtime_labels.py — Makes AI labels appear in real-time.
Run: python fix_realtime_labels.py
"""
from pathlib import Path

content = '''
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

import colorlog

try:
    from config import LOG_DIR, LOG_FILE
except ImportError:
    LOG_DIR  = Path("logs")
    LOG_FILE = LOG_DIR / "attacks.jsonl"

Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

_file_lock  = threading.Lock()

# ── Lazy imports ──────────────────────────────────────────────────────────────
_db_save  = None
_classify = None

def _get_db_save():
    global _db_save
    if _db_save is None:
        try:
            from capture.database import save_event
            _db_save = save_event
        except Exception:
            _db_save = lambda e: None
    return _db_save

def _get_classify():
    global _classify
    if _classify is None:
        try:
            from ml.predict import classify
            _classify = classify
        except Exception:
            _classify = lambda e: None
    return _classify

# ── Console logger ─────────────────────────────────────────────────────────
_handler = colorlog.StreamHandler()
_handler.setFormatter(colorlog.ColoredFormatter(
    fmt="%(log_color)s%(asctime)s%(reset)s [%(log_color)s%(levelname)-8s%(reset)s] %(cyan)s%(name)-10s%(reset)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    log_colors={
        "DEBUG"   : "white",
        "INFO"    : "green",
        "WARNING" : "yellow",
        "ERROR"   : "red",
        "CRITICAL": "bold_red",
    }
))
logging.basicConfig(level=logging.INFO, handlers=[_handler])


def get_logger(name: str):
    return logging.getLogger(name)


def log_event(service, attacker_ip, attacker_port, event_type, details=None):
    """
    Log a honeypot event:
      1. Classify immediately with AI
      2. Write to JSONL file
      3. Save to database WITH label already attached
      4. Print to console
    """
    event = {
        "timestamp"    : datetime.now(timezone.utc).isoformat(),
        "service"      : service,
        "attacker_ip"  : attacker_ip,
        "attacker_port": attacker_port,
        "event_type"   : event_type,
        "details"      : details or {},
    }

    # ── 1. AI Classification FIRST (before DB save) ───────────────────────
    classification = None
    try:
        classification = _get_classify()(event)
        if classification:
            event["classification"] = classification
    except Exception as e:
        get_logger("logger").debug(f"Classification failed: {e}")

    # ── 2. Write to JSONL ─────────────────────────────────────────────────
    with _file_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\\n")

    # ── 3. Save to DB with label ──────────────────────────────────────────
    try:
        db_event = dict(event)
        if classification:
            # Inject label into details so database.py picks it up
            db_event["attack_label"] = classification.get("label")
            db_event["attack_name"]  = classification.get("name")
        _save_with_label(db_event, classification)
    except Exception as e:
        get_logger("logger").debug(f"DB save failed: {e}")

    # ── 4. Console output ─────────────────────────────────────────────────
    logger = get_logger(service)
    if classification:
        label    = classification.get("name", "?")
        conf     = classification.get("confidence", 0)
        severity = classification.get("severity", "?")
        logger.info(
            f"[{event_type}] {attacker_ip}:{attacker_port} | "
            f"AI: {label} ({conf*100:.0f}%) [{severity.upper()}]"
        )
    else:
        logger.info(f"[{event_type}] {attacker_ip}:{attacker_port} | {details}")

    return event


def _save_with_label(event: dict, classification: dict):
    """Save event to DB and immediately update with AI label."""
    import json as _json
    from capture.database import Session, AttackEvent
    from datetime import datetime, timezone

    details = event.get("details", {})
    ts_raw  = event.get("timestamp")
    try:
        ts = datetime.fromisoformat(ts_raw).replace(tzinfo=None) if ts_raw else datetime.utcnow()
    except Exception:
        ts = datetime.utcnow()

    row = AttackEvent(
        timestamp     = ts,
        service       = event.get("service", ""),
        attacker_ip   = event.get("attacker_ip", ""),
        attacker_port = event.get("attacker_port", 0),
        event_type    = event.get("event_type", ""),
        details       = _json.dumps(details),
        username      = details.get("username"),
        password      = details.get("password"),
        password_len  = len(details["password"]) if details.get("password") else None,
        http_method   = details.get("method"),
        http_path     = details.get("path"),
        user_agent    = details.get("user_agent"),
        payload       = details.get("body") or details.get("command"),
        # ── AI label saved immediately ────────────────────────────────────
        attack_label  = classification.get("label") if classification else None,
        attack_name   = classification.get("name")  if classification else None,
    )

    session = Session()
    try:
        session.add(row)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()
'''.strip()

Path("capture/logger.py").write_text(content, encoding="utf-8")
print("Fixed: capture/logger.py")
print("AI labels will now appear in real-time on the dashboard!")

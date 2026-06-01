"""
capture/logger.py — Shared event logger with real-time AI classification.

Every honeypot event is:
  1. Logged to console (colorized)
  2. Written to JSONL file
  3. Saved to SQLite database
  4. Classified by the AI model in real-time
  5. Broadcast to dashboard via event queue
"""
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue

import colorlog

try:
    from config import LOG_DIR, LOG_FILE
except ImportError:
    LOG_DIR  = Path("logs")
    LOG_FILE = LOG_DIR / "attacks.jsonl"

Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

_file_lock  = threading.Lock()
event_queue = Queue(maxsize=1000)   # dashboard reads from this

# ── Lazy imports (avoid circular dependencies) ────────────────────────────────
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

# ── Console logger ────────────────────────────────────────────────────────────
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
    Log a honeypot event, classify it with AI, and broadcast to dashboard.
    """
    event = {
        "timestamp"    : datetime.now(timezone.utc).isoformat(),
        "service"      : service,
        "attacker_ip"  : attacker_ip,
        "attacker_port": attacker_port,
        "event_type"   : event_type,
        "details"      : details or {},
    }

    # 1. Write to JSONL
    with _file_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    # 2. Save to database
    try:
        _get_db_save()(event)
    except Exception as e:
        get_logger("logger").debug(f"DB save failed: {e}")

    # 3. AI Classification
    classification = None
    try:
        classification = _get_classify()(event)
        if classification:
            event["classification"] = classification
    except Exception as e:
        get_logger("logger").debug(f"Classification failed: {e}")

    # 4. Push to dashboard queue
    try:
        event_queue.put_nowait(event)
    except Exception:
        pass

    # 5. Console output
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
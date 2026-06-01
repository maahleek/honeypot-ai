"""
setup_phase4.py — Writes all Phase 4 real-time inference files.
Run: python setup_phase4.py
"""
from pathlib import Path

def write(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  created: {path}")

print("\nWriting Phase 4 files...\n")

# ── Updated capture/logger.py — now classifies every event in real-time ───────
write('capture/logger.py', r'''
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
'''.strip())


# ── capture/inference_engine.py ───────────────────────────────────────────────
write('capture/inference_engine.py', r'''
"""
capture/inference_engine.py — Background inference engine.

Runs in a separate thread and continuously classifies
events from the queue, updating the database with labels.

This decouples classification from the honeypot services
so slow model inference never blocks attack capture.
"""
import threading
import time
from capture.logger import event_queue, get_logger

logger = get_logger("AI-ENGINE")
_running = False


def _worker():
    """Background thread: classify events from the queue."""
    logger.info("AI Inference Engine started")

    try:
        from ml.predict import classify
        from capture.database import Session, AttackEvent
        model_available = True
        logger.info("AI model loaded successfully")
    except Exception as e:
        logger.warning(f"AI model not available: {e}")
        model_available = False

    while _running:
        try:
            if event_queue.empty():
                time.sleep(0.05)
                continue

            event = event_queue.get(timeout=0.1)

            if model_available and "classification" not in event:
                try:
                    result = classify(event)
                    if result:
                        # Update DB with classification
                        session = Session()
                        try:
                            from sqlalchemy import desc
                            row = (session.query(AttackEvent)
                                   .filter_by(
                                       attacker_ip=event.get("attacker_ip"),
                                       event_type =event.get("event_type"),
                                       service    =event.get("service"),
                                   )
                                   .order_by(desc(AttackEvent.id))
                                   .first())
                            if row:
                                row.attack_label = result["label"]
                                row.attack_name  = result["name"]
                                session.commit()
                        except Exception:
                            session.rollback()
                        finally:
                            session.close()
                except Exception as e:
                    logger.debug(f"Inference error: {e}")

            event_queue.task_done()

        except Exception:
            pass


def start():
    """Start the background inference engine thread."""
    global _running
    _running = True
    t = threading.Thread(target=_worker, name="InferenceEngine", daemon=True)
    t.start()
    return t


def stop():
    """Stop the inference engine."""
    global _running
    _running = False
'''.strip())


# ── Updated main.py — now starts inference engine alongside honeypots ─────────
write('main.py', r'''
"""
main.py — AI-Enhanced Honeypot System — Entry Point (Phase 4)

Starts all services:
  • SSH Honeypot       (port 2222)
  • HTTP Honeypot      (port 8080)
  • FTP Honeypot       (port 2121)
  • Telnet Honeypot    (port 2323)
  • AI Inference Engine (background thread)
"""

import sys
import threading
import time
from pathlib import Path

for d in ["data", "logs", "ml/model"]:
    Path(d).mkdir(parents=True, exist_ok=True)

from capture.logger import get_logger
from config import SSH_PORT, HTTP_PORT, FTP_PORT, TELNET_PORT

from honeypots.ssh_honeypot    import start_ssh_honeypot
from honeypots.http_honeypot   import start_http_honeypot
from honeypots.ftp_honeypot    import start_ftp_honeypot
from honeypots.telnet_honeypot import start_telnet_honeypot
from capture.inference_engine  import start as start_inference

logger = get_logger("MAIN")


def _print_banner():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║       AI-Enhanced Honeypot System  v1.0 (Phase 4)       ║
║          Real-Time Attack Classification Active          ║
╠══════════════════════════════════════════════════════════╣
║  SSH       │  {SSH_PORT:<5}                                    ║
║  HTTP      │  {HTTP_PORT:<5}                                    ║
║  FTP       │  {FTP_PORT:<5}                                    ║
║  Telnet    │  {TELNET_PORT:<5}                                    ║
║  AI Engine │  Active                                     ║
╠══════════════════════════════════════════════════════════╣
║  Logs      →  logs/attacks.jsonl                         ║
║  Database  →  data/honeypot.db                           ║
║  Dashboard →  http://localhost:5000  (Phase 5)           ║
╚══════════════════════════════════════════════════════════╝
""")


_SERVICES = [
    ("SSH-Honeypot",    start_ssh_honeypot),
    ("HTTP-Honeypot",   start_http_honeypot),
    ("FTP-Honeypot",    start_ftp_honeypot),
    ("Telnet-Honeypot", start_telnet_honeypot),
]


def _launch(name, fn):
    t = threading.Thread(target=fn, name=name, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    _print_banner()

    # Start AI inference engine first
    start_inference()
    logger.info("AI Inference Engine started")
    time.sleep(0.5)

    # Start honeypot services
    threads = []
    for name, fn in _SERVICES:
        try:
            t = _launch(name, fn)
            threads.append(t)
            logger.info(f"✓ {name} started")
            time.sleep(0.3)
        except Exception as e:
            logger.error(f"✗ Failed to start {name}: {e}")

    logger.info("All honeypots running. Listening for attackers... (Ctrl+C to stop)\n")

    try:
        while True:
            time.sleep(1)
            for i, (name, fn) in enumerate(_SERVICES):
                if not threads[i].is_alive():
                    logger.warning(f"⚠  {name} died — restarting...")
                    threads[i] = _launch(name, fn)
    except KeyboardInterrupt:
        print()
        logger.info("Shutdown requested. Stopping honeypots...")
        sys.exit(0)
'''.strip())


# ── test_classifier.py — quick sanity check ───────────────────────────────────
write('test_classifier.py', r'''
"""
test_classifier.py — Test the AI classifier with sample events.
Run: python test_classifier.py
"""
from ml.predict import classify

test_events = [
    {
        "service": "SSH", "event_type": "AUTH_ATTEMPT",
        "details": {"username": "root", "password": "123456"}
    },
    {
        "service": "HTTP", "event_type": "SQLI_ATTEMPT",
        "details": {"path": "/search?q=' OR 1=1--", "method": "GET"}
    },
    {
        "service": "SSH", "event_type": "CONNECTION",
        "details": {"status": "connected"}
    },
    {
        "service": "HTTP", "event_type": "ADMIN_ACCESS",
        "details": {"path": "/wp-admin", "username": "admin", "password": "admin"}
    },
    {
        "service": "SSH", "event_type": "COMMAND",
        "details": {"command": "cat /etc/passwd"}
    },
    {
        "service": "HTTP", "event_type": "PATH_TRAVERSAL",
        "details": {"path": "/../../../etc/passwd"}
    },
]

print("\nAI Classifier Test\n" + "="*50)
for event in test_events:
    result = classify(event)
    if result:
        print(f"Service  : {event['service']}")
        print(f"Event    : {event['event_type']}")
        print(f"AI Label : {result['name']}")
        print(f"Confidence: {result['confidence']*100:.1f}%")
        print(f"Severity : {result['severity'].upper()}")
        print("-"*50)
    else:
        print("Model not loaded — run: python -m ml.train")
'''.strip())

print("\nAll Phase 4 files written successfully!")
print("\nNext steps:")
print("  1. python test_classifier.py   — test AI on sample attacks")
print("  2. python main.py              — run honeypot with live AI")
print()

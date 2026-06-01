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
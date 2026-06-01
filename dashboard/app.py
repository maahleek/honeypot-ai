from flask import Flask, render_template, jsonify
from capture.logger import event_queue, get_logger
from capture.database import get_recent_events, get_stats
import threading

try:
    from config import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY
except ImportError:
    DASHBOARD_HOST = "0.0.0.0"
    DASHBOARD_PORT = 5000
    SECRET_KEY     = "honeypot-secret"

logger = get_logger("DASHBOARD")
app            = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = SECRET_KEY

SEVERITY_MAP = {0:"low",1:"high",2:"medium",3:"critical",4:"critical",5:"critical",6:"high"}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/events")
def api_events():
    from capture.database import Session, AttackEvent
    import json as _json
    session = Session()
    try:
        rows = (session.query(AttackEvent)
                .order_by(AttackEvent.id.desc())
                .limit(50).all())
        events = []
        for r in rows:
            try:
                details = _json.loads(r.details) if r.details else {}
            except:
                details = {}
            cls = None
            if r.attack_name:
                cls = {
                    "name"      : r.attack_name,
                    "label"     : r.attack_label,
                    "confidence": 0.95,
                    "severity"  : SEVERITY_MAP.get(r.attack_label or 0, "low"),
                }
            events.append({
                "timestamp"     : str(r.timestamp),
                "service"       : r.service,
                "attacker_ip"   : r.attacker_ip,
                "attacker_port" : r.attacker_port,
                "event_type"    : r.event_type,
                "classification": cls,
            })
        return jsonify(events)
    finally:
        session.close()

def _event_broadcaster():
    logger.info("Event broadcaster started")
    while True:
        try:
            event = event_queue.get(timeout=1)
            event_queue.task_done()
        except Exception:
            pass

def start_dashboard():
    t = threading.Thread(target=_event_broadcaster, name="EventBroadcaster", daemon=True)
    t.start()
    logger.info(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    from flask import Flask
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, threaded=True,
            use_reloader=False, debug=False)
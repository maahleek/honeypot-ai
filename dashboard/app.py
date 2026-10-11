from flask import Flask, jsonify, render_template

from capture.database import get_stats
from capture.logger import get_logger

try:
    from config import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY
except ImportError:
    DASHBOARD_HOST = "127.0.0.1"
    DASHBOARD_PORT = 5000
    SECRET_KEY = "honeypot-secret"

logger = get_logger("DASHBOARD")
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = SECRET_KEY

SEVERITY_MAP = {
    0: "low",
    1: "high",
    2: "medium",
    3: "critical",
    4: "critical",
    5: "critical",
    6: "high",
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/events")
def api_events():
    from capture.database import AttackEvent, Session

    session = Session()
    try:
        rows = (
            session.query(AttackEvent)
            .order_by(AttackEvent.id.desc())
            .limit(50)
            .all()
        )

        events = []
        for row in rows:
            classification = None
            if row.attack_name:
                classification = {
                    "name": row.attack_name,
                    "label": row.attack_label,
                    # Historical rows do not persist model confidence, so do
                    # not manufacture a confidence value for the dashboard.
                    "confidence": None,
                    "severity": SEVERITY_MAP.get(row.attack_label or 0, "low"),
                }

            events.append(
                {
                    "timestamp": str(row.timestamp),
                    "service": row.service,
                    "attacker_ip": row.attacker_ip,
                    "attacker_port": row.attacker_port,
                    "event_type": row.event_type,
                    "classification": classification,
                }
            )
        return jsonify(events)
    finally:
        session.close()


def start_dashboard():
    logger.info(
        f"Dashboard running at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
    )
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        threaded=True,
        use_reloader=False,
        debug=False,
    )

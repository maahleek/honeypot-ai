"""
setup_phase5.py — Writes all Phase 5 dashboard files.
Run: python setup_phase5.py
"""
from pathlib import Path

def write(path, content):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  created: {path}")

print("\nWriting Phase 5 dashboard files...\n")

# ── dashboard/__init__.py ─────────────────────────────────────────────────────
write('dashboard/__init__.py', '# dashboard package\n')

# ── dashboard/app.py ──────────────────────────────────────────────────────────
write('dashboard/app.py', r'''
"""
dashboard/app.py — Real-time web dashboard.

Features:
  - Live attack feed via WebSocket
  - Attack type distribution chart
  - Service breakdown chart
  - Top attacker IPs
  - Total stats counters
  - Severity colour coding
"""
import threading
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit

from capture.logger import event_queue, get_logger
from capture.database import get_recent_events, get_stats

try:
    from config import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY
except ImportError:
    DASHBOARD_HOST = "0.0.0.0"
    DASHBOARD_PORT = 5000
    SECRET_KEY     = "honeypot-secret"

logger = get_logger("DASHBOARD")

app            = Flask(__name__, template_folder="templates",
                        static_folder="static")
app.secret_key = SECRET_KEY
socketio       = SocketIO(app, cors_allowed_origins="*",
                           async_mode="threading")


# ── REST API endpoints ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/events")
def api_events():
    return jsonify(get_recent_events(50))


# ── Background thread: push events to dashboard via WebSocket ─────────────────
def _event_broadcaster():
    """Reads from event_queue and broadcasts to all connected clients."""
    logger.info("Event broadcaster started")
    while True:
        try:
            event = event_queue.get(timeout=1)
            socketio.emit("new_event", event)
            event_queue.task_done()
        except Exception:
            pass


def start_dashboard():
    """Start the dashboard server + broadcaster thread."""
    t = threading.Thread(target=_event_broadcaster,
                         name="EventBroadcaster", daemon=True)
    t.start()
    logger.info(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    socketio.run(app, host=DASHBOARD_HOST, port=DASHBOARD_PORT,
                 use_reloader=False, debug=False, allow_unsafe_werkzeug=True)
'''.strip())


# ── dashboard/templates/index.html ───────────────────────────────────────────
write('dashboard/templates/index.html', r'''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Honeypot Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Segoe UI',sans-serif; background:#0d1117; color:#e6edf3; }

    header {
      background:linear-gradient(135deg,#161b22,#1f2937);
      padding:16px 24px;
      border-bottom:1px solid #30363d;
      display:flex; align-items:center; gap:12px;
    }
    header h1 { font-size:1.3rem; font-weight:700; color:#58a6ff; }
    header span { font-size:.8rem; color:#8b949e; }
    .dot { width:10px;height:10px;border-radius:50%;background:#3fb950;
           animation:pulse 2s infinite; }
    @keyframes pulse {
      0%,100%{opacity:1} 50%{opacity:.4}
    }

    .stats {
      display:grid; grid-template-columns:repeat(4,1fr);
      gap:12px; padding:20px 24px;
    }
    .stat-card {
      background:#161b22; border:1px solid #30363d;
      border-radius:10px; padding:16px; text-align:center;
    }
    .stat-card .num { font-size:2rem; font-weight:700; color:#58a6ff; }
    .stat-card .lbl { font-size:.75rem; color:#8b949e; margin-top:4px; }

    .charts {
      display:grid; grid-template-columns:1fr 1fr;
      gap:16px; padding:0 24px 20px;
    }
    .chart-card {
      background:#161b22; border:1px solid #30363d;
      border-radius:10px; padding:16px;
    }
    .chart-card h3 { font-size:.85rem; color:#8b949e;
                     margin-bottom:12px; text-transform:uppercase;
                     letter-spacing:.05em; }

    .feed-section { padding:0 24px 24px; }
    .feed-section h3 { font-size:.85rem; color:#8b949e;
                       margin-bottom:10px; text-transform:uppercase;
                       letter-spacing:.05em; }
    #feed {
      background:#161b22; border:1px solid #30363d;
      border-radius:10px; overflow:hidden;
      max-height:340px; overflow-y:auto;
    }
    .feed-row {
      display:grid;
      grid-template-columns:140px 70px 100px 130px 1fr 90px;
      padding:9px 16px; border-bottom:1px solid #21262d;
      font-size:.78rem; align-items:center;
      animation:fadein .4s ease;
    }
    @keyframes fadein { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }
    .feed-row:hover { background:#1f2937; }
    .feed-header {
      display:grid;
      grid-template-columns:140px 70px 100px 130px 1fr 90px;
      padding:8px 16px; background:#1f2937;
      font-size:.72rem; color:#8b949e; text-transform:uppercase;
      letter-spacing:.05em; font-weight:600;
    }

    .badge {
      display:inline-block; padding:2px 8px;
      border-radius:20px; font-size:.7rem; font-weight:600;
    }
    .sev-critical { background:#3d1515; color:#f85149; }
    .sev-high     { background:#2d1b00; color:#e3b341; }
    .sev-medium   { background:#0d2434; color:#58a6ff; }
    .sev-low      { background:#0d2119; color:#3fb950; }

    .svc-ssh    { color:#d2a8ff; }
    .svc-http   { color:#58a6ff; }
    .svc-ftp    { color:#ffa657; }
    .svc-telnet { color:#79c0ff; }
  </style>
</head>
<body>

<header>
  <div class="dot"></div>
  <h1>🍯 AI-Enhanced Honeypot System</h1>
  <span id="status-text">Connecting...</span>
</header>

<div class="stats">
  <div class="stat-card">
    <div class="num" id="total">0</div>
    <div class="lbl">Total Events</div>
  </div>
  <div class="stat-card">
    <div class="num" id="critical" style="color:#f85149">0</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="stat-card">
    <div class="num" id="unique-ips" style="color:#3fb950">0</div>
    <div class="lbl">Unique IPs</div>
  </div>
  <div class="stat-card">
    <div class="num" id="classified" style="color:#e3b341">0</div>
    <div class="lbl">AI Classified</div>
  </div>
</div>

<div class="charts">
  <div class="chart-card">
    <h3>Attack Types</h3>
    <canvas id="typeChart" height="180"></canvas>
  </div>
  <div class="chart-card">
    <h3>Services</h3>
    <canvas id="svcChart" height="180"></canvas>
  </div>
</div>

<div class="feed-section">
  <h3>Live Attack Feed</h3>
  <div id="feed">
    <div class="feed-header">
      <span>Timestamp</span>
      <span>Service</span>
      <span>IP</span>
      <span>Event</span>
      <span>AI Label</span>
      <span>Severity</span>
    </div>
  </div>
</div>

<script>
  // ── Charts ─────────────────────────────────────────────────────────────────
  const COLORS = ['#58a6ff','#3fb950','#f85149','#e3b341','#d2a8ff','#ffa657','#79c0ff'];

  const typeChart = new Chart(document.getElementById('typeChart'), {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: COLORS }] },
    options: { plugins: { legend: { labels: { color:'#e6edf3', font:{size:11} } } } }
  });

  const svcChart = new Chart(document.getElementById('svcChart'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{ data: [], backgroundColor: COLORS,
                   borderRadius: 6, borderSkipped: false }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color:'#8b949e' }, grid: { color:'#21262d' } },
        y: { ticks: { color:'#8b949e' }, grid: { color:'#21262d' } }
      }
    }
  });

  // ── Stats loader ───────────────────────────────────────────────────────────
  let critCount = 0, classCount = 0;

  function loadStats() {
    fetch('/api/stats').then(r => r.json()).then(d => {
      document.getElementById('total').textContent = d.total || 0;
      document.getElementById('unique-ips').textContent =
        Object.keys(d.top_ips || {}).length;

      // Attack type chart
      const et = d.by_event_type || {};
      typeChart.data.labels   = Object.keys(et);
      typeChart.data.datasets[0].data = Object.values(et);
      typeChart.update();

      // Service chart
      const sv = d.by_service || {};
      svcChart.data.labels   = Object.keys(sv);
      svcChart.data.datasets[0].data = Object.values(sv);
      svcChart.update();
    });
  }

  // ── Recent events loader ───────────────────────────────────────────────────
  function loadRecent() {
    fetch('/api/events').then(r => r.json()).then(events => {
      events.slice(0, 30).forEach(addRow);
    });
  }

  // ── Row builder ───────────────────────────────────────────────────────────
  function addRow(event) {
    const feed  = document.getElementById('feed');
    const cls   = event.classification || {};
    const sev   = cls.severity || 'low';
    const label = cls.name || '—';
    const conf  = cls.confidence ? `${(cls.confidence*100).toFixed(0)}%` : '';
    const ts    = event.timestamp
                  ? new Date(event.timestamp).toLocaleTimeString()
                  : '—';
    const svc   = (event.service || '').toLowerCase();

    const row = document.createElement('div');
    row.className = 'feed-row';
    row.innerHTML = `
      <span style="color:#8b949e">${ts}</span>
      <span class="svc-${svc}">${event.service || '—'}</span>
      <span>${event.attacker_ip || '—'}</span>
      <span style="color:#cdd9e5">${event.event_type || '—'}</span>
      <span>${label} ${conf ? '<small style="color:#8b949e">'+conf+'</small>' : ''}</span>
      <span><span class="badge sev-${sev}">${sev.toUpperCase()}</span></span>
    `;

    // Insert after header
    const header = feed.querySelector('.feed-header');
    feed.insertBefore(row, header ? header.nextSibling : feed.firstChild);

    // Keep max 50 rows
    const rows = feed.querySelectorAll('.feed-row');
    if (rows.length > 50) rows[rows.length - 1].remove();

    // Update counters
    if (sev === 'critical') {
      critCount++;
      document.getElementById('critical').textContent = critCount;
    }
    if (cls.name) {
      classCount++;
      document.getElementById('classified').textContent = classCount;
    }
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────
  const socket = io();
  socket.on('connect', () => {
    document.getElementById('status-text').textContent = 'Live — connected';
    document.getElementById('status-text').style.color = '#3fb950';
  });
  socket.on('disconnect', () => {
    document.getElementById('status-text').textContent = 'Disconnected';
    document.getElementById('status-text').style.color = '#f85149';
  });
  socket.on('new_event', event => {
    addRow(event);
    loadStats();   // refresh charts on every new event
  });

  // ── Init ──────────────────────────────────────────────────────────────────
  loadStats();
  loadRecent();
  setInterval(loadStats, 10000);   // refresh charts every 10s
</script>
</body>
</html>
'''.strip())


# ── Updated main.py — now starts dashboard too ────────────────────────────────
write('main.py', r'''
"""
main.py — AI-Enhanced Honeypot System — Full Stack (Phase 5)

Starts all services:
  SSH / HTTP / FTP / Telnet honeypots
  AI Inference Engine
  Real-time Web Dashboard  →  http://localhost:5000
"""
import sys, threading, time
from pathlib import Path

for d in ["data","logs","ml/model","dashboard/templates","dashboard/static"]:
    Path(d).mkdir(parents=True, exist_ok=True)

from capture.logger import get_logger
from config import SSH_PORT, HTTP_PORT, FTP_PORT, TELNET_PORT, DASHBOARD_PORT

from honeypots.ssh_honeypot    import start_ssh_honeypot
from honeypots.http_honeypot   import start_http_honeypot
from honeypots.ftp_honeypot    import start_ftp_honeypot
from honeypots.telnet_honeypot import start_telnet_honeypot
from capture.inference_engine  import start as start_inference
from dashboard.app             import start_dashboard

logger = get_logger("MAIN")

def _print_banner():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║       AI-Enhanced Honeypot System  v1.0 (Phase 5)       ║
║          Full Stack — Honeypot + AI + Dashboard          ║
╠══════════════════════════════════════════════════════════╣
║  SSH       │  {SSH_PORT:<5}                                    ║
║  HTTP      │  {HTTP_PORT:<5}                                    ║
║  FTP       │  {FTP_PORT:<5}                                    ║
║  Telnet    │  {TELNET_PORT:<5}                                    ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard →  http://localhost:{DASHBOARD_PORT}                  ║
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

    start_inference()
    logger.info("AI Inference Engine started")
    time.sleep(0.5)

    threads = []
    for name, fn in _SERVICES:
        try:
            t = _launch(name, fn)
            threads.append(t)
            logger.info(f"✓ {name} started")
            time.sleep(0.3)
        except Exception as e:
            logger.error(f"✗ Failed to start {name}: {e}")

    logger.info(f"Dashboard → http://localhost:{DASHBOARD_PORT}")
    logger.info("All systems running. (Ctrl+C to stop)\n")

    # Start dashboard in main thread (blocking)
    try:
        start_dashboard()
    except KeyboardInterrupt:
        print()
        logger.info("Shutdown requested.")
        sys.exit(0)
'''.strip())

print("\nAll Phase 5 files written successfully!")
print("\nNext step:")
print("  python main.py")
print("  Then open: http://localhost:5000")
print()

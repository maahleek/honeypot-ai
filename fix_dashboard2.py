from pathlib import Path

Path("dashboard/templates").mkdir(parents=True, exist_ok=True)

html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Honeypot Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:"Segoe UI",sans-serif; background:#0d1117; color:#e6edf3; }
    header {
      background:linear-gradient(135deg,#161b22,#1f2937);
      padding:16px 24px; border-bottom:1px solid #30363d;
      display:flex; align-items:center; gap:12px;
    }
    header h1 { font-size:1.3rem; font-weight:700; color:#58a6ff; }
    .dot { width:10px;height:10px;border-radius:50%;background:#3fb950;
           animation:pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    .live { font-size:.8rem; color:#3fb950; }
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
    .chart-card h3 { font-size:.85rem; color:#8b949e; margin-bottom:12px;
                     text-transform:uppercase; letter-spacing:.05em; }
    .feed-section { padding:0 24px 24px; }
    .feed-section h3 { font-size:.85rem; color:#8b949e; margin-bottom:10px;
                       text-transform:uppercase; letter-spacing:.05em; }
    table { width:100%; border-collapse:collapse;
            background:#161b22; border-radius:10px; overflow:hidden;
            border:1px solid #30363d; }
    th { background:#1f2937; padding:10px 14px; font-size:.72rem;
         color:#8b949e; text-align:left; text-transform:uppercase; }
    td { padding:9px 14px; font-size:.78rem; border-bottom:1px solid #21262d; }
    tr:hover td { background:#1f2937; }
    .badge { display:inline-block; padding:2px 8px; border-radius:20px;
             font-size:.7rem; font-weight:600; }
    .sev-critical { background:#3d1515; color:#f85149; }
    .sev-high     { background:#2d1b00; color:#e3b341; }
    .sev-medium   { background:#0d2434; color:#58a6ff; }
    .sev-low      { background:#0d2119; color:#3fb950; }
    .svc-SSH    { color:#d2a8ff; }
    .svc-HTTP   { color:#58a6ff; }
    .svc-FTP    { color:#ffa657; }
    .svc-TELNET { color:#79c0ff; }
  </style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>AI-Enhanced Honeypot System</h1>
  <span class="live" id="live-txt">Live</span>
</header>

<div class="stats">
  <div class="stat-card">
    <div class="num" id="total">0</div>
    <div class="lbl">Total Events</div>
  </div>
  <div class="stat-card">
    <div class="num" id="ssh-count" style="color:#d2a8ff">0</div>
    <div class="lbl">SSH Attacks</div>
  </div>
  <div class="stat-card">
    <div class="num" id="http-count" style="color:#58a6ff">0</div>
    <div class="lbl">HTTP Attacks</div>
  </div>
  <div class="stat-card">
    <div class="num" id="unique-ips" style="color:#3fb950">0</div>
    <div class="lbl">Unique IPs</div>
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
  <table>
    <thead>
      <tr>
        <th>Time</th><th>Service</th><th>IP</th>
        <th>Event</th><th>AI Label</th><th>Severity</th>
      </tr>
    </thead>
    <tbody id="feed-body"></tbody>
  </table>
</div>

<script>
  const COLORS = ["#58a6ff","#3fb950","#f85149","#e3b341","#d2a8ff","#ffa657","#79c0ff"];

  const typeChart = new Chart(document.getElementById("typeChart"), {
    type: "doughnut",
    data: { labels:[], datasets:[{ data:[], backgroundColor:COLORS }] },
    options: { plugins:{ legend:{ labels:{ color:"#e6edf3", font:{size:11} } } } }
  });

  const svcChart = new Chart(document.getElementById("svcChart"), {
    type: "bar",
    data: { labels:[], datasets:[{ data:[], backgroundColor:COLORS,
            borderRadius:6, borderSkipped:false }] },
    options: {
      plugins:{ legend:{ display:false } },
      scales:{
        x:{ ticks:{color:"#8b949e"}, grid:{color:"#21262d"} },
        y:{ ticks:{color:"#8b949e"}, grid:{color:"#21262d"} }
      }
    }
  });

  let lastEventId = 0;

  function loadStats() {
    fetch("/api/stats")
      .then(r => r.json())
      .then(d => {
        document.getElementById("total").textContent = d.total || 0;
        document.getElementById("unique-ips").textContent =
          Object.keys(d.top_ips || {}).length;
        document.getElementById("ssh-count").textContent =
          (d.by_service || {}).SSH || 0;
        document.getElementById("http-count").textContent =
          (d.by_service || {}).HTTP || 0;

        const et = d.by_event_type || {};
        typeChart.data.labels = Object.keys(et);
        typeChart.data.datasets[0].data = Object.values(et);
        typeChart.update();

        const sv = d.by_service || {};
        svcChart.data.labels = Object.keys(sv);
        svcChart.data.datasets[0].data = Object.values(sv);
        svcChart.update();
      })
      .catch(() => {
        document.getElementById("live-txt").textContent = "Reconnecting...";
      });
  }

  function loadEvents() {
    fetch("/api/events")
      .then(r => r.json())
      .then(events => {
        const tbody = document.getElementById("feed-body");
        tbody.innerHTML = "";
        events.slice(0, 30).forEach(ev => {
          const cls  = ev.classification || {};
          const sev  = cls.severity || "low";
          const name = cls.name || "-";
          const conf = cls.confidence ? (cls.confidence*100).toFixed(0)+"%" : "";
          const ts   = ev.timestamp
            ? new Date(ev.timestamp).toLocaleTimeString() : "-";
          const tr = document.createElement("tr");
          tr.innerHTML =
            "<td style=\\"color:#8b949e\\">" + ts + "</td>" +
            "<td class=\\"svc-" + ev.service + "\\">" + (ev.service||"-") + "</td>" +
            "<td>" + (ev.attacker_ip||"-") + "</td>" +
            "<td>" + (ev.event_type||"-") + "</td>" +
            "<td>" + name + " <small style=\\"color:#8b949e\\">" + conf + "</small></td>" +
            "<td><span class=\\"badge sev-" + sev + "\\">" + sev.toUpperCase() + "</span></td>";
          tbody.appendChild(tr);
        });
        document.getElementById("live-txt").textContent = "Live";
      });
  }

  loadStats();
  loadEvents();
  setInterval(loadStats,  3000);
  setInterval(loadEvents, 3000);
</script>
</body>
</html>'''

Path("dashboard/templates/index.html").write_text(html, encoding="utf-8")
print("Dashboard fixed - pure polling, no WebSocket needed")

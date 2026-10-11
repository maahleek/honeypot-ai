"""
main.py — AI-Enhanced Honeypot System — Full Stack (Phase 5)

Starts all services:
  SSH / HTTP / FTP / Telnet honeypots
  Synchronous ML classification
  Real-time Web Dashboard
"""
import sys, threading, time
from pathlib import Path

for d in ["data", "data/ftp_root", "logs", "keys", "ml/model", "dashboard/templates", "dashboard/static"]:
    Path(d).mkdir(parents=True, exist_ok=True)

from capture.logger import get_logger
from config import SSH_PORT, HTTP_PORT, FTP_PORT, TELNET_PORT, DASHBOARD_HOST, DASHBOARD_PORT

from honeypots.ssh_honeypot    import start_ssh_honeypot
from honeypots.http_honeypot   import start_http_honeypot
from honeypots.ftp_honeypot    import start_ftp_honeypot
from honeypots.telnet_honeypot import start_telnet_honeypot
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
║  Dashboard →  http://{DASHBOARD_HOST}:{DASHBOARD_PORT}                  ║
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

    threads = []
    for name, fn in _SERVICES:
        try:
            t = _launch(name, fn)
            threads.append(t)
            logger.info(f"✓ {name} started")
            time.sleep(0.3)
        except Exception as e:
            logger.error(f"✗ Failed to start {name}: {e}")

    logger.info(f"Dashboard → http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    logger.info("All systems running. (Ctrl+C to stop)\n")

    # Start dashboard in main thread (blocking)
    try:
        start_dashboard()
    except KeyboardInterrupt:
        print()
        logger.info("Shutdown requested.")
        sys.exit(0)
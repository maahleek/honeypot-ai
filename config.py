"""
config.py — Central configuration for the AI-Enhanced Honeypot System
All ports, paths, banners, and settings live here.
"""

import os
from pathlib import Path

# ─── Base Directory ───────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent

# ─── Honeypot Network Settings ───────────────────────────────────────────────
HOST        = '0.0.0.0'     # Listen on all interfaces

SSH_PORT    = 2222          # Real SSH is on 22; we use 2222 for dev/testing
HTTP_PORT   = 8080          # Real HTTP is on 80
FTP_PORT    = 2121          # Real FTP is on 21
TELNET_PORT = 2323          # Real Telnet is on 23

# NOTE: On a real deployment server (VPS/cloud), change these to:
#   SSH_PORT=22, HTTP_PORT=80, FTP_PORT=21, TELNET_PORT=23
#   and run with sudo so the OS allows binding to privileged ports (<1024)

# ─── Dashboard Settings ───────────────────────────────────────────────────────
DASHBOARD_HOST = '0.0.0.0'
DASHBOARD_PORT = 5000
SECRET_KEY     = os.getenv('SECRET_KEY', 'hp-dev-secret-CHANGE-IN-PRODUCTION')

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH = BASE_DIR / 'data' / 'honeypot.db'

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR  = BASE_DIR / 'logs'
LOG_FILE = LOG_DIR / 'attacks.jsonl'   # JSON Lines — one event per line

# ─── Service Banners (make honeypot look like a real server) ──────────────────
SSH_BANNER          = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'
HTTP_SERVER_HEADER  = 'Apache/2.4.57 (Ubuntu)'
HTTP_POWERED_BY     = 'PHP/8.1.2'
FTP_BANNER          = '220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.1.1]'
TELNET_BANNER       = (
    "\r\n"
    "Ubuntu 22.04.3 LTS\r\n"
    "Kernel 5.15.0-91-generic on an x86_64\r\n"
    "\r\n"
    "login: "
)

# ─── Honeypot Behaviour ───────────────────────────────────────────────────────
MAX_CONNECTIONS_PER_IP = 10     # Block IPs that exceed this per minute
AUTH_DELAY_SECONDS     = 1.5    # Fake auth delay (slows down brute-force)
MAX_LOGIN_ATTEMPTS     = 3      # Show "login incorrect" N times before closing
SESSION_TIMEOUT        = 30     # Seconds to keep an idle connection open

# ─── ML Model ─────────────────────────────────────────────────────────────────
MODEL_DIR  = BASE_DIR / 'ml' / 'model'
MODEL_PATH = MODEL_DIR / 'classifier.joblib'
SCALER_PATH= MODEL_DIR / 'scaler.joblib'

# Attack class labels
ATTACK_LABELS = {
    0: 'Normal',
    1: 'Brute Force',
    2: 'Port Scan',
    3: 'DoS / Flood',
    4: 'SQL Injection',
    5: 'Command Injection',
    6: 'Credential Stuffing',
}
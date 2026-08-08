"""
capture/feature_extractor.py — Converts raw honeypot events
into numerical feature vectors ready for ML training.

Feature vector (17 features):
  0  service_ssh        — 1 if SSH, else 0
  1  service_http       — 1 if HTTP, else 0
  2  service_ftp        — 1 if FTP, else 0
  3  service_telnet     — 1 if TELNET, else 0
  4  is_auth_attempt    — 1 if AUTH_ATTEMPT / CREDENTIAL_ATTEMPT
  5  is_admin_access    — 1 if ADMIN_ACCESS
  6  is_sqli            — 1 if SQLI_ATTEMPT
  7  is_path_traversal  — 1 if PATH_TRAVERSAL
  8  is_command         — 1 if COMMAND
  9  password_len       — length of password (0 if none)
  10 username_is_root   — 1 if username is root/admin/administrator
  11 has_sqli_chars     — 1 if payload contains SQL chars
  12 has_traversal      — 1 if payload contains ../
  13 payload_len        — length of payload/body (0 if none)
  14 is_connection      — 1 if CONNECTION event
  15 is_disconnection   — 1 if DISCONNECTION event
  16 is_request         — 1 if REQUEST event
"""

import json
import re

FEATURE_NAMES = [
    "service_ssh", "service_http", "service_ftp", "service_telnet",
    "is_auth_attempt", "is_admin_access", "is_sqli", "is_path_traversal",
    "is_command", "password_len", "username_is_root",
    "has_sqli_chars", "has_traversal", "payload_len",
    "is_connection", "is_disconnection", "is_request",
]

_SQLI_RE      = re.compile(r"('|\"|--|;|union|select|drop|insert|update|delete|exec|cast)",
                            re.IGNORECASE)
_TRAVERSAL_RE = re.compile(r"\.\./", re.IGNORECASE)
_ROOT_USERS   = {"root", "admin", "administrator", "superuser", "sa", "postgres"}


def extract(event: dict) -> list:
    """
    Takes a raw event dict and returns a list of 17 numeric features.
    """
    service    = event.get("service", "").upper()
    event_type = event.get("event_type", "").upper()
    details    = event.get("details", {})
    if isinstance(details, str):
        try: details = json.loads(details)
        except: details = {}

    username = str(details.get("username") or "").lower()
    password = str(details.get("password") or "")
    payload  = str(
        details.get("body") or
        details.get("command") or
        details.get("path") or ""
    )

    features = [
        # ── Service one-hot ──────────────────────────────────────────────────
        1 if service == "SSH"    else 0,
        1 if service == "HTTP"   else 0,
        1 if service == "FTP"    else 0,
        1 if service == "TELNET" else 0,

        # ── Event type flags ─────────────────────────────────────────────────
        1 if event_type in ("AUTH_ATTEMPT", "CREDENTIAL_ATTEMPT") else 0,
        1 if event_type == "ADMIN_ACCESS"   else 0,
        1 if event_type == "SQLI_ATTEMPT"   else 0,
        1 if event_type == "PATH_TRAVERSAL" else 0,
        1 if event_type == "COMMAND"        else 0,

        # ── Credential features ──────────────────────────────────────────────
        len(password),
        1 if username in _ROOT_USERS else 0,

        # ── Payload features ─────────────────────────────────────────────────
        1 if _SQLI_RE.search(payload)      else 0,
        1 if _TRAVERSAL_RE.search(payload) else 0,
        len(payload),

        # ── Connection type features (added for Normal vs Port Scan) ─────────
        1 if event_type == "CONNECTION"    else 0,
        1 if event_type == "DISCONNECTION" else 0,
        1 if event_type == "REQUEST"       else 0,
    ]
    return features


def extract_batch(events: list) -> list:
    """Extract features from a list of events."""
    return [extract(e) for e in events]


def event_to_row(event: dict) -> dict:
    """Return a flat dict with feature names as keys (for pandas/CSV)."""
    return dict(zip(FEATURE_NAMES, extract(event)))

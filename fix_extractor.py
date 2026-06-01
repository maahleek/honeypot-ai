from pathlib import Path

content = r'''
import json
import re

FEATURE_NAMES = [
    "service_ssh", "service_http", "service_ftp", "service_telnet",
    "is_auth_attempt", "is_admin_access", "is_sqli", "is_path_traversal",
    "is_command", "password_len", "username_is_root",
    "has_sqli_chars", "has_traversal", "payload_len",
]

_SQLI_RE      = re.compile(r"('|\"|--|;|union|select|drop|insert|update|delete|exec|cast)", re.IGNORECASE)
_TRAVERSAL_RE = re.compile(r"\.\./", re.IGNORECASE)
_ROOT_USERS   = {"root", "admin", "administrator", "superuser", "sa", "postgres"}


def extract(event: dict) -> list:
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

    return [
        1 if service == "SSH"    else 0,
        1 if service == "HTTP"   else 0,
        1 if service == "FTP"    else 0,
        1 if service == "TELNET" else 0,
        1 if event_type in ("AUTH_ATTEMPT", "CREDENTIAL_ATTEMPT") else 0,
        1 if event_type == "ADMIN_ACCESS"   else 0,
        1 if event_type == "SQLI_ATTEMPT"   else 0,
        1 if event_type == "PATH_TRAVERSAL" else 0,
        1 if event_type == "COMMAND"        else 0,
        len(password),
        1 if username in _ROOT_USERS else 0,
        1 if _SQLI_RE.search(payload)      else 0,
        1 if _TRAVERSAL_RE.search(payload) else 0,
        len(payload),
    ]


def extract_batch(events: list) -> list:
    return [extract(e) for e in events]


def event_to_row(event: dict) -> dict:
    return dict(zip(FEATURE_NAMES, extract(event)))
'''

Path("capture/feature_extractor.py").write_text(content.strip(), encoding="utf-8")
print("Fixed: capture/feature_extractor.py")

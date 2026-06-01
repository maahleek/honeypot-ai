import socket, threading, time
from capture.logger import log_event, get_logger
from config import HOST, TELNET_PORT, TELNET_BANNER, AUTH_DELAY_SECONDS, MAX_LOGIN_ATTEMPTS, SESSION_TIMEOUT

logger = get_logger("TELNET")

def _strip(data):
    result, i = bytearray(), 0
    while i < len(data):
        if data[i] == 0xFF and i+2 < len(data): i += 3
        else: result.append(data[i]); i += 1
    return result.decode("utf-8", errors="ignore").strip()

def _recv(sock, timeout=30.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(256)
            if not chunk: break
            buf += chunk
            if b"\n" in buf or b"\r" in buf: break
    except (socket.timeout, OSError): pass
    return _strip(buf)

def _handle(sock, addr):
    ip, port = addr
    log_event("TELNET", ip, port, "CONNECTION", {"status": "connected"})
    try:
        sock.send(TELNET_BANNER.encode())
        for attempt in range(1, MAX_LOGIN_ATTEMPTS+1):
            username = _recv(sock, SESSION_TIMEOUT)
            if not username: break
            sock.send(b"Password: ")
            password = _recv(sock, SESSION_TIMEOUT)
            log_event("TELNET", ip, port, "AUTH_ATTEMPT",
                      {"username": username, "password": password, "attempt": attempt})
            time.sleep(AUTH_DELAY_SECONDS)
            if attempt < MAX_LOGIN_ATTEMPTS:
                sock.send(b"\r\nLogin incorrect\r\n\r\n")
                sock.send(TELNET_BANNER.encode())
            else:
                sock.send(b"\r\nLogin incorrect\r\nConnection closed.\r\n")
    except (BrokenPipeError, ConnectionResetError, OSError): pass
    finally:
        try: sock.close()
        except: pass
        log_event("TELNET", ip, port, "DISCONNECTION", {})

def start_telnet_honeypot():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind((HOST, TELNET_PORT))
    except PermissionError:
        logger.error(f"Cannot bind port {TELNET_PORT}. Use sudo for ports < 1024."); return
    s.listen(128)
    logger.info(f"Telnet Honeypot listening on {HOST}:{TELNET_PORT}")
    while True:
        try:
            client, addr = s.accept()
            threading.Thread(target=_handle, args=(client, addr), daemon=True).start()
        except Exception as e: logger.error(f"Telnet error: {e}")

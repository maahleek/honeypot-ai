import socket, threading, time
import paramiko
from capture.logger import log_event, get_logger
from config import HOST, SSH_PORT, SSH_BANNER, AUTH_DELAY_SECONDS, SESSION_TIMEOUT

logger   = get_logger("SSH")
import os
_KEY_PATH = os.path.join(os.path.dirname(__file__), '..', 'keys', 'ssh_host_key')
try:
    HOST_KEY = paramiko.RSAKey(filename=_KEY_PATH)
except Exception:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(_KEY_PATH)

class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip, port):
        self.client_ip   = ip
        self.client_port = port
        self.shell_event = threading.Event()
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_shell_request(self, channel):
        self.shell_event.set(); return True
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    def check_auth_password(self, username, password):
        time.sleep(AUTH_DELAY_SECONDS)
        log_event("SSH", self.client_ip, self.client_port, "AUTH_ATTEMPT",
                  {"username": username, "password": password, "method": "password"})
        return paramiko.AUTH_FAILED
    def check_auth_publickey(self, username, key):
        log_event("SSH", self.client_ip, self.client_port, "AUTH_ATTEMPT",
                  {"username": username, "key_type": key.get_name(), "method": "publickey"})
        return paramiko.AUTH_FAILED
    def get_allowed_auths(self, username): return "password,publickey"

def _handle_client(sock, addr):
    ip, port = addr
    log_event("SSH", ip, port, "CONNECTION", {"status": "connected"})
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)
        server = SSHHoneypotServer(ip, port)
        try: transport.start_server(server=server)
        except paramiko.SSHException: return
        channel = transport.accept(SESSION_TIMEOUT)
        if channel:
            channel.send(b"\r\nWelcome to Ubuntu 22.04\r\nroot@ubuntu:~# ")
            server.shell_event.wait(SESSION_TIMEOUT)
            channel.settimeout(SESSION_TIMEOUT)
            try:
                while True:
                    data = channel.recv(4096)
                    if not data: break
                    cmd = data.decode("utf-8", errors="ignore").strip()
                    if cmd:
                        log_event("SSH", ip, port, "COMMAND", {"command": cmd})
                    channel.send(f"\r\nbash: {cmd}: command not found\r\nroot@ubuntu:~# ".encode())
            except socket.timeout: pass
            finally: channel.close()
    except Exception as e: logger.debug(f"SSH error {ip}: {e}")
    finally:
        if transport:
            try: transport.close()
            except: pass
        try: sock.close()
        except: pass
        log_event("SSH", ip, port, "DISCONNECTION", {})

def start_ssh_honeypot():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind((HOST, SSH_PORT))
    except PermissionError:
        logger.error(f"Cannot bind port {SSH_PORT}. Use sudo for ports < 1024."); return
    s.listen(128)
    logger.info(f"SSH Honeypot listening on {HOST}:{SSH_PORT}")
    while True:
        try:
            client, addr = s.accept()
            threading.Thread(target=_handle_client, args=(client, addr), daemon=True).start()
        except Exception as e: logger.error(f"SSH accept error: {e}")

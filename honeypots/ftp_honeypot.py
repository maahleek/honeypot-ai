import logging
from pyftpdlib.handlers   import FTPHandler
from pyftpdlib.servers    import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from capture.logger import log_event, get_logger
from config import HOST, FTP_PORT, FTP_BANNER, MAX_LOGIN_ATTEMPTS

logger = get_logger("FTP")
logging.getLogger("pyftpdlib").setLevel(logging.WARNING)

class HoneypotFTPHandler(FTPHandler):
    def on_connect(self):
        log_event("FTP", self.remote_ip, self.remote_port, "CONNECTION", {"status": "connected"})
    def on_disconnect(self):
        log_event("FTP", self.remote_ip, self.remote_port, "DISCONNECTION", {})
    def on_login_failed(self, username, password):
        log_event("FTP", self.remote_ip, self.remote_port, "AUTH_ATTEMPT",
                  {"username": username, "password": password, "result": "failed"})
    def on_login(self, username):
        log_event("FTP", self.remote_ip, self.remote_port, "AUTH_SUCCESS", {"username": username})
    def on_file_received(self, file):
        log_event("FTP", self.remote_ip, self.remote_port, "FILE_UPLOAD", {"file": file})
    def on_file_sent(self, file):
        log_event("FTP", self.remote_ip, self.remote_port, "FILE_DOWNLOAD", {"file": file})

def start_ftp_honeypot():
    auth = DummyAuthorizer()
    auth.add_anonymous("/tmp", perm="elradfmwMT")
    HoneypotFTPHandler.authorizer       = auth
    HoneypotFTPHandler.banner           = FTP_BANNER
    HoneypotFTPHandler.passive_ports    = range(60000, 60100)
    HoneypotFTPHandler.max_login_attempts = MAX_LOGIN_ATTEMPTS
    srv = FTPServer((HOST, FTP_PORT), HoneypotFTPHandler)
    srv.max_cons = 50
    logger.info(f"FTP Honeypot listening on {HOST}:{FTP_PORT}")
    srv.serve_forever()

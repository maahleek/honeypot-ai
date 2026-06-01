from flask import Flask, request, make_response
from capture.logger import log_event, get_logger
from config import HOST, HTTP_PORT, HTTP_SERVER_HEADER, HTTP_POWERED_BY

logger = get_logger("HTTP")
app    = Flask(__name__)
app.config["PROPAGATE_EXCEPTIONS"] = False

_SQLI = ["1=1","OR 1","SELECT","UNION","DROP","INSERT","UPDATE","DELETE","EXEC","--","/*"]
_ADMIN = {"/admin","/wp-admin","/wp-login.php","/phpmyadmin","/login","/administrator"}

def _detect(path, body, args):
    full = (path + str(args) + body).upper()
    if "../" in path or "..%2f" in path.lower(): return "PATH_TRAVERSAL"
    if any(p.upper() in full for p in _SQLI): return "SQLI_ATTEMPT"
    if any(path.rstrip("/").lower().startswith(a) for a in _ADMIN): return "ADMIN_ACCESS"
    return "REQUEST"

def _resp(body, status=200):
    r = make_response(body, status)
    r.headers["Server"]       = HTTP_SERVER_HEADER
    r.headers["X-Powered-By"] = HTTP_POWERED_BY
    return r

LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<h2>System Login</h2><form method="POST">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Login"></form>{error}</body></html>"""

@app.route("/wp-login.php", methods=["GET","POST"])
@app.route("/admin", methods=["GET","POST"])
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        log_event("HTTP", request.remote_addr, 0, "CREDENTIAL_ATTEMPT",
                  {"username": request.form.get("username",""), "password": request.form.get("password","")})
        return _resp(LOGIN_PAGE.format(error="<p style=color:red>Invalid credentials.</p>"), 401)
    log_event("HTTP", request.remote_addr, 0, "ADMIN_ACCESS", {"path": request.path})
    return _resp(LOGIN_PAGE.format(error=""))

@app.route("/", defaults={"path":""}, methods=["GET","POST","PUT","DELETE","OPTIONS","HEAD"])
@app.route("/<path:path>",            methods=["GET","POST","PUT","DELETE","OPTIONS","HEAD"])
def catch_all(path):
    body = request.get_data(as_text=True)
    et   = _detect(request.path, body, dict(request.args))
    log_event("HTTP", request.remote_addr, 0, et,
              {"method": request.method, "path": request.path,
               "user_agent": request.headers.get("User-Agent",""), "body": body[:500]})
    return _resp("<h1>404 Not Found</h1>", 404)

def start_http_honeypot():
    logger.info(f"HTTP Honeypot listening on {HOST}:{HTTP_PORT}")
    app.run(host=HOST, port=HTTP_PORT, threaded=True, use_reloader=False, debug=False)

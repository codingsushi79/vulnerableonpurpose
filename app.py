#!/usr/bin/env python3
"""
VulnLab — intentionally vulnerable practice app for local cybersec training.
Run: python app.py
NEVER deploy this to the public internet.
"""

import base64
import json
import os
import sqlite3
import subprocess
from functools import wraps
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "vulnlab.db"
SECRETS_DIR = APP_DIR / "secrets"

# Hard-coded secrets students should discover via recon / exploitation
ADMIN_PASSWORD = "Sup3rS3cr3t!"
LAB_FLAG = "VULN{1nt3rc3pt_4nd_1nj3ct}"
INTERNAL_TOKEN = "tok_live_7f3a9c2e"
XSS_FLAG = "VULN{xss_p4yl0ad_fired}"
IDOR_FLAG = "VULN{id0r_us3r_l33k}"
LFI_FLAG = "VULN{l0cal_f1le_r3ad}"
CMDI_FLAG = "VULN{c0mm4nd_1nj3ct}"
SSRF_FLAG = "VULN{ssrf_1ntern4l}"
BACKUP_FLAG = "VULN{b4ckup_expos3d}"
RESET_FLAG = "VULN{w34k_r3s3t_t0k3n}"

# Labels match the /check form — shown when each value is discovered
CHECK_LABELS = {
    "username": "Username",
    "bypass_method": "Bypass method",
    "admin_password": "Admin password",
    "lab_flag": "Dashboard flag",
    "internal_token": "Internal token",
    "cookie_role": "Cookie role",
    "xss_flag": "XSS canary flag",
    "stored_xss": "Stored XSS",
    "idor_flag": "IDOR flag",
    "lfi_flag": "LFI flag",
    "cmdi_flag": "Command injection flag",
    "ssrf_flag": "SSRF flag",
    "backup_flag": "Backup config flag",
    "reset_flag": "Password reset flag",
}

app = Flask(__name__)
app.secret_key = "dev-only-not-random"


def check_tag(key: str) -> str:
    return CHECK_LABELS[key]


@app.context_processor
def inject_check_labels():
    return {"check_labels": CHECK_LABELS, "check_tag": check_tag}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    SECRETS_DIR.mkdir(exist_ok=True)
    (SECRETS_DIR / "backup_flag.txt").write_text(
        f"CONFIDENTIAL BACKUP\n"
        f"{check_tag('lfi_flag')}: {LFI_FLAG}\n",
        encoding="utf-8",
    )
    (SECRETS_DIR / "employee_records.txt").write_text(
        "Employee SSN fragments — internal use only\n", encoding="utf-8"
    )

    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS feedback;
        DROP TABLE IF EXISTS profiles;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE profiles (
            user_id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            department TEXT,
            api_key TEXT,
            secret_note TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    db.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("guest", "guest123", "user"),
            ("analyst", "password", "user"),
            ("admin", ADMIN_PASSWORD, "admin"),
        ],
    )
    db.executemany(
        """
        INSERT INTO profiles (user_id, email, department, api_key, secret_note)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (1, "guest@securecorp.local", "Support", "key_guest_public", "Guest access only."),
            (
                2,
                "analyst@securecorp.local",
                "SOC",
                "key_analyst_9b2c",
                "Monitor login anomalies.",
            ),
            (
                3,
                "admin@securecorp.local",
                "IT Admin",
                IDOR_FLAG,
                "Master credentials rotated quarterly.",
            ),
        ],
    )
    db.execute(
        "INSERT INTO feedback (author, message) VALUES (?, ?)",
        ("system", "Welcome to the feedback portal. Reports are visible to all staff."),
    )
    db.commit()
    db.close()


def decode_session_cookie(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        padding = "=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(raw + padding).decode("utf-8")
        return json.loads(data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def encode_session_cookie(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def current_identity() -> dict:
    cookie_data = decode_session_cookie(request.cookies.get("vulnlab_session"))
    session_data = {
        "username": session.get("username"),
        "role": session.get("role", "guest"),
    }
    if cookie_data.get("username"):
        session_data["username"] = cookie_data["username"]
    if cookie_data.get("role"):
        session_data["role"] = cookie_data["role"]
    return session_data


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        ident = current_identity()
        if not ident.get("username"):
            flash("Please sign in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def weak_reset_token(username: str) -> str:
    # Predictable token — md5-ish pattern for lab (not real crypto)
    return base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")


@app.route("/")
def index():
    return redirect(url_for("home"))


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    db = get_db()
    query = (
        "SELECT id, username, password, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as exc:
        flash(f"Database error: {exc}", "error")
        return render_template("login.html"), 500

    authenticated = row is not None

    if authenticated or role == "admin":
        effective_user = row["username"] if row else username or "anonymous"
        effective_role = role if role == "admin" else (row["role"] if row else "user")

        session["username"] = effective_user
        session["role"] = effective_role

        resp = make_response(redirect(url_for("dashboard")))
        resp.set_cookie(
            "vulnlab_session",
            encode_session_cookie({"username": effective_user, "role": effective_role}),
            httponly=False,
            secure=False,
            samesite="Lax",
        )
        flash(f"Welcome, {effective_user}.", "success")
        return resp

    # User enumeration — different errors leak whether username exists
    exists = db.execute(
        f"SELECT 1 FROM users WHERE username = '{username}' LIMIT 1"
    ).fetchone()
    if exists:
        flash("Invalid password for that account.", "error")
    else:
        flash("Unknown username.", "error")
    return render_template("login.html"), 401


@app.route("/dashboard")
@login_required
def dashboard():
    ident = current_identity()
    secrets = {}
    if ident.get("role") == "admin":
        secrets = {
            "admin_password": ADMIN_PASSWORD,
            "lab_flag": LAB_FLAG,
            "internal_token": INTERNAL_TOKEN,
        }
    return render_template("dashboard.html", identity=ident, secrets=secrets)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("vulnlab_session")
    flash("Signed out.", "success")
    return resp


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Reflected XSS — rendered unsafely in template
    return render_template("search.html", query=Markup(query), raw_query=query)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous").strip() or "anonymous"
        message = request.form.get("message", "").strip()
        if message:
            db.execute(
                "INSERT INTO feedback (author, message) VALUES (?, ?)",
                (author, message),
            )
            db.commit()
            flash("Feedback submitted.", "success")
            return redirect(url_for("feedback"))

    rows = db.execute(
        "SELECT author, message, created_at FROM feedback ORDER BY id DESC LIMIT 20"
    ).fetchall()
    # Stored XSS — messages rendered with |safe in template
    entries = [
        {"author": r["author"], "message": Markup(r["message"]), "created_at": r["created_at"]}
        for r in rows
    ]
    return render_template("feedback.html", entries=entries)


@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    # IDOR — no ownership check; sequential IDs expose other users
    db = get_db()
    row = db.execute(
        """
        SELECT u.id, u.username, u.role, p.email, p.department, p.api_key, p.secret_note
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()
    if not row:
        return {"error": "not found"}, 404
    data = {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "email": row["email"],
        "department": row["department"],
        "api_key": row["api_key"],
        "secret_note": row["secret_note"],
    }
    if row["api_key"] == IDOR_FLAG:
        data["api_key_check_label"] = CHECK_LABELS["idor_flag"]
    return data


@app.route("/api/check_user")
def api_check_user():
    username = request.args.get("username", "")
    db = get_db()
    row = db.execute(
        f"SELECT username FROM users WHERE username = '{username}' LIMIT 1"
    ).fetchone()
    return {"username": username, "exists": row is not None}


@app.route("/files")
def files():
    name = request.args.get("name", "readme.txt")
    if name == "readme.txt":
        return (
            "SecureCorp document viewer\n"
            "Specify a filename to retrieve archived files.\n"
        )
    # Path traversal — no canonicalization
    target = SECRETS_DIR / name
    try:
        return target.read_text(encoding="utf-8")
    except OSError:
        return f"Could not open: {name}", 404


@app.route("/tools/ping", methods=["GET", "POST"])
def tools_ping():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if host:
            # Command injection — shell=True with unsanitized input
            try:
                completed = subprocess.run(
                    f"ping -c 1 {host}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                output = completed.stdout + completed.stderr
                if any(ch in host for ch in (";", "|", "&", "`", "$(")):
                    output += (
                        f"\n[debug] {check_tag('cmdi_flag')}: {CMDI_FLAG}\n"
                    )
            except subprocess.TimeoutExpired:
                output = "Command timed out."
            except OSError as exc:
                output = str(exc)
    return render_template("ping.html", host=host, output=output)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not url:
        return render_template("fetch.html", result=None, url="")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return render_template(
            "fetch.html",
            url=url,
            result={"error": "Only http/https URLs supported."},
        )

    try:
        req = urlrequest.Request(url, headers={"User-Agent": "SecureCorp-Preview/1.0"})
        with urlrequest.urlopen(req, timeout=3) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            result = {"status": resp.status, "body": body}
    except urlerror.URLError as exc:
        result = {"error": str(exc.reason)}
    return render_template("fetch.html", url=url, result=result)


@app.route("/internal/health")
def internal_health():
    # Intended to be reached via SSRF, not linked in nav
    return {
        "status": "ok",
        "environment": "internal",
        "ssrf_flag": SSRF_FLAG,
        "ssrf_flag_check_label": CHECK_LABELS["ssrf_flag"],
        "message": "Internal health check — not for external callers.",
    }


@app.route("/reset", methods=["GET", "POST"])
def password_reset():
    message = None
    token = request.args.get("token", "")
    username = request.form.get("username", "") if request.method == "POST" else request.args.get("user", "")

    if request.method == "POST" and username:
        message = (
            f"Reset link generated for {username}: "
            f"/reset?user={username}&token={weak_reset_token(username)}"
        )
    elif token and username:
        if token == weak_reset_token(username):
            message = f"Password reset approved. {check_tag('reset_flag')}: {RESET_FLAG}"
        else:
            message = "Invalid reset token."

    return render_template("reset.html", message=message, username=username, token=token)


@app.route("/robots.txt")
def robots():
    body = """User-agent: *
Disallow: /backup/
Disallow: /internal/
Disallow: /api/user/
Disallow: /secrets/

# Old admin panel moved to /backup/config.bak
"""
    return app.response_class(body, mimetype="text/plain")


@app.route("/backup/config.bak")
def backup_config():
    port = request.environ.get("SERVER_PORT", "5000")
    internal_url = f"http://127.0.0.1:{port}/internal/health"
    body = f"""# SecureCorp legacy configuration backup
DB_HOST=127.0.0.1
DB_NAME=securecorp
DB_USER=portal_app
DB_PASS=Ch4ng3M3!

INTERNAL_HEALTH_URL={internal_url}
{check_tag('backup_flag')}: {BACKUP_FLAG}

# Canary token
{check_tag('xss_flag')}: {XSS_FLAG}
"""
    return app.response_class(body, mimetype="text/plain")


@app.route("/check", methods=["GET", "POST"])
def check():
    results = None
    if request.method == "POST":
        submitted = {k: request.form.get(k, "").strip() for k in request.form}
        for key in ("bypass_method", "cookie_role"):
            submitted[key] = submitted.get(key, "").lower()

        checks = []

        def add(label, ok):
            checks.append({"label": label, "ok": ok})

        add(CHECK_LABELS["username"], submitted.get("username") in {"guest", "analyst", "admin", "anonymous"})

        bypass = submitted.get("bypass_method", "")
        add(
            CHECK_LABELS["bypass_method"],
            bypass
            in {
                "sqli",
                "sql injection",
                "hidden role",
                "role tamper",
                "cookie",
                "cookie tamper",
            },
        )

        add(CHECK_LABELS["admin_password"], submitted.get("admin_password") == ADMIN_PASSWORD)
        add(CHECK_LABELS["lab_flag"], submitted.get("lab_flag") == LAB_FLAG)
        add(CHECK_LABELS["internal_token"], submitted.get("internal_token") == INTERNAL_TOKEN)
        add(CHECK_LABELS["cookie_role"], submitted.get("cookie_role") == "admin")
        add(CHECK_LABELS["xss_flag"], submitted.get("xss_flag") == XSS_FLAG)
        add(CHECK_LABELS["stored_xss"], submitted.get("stored_xss") == "yes")
        add(CHECK_LABELS["idor_flag"], submitted.get("idor_flag") == IDOR_FLAG)
        add(CHECK_LABELS["lfi_flag"], submitted.get("lfi_flag") == LFI_FLAG)
        add(CHECK_LABELS["cmdi_flag"], submitted.get("cmdi_flag") == CMDI_FLAG)
        add(CHECK_LABELS["ssrf_flag"], submitted.get("ssrf_flag") == SSRF_FLAG)
        add(CHECK_LABELS["backup_flag"], submitted.get("backup_flag") == BACKUP_FLAG)
        add(CHECK_LABELS["reset_flag"], submitted.get("reset_flag") == RESET_FLAG)

        score = sum(1 for c in checks if c["ok"])
        results = {
            "checks": checks,
            "score": score,
            "total": len(checks),
            "complete": score == len(checks),
        }

    return render_template("check.html", results=results)


@app.route("/api/status")
def api_status():
    ident = current_identity()
    return {
        "service": "SecureCorp Employee Portal",
        "version": "2.4.1",
        "authenticated": bool(ident.get("username")),
        "role": ident.get("role"),
    }


if __name__ == "__main__":
    if not DB_PATH.exists() or os.environ.get("VULNLAB_RESET") == "1":
        init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  VulnLab running at http://127.0.0.1:{port}")
    print("  Intentionally vulnerable — local use only.\n")
    app.run(host="127.0.0.1", port=port, debug=True)

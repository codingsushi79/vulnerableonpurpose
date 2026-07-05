#!/usr/bin/env python3
"""
VulnLab — intentionally vulnerable practice app for local cybersec training.
Run: python app.py
NEVER deploy this to the public internet.
"""

import base64
import json
import os
import random
import re
import secrets
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
    jsonify,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from markupsafe import Markup

import cops_workforce
import game as game_mode
import guide_challenges
import lab_flags
import sensitive_pdfs

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "vulnlab.db"
SECRETS_DIR = APP_DIR / "secrets"

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
    "ssti_flag": "SSTI flag",
    "profile_flag": "Profile escalation flag",
    "report_flag": "Report SQLi flag",
    "pdf_board_sha256": "Board memo PDF SHA256",
    "pdf_acquisition_sha256": "Acquisition brief PDF SHA256",
}

app = Flask(__name__)

game_mode.configure(
    cops_and_robbers=os.environ.get("COPS_AND_ROBBERS") == "1",
    time_trial=os.environ.get("TIME_TRIAL") == "1",
)
if game_mode.game_mode_active() and lab_flags.VAULT_PATH.exists():
    lab_flags.load(use_vault=True)
else:
    lab_flags.load(use_vault=False)
app.secret_key = lab_flags.get_epoch()


def check_tag(key: str) -> str:
    return CHECK_LABELS[key]


@app.context_processor
def inject_check_labels():
    ident = current_identity()
    gs = game_mode.public_status()
    return {
        "check_labels": CHECK_LABELS,
        "check_tag": check_tag,
        "identity": ident,
        "logged_in": bool(ident.get("username")),
        "game_active": game_mode.game_mode_active(),
        "cops_and_robbers": game_mode.COPS_AND_ROBBERS,
        "time_trial": game_mode.TIME_TRIAL,
        "game_status": gs,
        "game_finished": gs["phase"] == "finished",
        "guide_unlocked": guide_challenges.unlocked_list(session),
        "guide_ready": {
            n: guide_challenges.phase_ready(n, session)
            for n in guide_challenges.GUIDE_CHALLENGES
        },
        "guide_challenges": guide_challenges.GUIDE_CHALLENGES,
    }


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


def guide_mark(key: str) -> None:
    progress = session.setdefault("guide_progress", [])
    if key not in progress:
        progress.append(key)
        session.modified = True


def init_db(*, empty_users: bool = False):
    secrets = lab_flags.all_secrets()
    SECRETS_DIR.mkdir(exist_ok=True)
    (SECRETS_DIR / "backup_flag.txt").write_text(
        f"CONFIDENTIAL BACKUP\n"
        f"{check_tag('lfi_flag')}: {secrets['lfi_flag']}\n",
        encoding="utf-8",
    )
    (SECRETS_DIR / "employee_records.txt").write_text(
        "Employee SSN fragments — internal use only\n", encoding="utf-8"
    )
    (SECRETS_DIR / "deployment_notes.txt").write_text(
        "SecureCorp portal deployment notes\n"
        "---------------------------------\n"
        "App process user: www-data\n"
        "Internal health URL is set in backup config (INTERNAL_HEALTH_URL).\n"
        "Network diagnostics tool invokes /bin/ping via shell — restrict in prod.\n"
        "Confidential PDFs: board_memo.pdf, acquisition_target.pdf (internal archive).\n",
        encoding="utf-8",
    )
    sensitive_pdfs.write_sensitive_pdfs(SECRETS_DIR)

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
            last_login_ip TEXT,
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
    if not empty_users:
        pw = secrets["admin_password"]
        db.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("guest", "guest123", "user"),
                ("analyst", "password", "user"),
                ("admin", pw, "admin"),
            ],
        )
        db.executemany(
            """
            INSERT INTO profiles (user_id, email, department, api_key, secret_note, last_login_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "guest@securecorp.local", "Support", "key_guest_public", "Guest access only.", None),
                (
                    2,
                    "analyst@securecorp.local",
                    "SOC",
                    "key_analyst_9b2c",
                    "Monitor login anomalies.",
                    None,
                ),
                (
                    3,
                    "admin@securecorp.local",
                    "IT Admin",
                    secrets["idor_flag"],
                    "Master credentials rotated quarterly.",
                    None,
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
    epoch = lab_flags.get_epoch()
    cookie_data = decode_session_cookie(request.cookies.get("vulnlab_session"))
    if cookie_data.get("epoch") != epoch:
        cookie_data = {}
    session_data = {
        "username": session.get("username"),
        "role": session.get("role", "guest"),
    }
    if session.get("lab_epoch") and session.get("lab_epoch") != epoch:
        session.clear()
        session_data = {"username": None, "role": "guest"}
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


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        ident = current_identity()
        if not ident.get("username"):
            flash("Please sign in first.", "error")
            return redirect(url_for("login"))
        if ident.get("role") != "admin":
            flash("Administrator access required.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def apply_identity(resp, username: str, role: str):
    epoch = lab_flags.get_epoch()
    session["username"] = username
    session["role"] = role
    session["lab_epoch"] = epoch
    resp.set_cookie(
        "vulnlab_session",
        encode_session_cookie({"username": username, "role": role, "epoch": epoch}),
        httponly=False,
        secure=False,
        samesite="Lax",
    )
    return resp


def clear_auth_cookies(resp):
    session.clear()
    resp.delete_cookie("vulnlab_session")
    return resp


def request_client_ip() -> str:
    if not game_mode.game_mode_active():
        return request.remote_addr or "127.0.0.1"
    sid = session.setdefault("game_session_id", secrets.token_hex(8))
    team = session.get("game_team")
    if team in ("cop", "perp"):
        return game_mode.assign_player_ip(sid, team)
    return request.remote_addr or "127.0.0.1"


def log_detail_for_request() -> str:
    path = request.path
    if path == "/login" and request.method == "POST":
        return "Authentication attempt"
    if path == "/check":
        return "Submission form access"
    if path.startswith("/files"):
        return "Document viewer request"
    if path == "/tools/ping":
        return "Network diagnostics"
    if path == "/fetch":
        return "URL preview fetch"
    if path == "/admin/register":
        return "Admin user provisioning"
    if path.startswith("/api/"):
        return "API call"
    return "Page request"


def suspicious_admin_login(authenticated: bool, row, role_param: str, effective_role: str) -> bool:
    if effective_role != "admin":
        return False
    if not authenticated:
        return True
    if role_param == "admin" and row["role"] != "admin":
        return True
    return False


GAME_EXEMPT_ENDPOINTS = {
    "static",
    "game_lobby",
    "game_join",
    "game_cops_setup",
    "game_trial_start",
    "game_status_api",
    "api_check_sync",
}


@app.before_request
def validate_lab_epoch():
    """Drop stale cookies from before the last VULNLAB_RESET."""
    if request.endpoint == "static":
        return None
    epoch = lab_flags.get_epoch()
    raw = request.cookies.get("vulnlab_session")
    if raw:
        data = decode_session_cookie(raw)
        if data.get("epoch") != epoch:
            session.clear()
            g.stale_lab_cookies = True
    return None


@app.after_request
def expire_stale_cookies(resp):
    if g.pop("stale_lab_cookies", None):
        resp.delete_cookie("vulnlab_session")
    return resp


@app.before_request
def game_before_request():
    if not game_mode.game_mode_active():
        return None
    if request.endpoint in GAME_EXEMPT_ENDPOINTS:
        return None

    ip = request_client_ip()
    if game_mode.COPS_AND_ROBBERS and game_mode.is_ip_banned(ip):
        if session.get("game_team") != "cop":
            return render_template("banned.html"), 403

    if game_mode.COPS_AND_ROBBERS and game_mode.get_state().phase == "active":
        ident = current_identity()
        game_mode.log_request(
            ip,
            request.method,
            request.full_path.rstrip("?") if request.query_string else request.path,
            ident.get("username") or "—",
            log_detail_for_request(),
        )
    return None


def weak_reset_token(username: str) -> str:
    # Predictable token — md5-ish pattern for lab (not real crypto)
    return base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")


@app.route("/")
def index():
    if game_mode.game_mode_active() and game_mode.get_state().phase == "lobby":
        return redirect(url_for("game_lobby"))
    return redirect(url_for("home"))


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/guide")
def guide():
    if game_mode.game_mode_active():
        return render_template(
            "guide.html",
            competitive_guide=True,
        )
    return render_template("guide.html", competitive_guide=False)


@app.route("/guide/unlock/<int:phase>", methods=["POST"])
def guide_unlock(phase: int):
    if not game_mode.game_mode_active():
        return redirect(url_for("guide"))
    if phase not in guide_challenges.GUIDE_CHALLENGES:
        flash("Unknown phase.", "error")
        return redirect(url_for("guide"))
    if guide_challenges.is_unlocked(phase, session):
        return redirect(url_for("guide"))
    if not guide_challenges.phase_ready(phase, session):
        flash("Complete the challenge first — hints stay locked until the server sees it.", "error")
        return redirect(url_for("guide"))

    unlocked = session.setdefault("guide_unlocked", [])
    unlocked.append(phase)
    session.modified = True

    spec = guide_challenges.GUIDE_CHALLENGES[phase]
    ident = current_identity()
    ip = request_client_ip()
    if game_mode.COPS_AND_ROBBERS:
        game_mode.log_hint_unlock(ip, ident.get("username") or "—", phase, spec["cop_log"])
    elif game_mode.TIME_TRIAL:
        game_mode.add_trial_penalty(spec["time_cost"])
        flash(f"Hints unlocked. +{spec['time_cost']}s added to your time.", "success")
    else:
        flash("Hints unlocked.", "success")
    return redirect(url_for("guide"))


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

        if game_mode.COPS_AND_ROBBERS and suspicious_admin_login(
            authenticated, row, role, effective_role
        ):
            game_mode.log_admin_intrusion(request_client_ip(), effective_user)

        resp = make_response(redirect(url_for("dashboard")))
        apply_identity(resp, effective_user, effective_role)
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
        guide_mark("admin_dashboard")
        secrets = {
            "admin_password": lab_flags.get("admin_password"),
            "lab_flag": lab_flags.get("lab_flag"),
            "internal_token": lab_flags.get("internal_token"),
        }
    return render_template(
        "dashboard.html",
        identity=ident,
        secrets=secrets,
        show_logs=game_mode.COPS_AND_ROBBERS,
    )


@app.route("/admin/register", methods=["GET", "POST"])
@admin_required
def admin_register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    if not username or not email or not password:
        flash("Username, email, and password are required.", "error")
        return render_template("register.html"), 400

    if role not in ("user", "admin"):
        flash("Invalid role.", "error")
        return render_template("register.html"), 400

    db = get_db()
    last_ip = None
    if game_mode.COPS_AND_ROBBERS:
        gs = game_mode.get_state()
        pool = gs.office_ip_pool or cops_workforce.OFFICE_IP_POOL
        last_ip = random.choice(pool)
    try:
        cur = db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password, role),
        )
        db.execute(
            """
            INSERT INTO profiles (user_id, email, department, api_key, secret_note, last_login_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                cur.lastrowid,
                email,
                "Staff",
                f"key_{username}_auto",
                "Provisioned via admin registration.",
                last_ip,
            ),
        )
        db.commit()
        if game_mode.COPS_AND_ROBBERS and last_ip:
            game_mode.get_state().user_ip_map[username] = last_ip
    except sqlite3.IntegrityError:
        flash("That username is already taken.", "error")
        return render_template("register.html"), 409

    flash(f"Employee account created for {username}.", "success")
    return redirect(url_for("dashboard"))


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
    ssti_result = None
    if query and "<script" in query.lower():
        guide_mark("xss_reflected")
    if query and ("{{" in query or "{%" in query):
        try:
            ssti_result = render_template_string(
                query,
                ssti_flag=lab_flags.get("ssti_flag"),
                check_tag=check_tag,
            )
            guide_mark("ssti_probe")
        except Exception as exc:
            ssti_result = f"Template error: {exc}"
    return render_template(
        "search.html",
        query=Markup(query),
        raw_query=query,
        ssti_result=ssti_result,
    )


@app.route("/documents")
@login_required
def documents():
    docs = [
        {"name": "backup_flag.txt", "title": "Backup archive"},
        {"name": "deployment_notes.txt", "title": "Deployment notes"},
        {"name": "employee_records.txt", "title": "Employee records (restricted)"},
        {"name": "board_memo.pdf", "title": "Board strategy memo (confidential PDF)"},
        {"name": "acquisition_target.pdf", "title": "Acquisition target brief (confidential PDF)"},
    ]
    return render_template("documents.html", docs=docs)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    ident = current_identity()
    message = None
    email = ident.get("username", "") + "@securecorp.local"
    if request.method == "POST":
        email = request.form.get("email", email)
        access_level = request.form.get("access_level", "standard")
        guide_mark("profile_post")
        if access_level == "admin":
            message = f"Profile elevated. {check_tag('profile_flag')}: {lab_flags.get('profile_flag')}"
        else:
            message = "Profile saved successfully."
    return render_template("profile.html", identity=ident, email=email, message=message)


@app.route("/api/reports")
def api_reports():
    dept = request.args.get("dept", "")
    if dept:
        guide_mark("reports_api")
    db = get_db()
    query = (
        "SELECT u.username, p.department FROM users u "
        "JOIN profiles p ON p.user_id = u.id "
        f"WHERE p.department = '{dept}'"
    )
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as exc:
        return {"error": str(exc)}, 500
    reports = [{"username": r["username"], "department": r["department"]} for r in rows]
    payload = {"reports": reports, "count": len(reports)}
    need = 1 if game_mode.game_mode_active() else 3
    if len(reports) >= need:
        payload["report_flag"] = lab_flags.get("report_flag")
        payload["report_flag_label"] = check_tag("report_flag")
    return payload


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous").strip() or "anonymous"
        message = request.form.get("message", "").strip()
        if message:
            if "<script" in message.lower():
                guide_mark("xss_stored")
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
    guide_mark("idor_api")
    # IDOR — no ownership check; sequential IDs expose other users
    db = get_db()
    row = db.execute(
        """
        SELECT u.id, u.username, u.role, p.email, p.department, p.api_key, p.secret_note,
               p.last_login_ip
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
        "last_login_ip": row["last_login_ip"],
    }
    if row["api_key"] == lab_flags.get("idor_flag"):
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
@login_required
def files():
    name = request.args.get("name", "readme.txt")
    if name != "readme.txt":
        guide_mark("lfi_read")
    if name == "readme.txt":
        return (
            "SecureCorp document viewer\n"
            "Specify a filename to retrieve archived files.\n"
        )
    # Path traversal — resolves paths but must stay inside secrets/
    secrets_root = SECRETS_DIR.resolve()
    target = (SECRETS_DIR / name).resolve()
    try:
        target.relative_to(secrets_root)
    except ValueError:
        return "Could not open: access denied", 403
    if target.suffix.lower() == ".py":
        return "Could not open: file type not allowed", 403
    if target.suffix.lower() == ".pdf":
        guide_mark("lfi_read")
        return send_file(target, mimetype="application/pdf")
    try:
        return target.read_text(encoding="utf-8")
    except OSError:
        return f"Could not open: {name}", 404


# Weak outbound filter on the diagnostics shell — bypassable, but blocks obvious abuse.
_PING_BLOCKED_COMMANDS = re.compile(
    r"\b("
    r"rm|rmdir|curl|wget|nc|netcat|nmap|python[23]?|perl|ruby|node|npm|"
    r"bash|sh|zsh|dash|chmod|chown|kill|pkill|mv|cp|dd|sudo|su|env|export|"
    r"openssl|ssh|scp|ftp|telnet|reboot|shutdown|launchctl|osascript"
    r")\b",
    re.IGNORECASE,
)
_PING_BLOCKED_PATHS = re.compile(
    r"(?:\.\./|\.\.\\|"
    r"/etc/|/root/|/usr/|/var/|/home/|/proc/|/sys/|/tmp/|/dev/|"
    r"\bapp\.py\b|\bgame\.py\b|\bvulnlab\.db\b|\.env\b|requirements\.txt|\.lab_flags\.json)",
    re.IGNORECASE,
)
_PING_BLOCKED_PY = re.compile(r"\.py\b", re.IGNORECASE)


def validate_ping_host(host: str) -> str | None:
    """Return an error message when input should be rejected."""
    if not host or len(host) > 200:
        return "Invalid host."
    if any(ch in host for ch in (">", "<", "\n", "\r", "\0")):
        return "Invalid characters in host."
    if _PING_BLOCKED_PATHS.search(host):
        return "Diagnostics blocked: path or file not allowed."
    if _PING_BLOCKED_PY.search(host):
        return "Diagnostics blocked: source files cannot be read via this tool."
    if _PING_BLOCKED_COMMANDS.search(host):
        return "Diagnostics blocked: command not permitted."
    return None


def run_ping_diagnostic(host: str) -> str:
    err = validate_ping_host(host)
    if err:
        return err

    try:
        completed = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=3,
            cwd=str(APP_DIR),
        )
        output = completed.stdout + completed.stderr
        if any(ch in host for ch in (";", "|", "&", "`", "$(")):
            guide_mark("cmdi_run")
            output += f"\n[debug] {check_tag('cmdi_flag')}: {lab_flags.get('cmdi_flag')}\n"
        return output
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except OSError as exc:
        return str(exc)


@app.route("/tools/ping", methods=["GET", "POST"])
def tools_ping():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if host:
            output = run_ping_diagnostic(host)
    return render_template("ping.html", host=host, output=output)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not url:
        return render_template("fetch.html", result=None, url="")

    if "internal/health" in url or "127.0.0.1" in url:
        guide_mark("ssrf_fetch")

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
    return {
        "status": "ok",
        "environment": "internal",
        "ssrf_flag": lab_flags.get("ssrf_flag"),
        "ssrf_flag_check_label": CHECK_LABELS["ssrf_flag"],
        "message": "Internal health check — not for external callers.",
    }


@app.route("/reset", methods=["GET", "POST"])
def password_reset():
    message = None
    token = request.args.get("token", "")
    username = request.form.get("username", "") if request.method == "POST" else request.args.get("user", "")

    if request.method == "POST" and username:
        guide_mark("reset_gen")
        message = (
            f"Reset link generated for {username}: "
            f"/reset?user={username}&token={weak_reset_token(username)}"
        )
    elif token and username:
        if token == weak_reset_token(username):
            message = f"Password reset approved. {check_tag('reset_flag')}: {lab_flags.get('reset_flag')}"
        else:
            message = "Invalid reset token."

    return render_template("reset.html", message=message, username=username, token=token)


@app.route("/robots.txt")
def robots():
    guide_mark("robots")
    body = """User-agent: *
Disallow: /backup/
Disallow: /backup/config.bak
Disallow: /internal/
Disallow: /api/user/
Disallow: /api/reports
Disallow: /secrets/
"""
    return app.response_class(body, mimetype="text/plain")


@app.route("/backup/config.bak")
def backup_config():
    guide_mark("backup_bak")
    port = request.environ.get("SERVER_PORT", "5000")
    internal_url = f"http://127.0.0.1:{port}/internal/health"
    idor_line = ""
    if game_mode.game_mode_active():
        idor_line = f"{check_tag('idor_flag')}: {lab_flags.get('idor_flag')}\n"
    body = f"""# SecureCorp legacy configuration backup
DB_HOST=127.0.0.1
DB_NAME=securecorp
DB_USER=portal_app
DB_PASS=Ch4ng3M3!

INTERNAL_HEALTH_URL={internal_url}
{check_tag('backup_flag')}: {lab_flags.get('backup_flag')}
{idor_line}
# Canary token
{check_tag('xss_flag')}: {lab_flags.get('xss_flag')}
"""
    return app.response_class(body, mimetype="text/plain")


@app.route("/check", methods=["GET", "POST"])
def check():
    guide_mark("check_visit")
    results = None
    if request.method == "POST":
        submitted = {k: request.form.get(k, "").strip() for k in request.form}
        for key in ("bypass_method", "cookie_role"):
            submitted[key] = submitted.get(key, "").lower()

        checks = []

        def add(label, ok):
            checks.append({"label": label, "ok": ok})

        add(
            CHECK_LABELS["username"],
            bool(submitted.get("username"))
            if game_mode.game_mode_active()
            else submitted.get("username") in {"guest", "analyst", "admin", "anonymous"},
        )

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

        add(CHECK_LABELS["admin_password"], submitted.get("admin_password") == lab_flags.get("admin_password"))
        add(CHECK_LABELS["lab_flag"], submitted.get("lab_flag") == lab_flags.get("lab_flag"))
        add(CHECK_LABELS["internal_token"], submitted.get("internal_token") == lab_flags.get("internal_token"))
        add(CHECK_LABELS["cookie_role"], submitted.get("cookie_role") == "admin")
        add(CHECK_LABELS["xss_flag"], submitted.get("xss_flag") == lab_flags.get("xss_flag"))
        add(CHECK_LABELS["stored_xss"], submitted.get("stored_xss") == "yes")
        add(CHECK_LABELS["idor_flag"], submitted.get("idor_flag") == lab_flags.get("idor_flag"))
        add(CHECK_LABELS["lfi_flag"], submitted.get("lfi_flag") == lab_flags.get("lfi_flag"))
        add(CHECK_LABELS["cmdi_flag"], submitted.get("cmdi_flag") == lab_flags.get("cmdi_flag"))
        add(CHECK_LABELS["ssrf_flag"], submitted.get("ssrf_flag") == lab_flags.get("ssrf_flag"))
        add(CHECK_LABELS["backup_flag"], submitted.get("backup_flag") == lab_flags.get("backup_flag"))
        add(CHECK_LABELS["reset_flag"], submitted.get("reset_flag") == lab_flags.get("reset_flag"))
        add(CHECK_LABELS["ssti_flag"], submitted.get("ssti_flag") == lab_flags.get("ssti_flag"))
        add(CHECK_LABELS["profile_flag"], submitted.get("profile_flag") == lab_flags.get("profile_flag"))
        add(CHECK_LABELS["report_flag"], submitted.get("report_flag") == lab_flags.get("report_flag"))
        pdf_hashes = sensitive_pdfs.pdf_hashes_from_disk(SECRETS_DIR)
        add(
            CHECK_LABELS["pdf_board_sha256"],
            submitted.get("pdf_board_sha256", "").lower()
            == pdf_hashes.get("pdf_board_sha256", "").lower(),
        )
        add(
            CHECK_LABELS["pdf_acquisition_sha256"],
            submitted.get("pdf_acquisition_sha256", "").lower()
            == pdf_hashes.get("pdf_acquisition_sha256", "").lower(),
        )

        score = sum(1 for c in checks if c["ok"])
        results = {
            "checks": checks,
            "score": score,
            "total": len(checks),
            "complete": score == len(checks),
        }

        if game_mode.COPS_AND_ROBBERS:
            game_mode.check_perp_win(score, len(checks))
        elif game_mode.TIME_TRIAL:
            game_mode.record_trial_finish(score, len(checks))

    shared = game_mode.get_check_state() if game_mode.game_mode_active() else None
    return render_template(
        "check.html",
        results=results,
        shared_check=shared,
        perp_threshold=game_mode.PERP_WIN_SCORE,
    )


@app.route("/api/status")
def api_status():
    ident = current_identity()
    return {
        "service": "SecureCorp Employee Portal",
        "version": "2.4.1",
        "authenticated": bool(ident.get("username")),
        "role": ident.get("role"),
    }


# --- Game modes (COPS_AND_ROBBERS=1 or TIME_TRIAL=1) ---


@app.route("/game")
def game_lobby():
    if not game_mode.game_mode_active():
        return redirect(url_for("home"))
    if request.args.get("reset") == "1":
        game_mode.reset_state()
        session.pop("game_team", None)
        session.pop("game_player", None)
        return redirect(url_for("game_lobby"))
    return render_template(
        "game_lobby.html",
        status=game_mode.public_status(),
        team=session.get("game_team"),
        player_name=session.get("game_player"),
    )


@app.route("/game/join", methods=["POST"])
def game_join():
    if not game_mode.COPS_AND_ROBBERS:
        return redirect(url_for("game_lobby"))
    team = request.form.get("team", "")
    name = request.form.get("player_name", "").strip() or "player"
    if team not in ("cop", "perp"):
        flash("Pick a team.", "error")
        return redirect(url_for("game_lobby"))
    session["game_team"] = team
    session["game_player"] = name
    session.setdefault("game_session_id", secrets.token_hex(8))
    game_mode.assign_player_ip(session["game_session_id"], team)
    flash(f"Joined {'Blue' if team == 'cop' else 'Red'} team as {name}.", "success")
    return redirect(url_for("game_lobby"))


@app.route("/game/cops/setup", methods=["POST"])
def game_cops_setup():
    if not game_mode.COPS_AND_ROBBERS or session.get("game_team") != "cop":
        flash("Cop team setup only.", "error")
        return redirect(url_for("game_lobby"))
    count = min(4, max(1, int(request.form.get("admin_count", 1))))
    password = request.form.get("password", "")
    if not password:
        flash("Password required.", "error")
        return redirect(url_for("game_lobby"))

    db = get_db()
    ip_map = cops_workforce.seed_cops_workforce(db, count, password)
    perp_ip = cops_workforce.pick_perp_ip(ip_map)
    game_mode.get_state().admin_accounts_created = count
    game_mode.get_state().cops_ready = True
    game_mode.start_cops_and_robbers(user_ip_map=ip_map, perp_ip=perp_ip)
    flash("Log monitoring started.", "success")
    return redirect(url_for("game_lobby"))


@app.route("/game/trial/start", methods=["POST"])
def game_trial_start():
    if not game_mode.TIME_TRIAL:
        return redirect(url_for("game_lobby"))
    players = int(request.form.get("players", 1))
    name = request.form.get("player_name", "").strip() or "runner"
    session["game_team"] = "perp"
    session["game_player"] = name
    session.setdefault("game_session_id", secrets.token_hex(8))
    game_mode.start_time_trial(players)
    flash("Timer started — go!", "success")
    return redirect(url_for("home"))


@app.route("/game/status")
def game_status_api():
    return game_mode.public_status()


@app.route("/api/admin/logs")
@admin_required
def api_admin_logs():
    if not game_mode.COPS_AND_ROBBERS:
        return jsonify({"error": "unavailable"}), 404
    gs = game_mode.get_state()
    return jsonify(
        {
            "logs": game_mode.logs_snapshot(tick=True),
            "alerts": gs.alerts,
            "ban_remaining": max(0, game_mode.ADMIN_BAN_ATTEMPTS - gs.ban_attempts_used),
            "game_over": gs.phase == "finished",
            "winner": gs.winner,
            "win_message": gs.win_message,
        }
    )


@app.route("/admin/logs")
@admin_required
def admin_logs():
    if not game_mode.COPS_AND_ROBBERS:
        flash("Logs are only available in Cops & Robbers mode.", "error")
        return redirect(url_for("dashboard"))
    gs = game_mode.get_state()
    game_mode.tick_live_logs()
    return render_template(
        "admin_logs.html",
        logs=game_mode.logs_snapshot(tick=False),
        alerts=gs.alerts,
        ban_remaining=max(0, game_mode.ADMIN_BAN_ATTEMPTS - gs.ban_attempts_used),
        game_over=gs.phase == "finished",
        winner=gs.winner,
        win_message=gs.win_message,
    )


@app.route("/admin/logs/ban", methods=["POST"])
@admin_required
def admin_logs_ban():
    if not game_mode.COPS_AND_ROBBERS:
        return redirect(url_for("dashboard"))
    ip = request.form.get("ip", "").strip()
    result = game_mode.attempt_ban(ip)
    wants_json = request.headers.get("X-Requested-With") == "fetch"
    if wants_json:
        return jsonify(result)
    if result.get("message"):
        flash(result["message"], "error" if not result.get("correct") else "success")
    elif result.get("error"):
        flash(result["error"], "error")
    return redirect(url_for("admin_logs"))


@app.route("/admin/logs/clear", methods=["POST"])
@admin_required
def admin_logs_clear():
    if not game_mode.COPS_AND_ROBBERS:
        return redirect(url_for("dashboard"))
    game_mode.clear_logs()
    wants_json = request.headers.get("X-Requested-With") == "fetch"
    if wants_json:
        return jsonify({"ok": True})
    flash("Real log entries cleared.", "success")
    return redirect(url_for("admin_logs"))


@app.route("/api/check/sync", methods=["GET", "POST"])
def api_check_sync():
    if not game_mode.game_mode_active():
        return {"enabled": False}
    player = session.get("game_player", "anonymous")
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        field = data.get("field", "")
        value = data.get("value", "")
        if field in CHECK_LABELS:
            game_mode.update_check_field(field, value, player)
    state = game_mode.get_check_state()
    status = game_mode.public_status()
    return {"enabled": True, **state, "game": status}


if __name__ == "__main__":
    cops = os.environ.get("COPS_AND_ROBBERS") == "1"
    trial = os.environ.get("TIME_TRIAL") == "1"
    competitive = cops or trial
    game_mode.configure(cops_and_robbers=cops, time_trial=trial)

    reset = os.environ.get("VULNLAB_RESET") == "1"
    if reset:
        lab_flags.bump_epoch()
        app.secret_key = lab_flags.get_epoch()
        game_mode.reset_state()

    if competitive and (reset or not lab_flags.VAULT_PATH.exists()):
        lab_flags.regenerate()
    else:
        lab_flags.load(use_vault=competitive and lab_flags.VAULT_PATH.exists())

    empty = cops  # time trial keeps default users (guest, analyst, admin)
    if not DB_PATH.exists() or reset:
        init_db(empty_users=empty)

    if reset:
        print("  VULNLAB_RESET=1 — all sessions and cookies invalidated.")

    port = int(os.environ.get("PORT", 5000))
    print(f"\n  VulnLab running at http://127.0.0.1:{port}")
    if cops:
        print("  Mode: COPS & ROBBERS — open /game to set up teams")
    elif trial:
        print("  Mode: TIME TRIAL — open /game to start the timer")
    else:
        print("  Intentionally vulnerable — local use only.")
    print()
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=not competitive)

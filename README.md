# VulnLab

A small, **intentionally vulnerable** web app for local cybersec practice — similar to a mini HackTheBox box you run on your own machine.

**Do not deploy this publicly.** It is designed to be exploited.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) and visit **/labs** for the full challenge index.

Reset the database (required after upgrades):

```bash
VULNLAB_RESET=1 python app.py
```

See **[GUIDE.md](GUIDE.md)** for the walkthrough. Open **http://127.0.0.1:5000/guide** in your browser for interactive hint dropdowns.

## Game modes

Optional multiplayer modes (local only):

```bash
# Cops watch logs and ban the attacker IP (2 guesses). Robbers need 13+ on /check.
VULNLAB_RESET=1 COPS_AND_ROBBERS=1 python app.py

# Timed cooperative run for 1–5 players, no admins.
VULNLAB_RESET=1 TIME_TRIAL=1 python app.py
```

Open **http://127.0.0.1:5000/game** to pick teams and start. In Cops & Robbers, blue team creates `admin1@gmail.com`, `admin2@gmail.com`, … accounts before monitoring begins. Preset users (`guest`, `analyst`, `admin`) are omitted in game modes.

In competitive modes, `/guide` solutions are disabled and hints require verified in-app challenges to unlock. Flags are randomized on each `VULNLAB_RESET` and stored in `.lab_flags.json` (not readable via LFI).

## Challenge areas

| Endpoint | Vulnerability |
|----------|---------------|
| `/login` | SQL injection, hidden field tampering, user enumeration |
| Session / cookies | Unsigned base64 cookie override |
| `/dashboard` | Broken access control → primary flags |
| `/admin/register` | Admin-only employee registration |
| `/documents` | Document archive → leads to file viewer |
| `/profile` | Hidden field privilege escalation |
| `/search` | Reflected XSS + SSTI |
| `/api/reports` | SQL injection on department filter |
| `/feedback` | Stored XSS |
| `/api/user/<id>` | IDOR — enumerate sequential IDs |
| `/files` | Local file inclusion / path traversal |
| `/tools/ping` | OS command injection |
| `/fetch` | SSRF to internal endpoints |
| `/reset` | Weak predictable reset tokens |
| `/robots.txt`, `/backup/config.bak` | Information disclosure |
| `/internal/health` | Internal-only data (reach via SSRF) |
| `/check` | Validate all 17 findings |

## License

MIT — for educational use only.

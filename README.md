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

## Challenge areas

| Endpoint | Vulnerability |
|----------|---------------|
| `/login` | SQL injection, hidden field tampering, user enumeration |
| Session / cookies | Unsigned base64 cookie override |
| `/dashboard` | Broken access control → primary flags |
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
| `/sys/console` | Hidden web shell — host compromise |
| `/check` | Validate all 19 findings |

## License

MIT — for educational use only.

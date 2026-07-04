# SecureCorp Lab Guide

Open the interactive guide in your browser — hints use clickable dropdowns:

**http://127.0.0.1:5000/guide**

The `/guide` page is not linked from the portal. Bookmark it for reference while you work.

---

## What you will practice

- Mapping a web application without an obvious challenge list
- Intercepting and modifying HTTP traffic
- Authentication bypass, session abuse, and privilege escalation
- Client-side and server-side injection flaws
- Collecting labeled findings and submitting them for scoring

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
VULNLAB_RESET=1 python app.py
```

Open **http://127.0.0.1:5000** and treat it like a real internal portal.

---

## Recommended tools

| Tool | Use for |
|------|---------|
| **Browser DevTools** | Page source, network log, cookies |
| **Burp Suite / OWASP ZAP** | Intercepting and editing requests |
| **curl** | Repeating requests and probing APIs |

---

## How to use this guide

Each phase in `/guide` gives you a **goal**, **steps**, and a **done when** checkpoint. Specific endpoints, payloads, and answers are inside **Hints** dropdowns — click to expand only when you need them.

The submission form at `/check` is not linked on the site. Find it yourself or use the Phase 9 hint.

---

## Safety reminder

This application is **intentionally insecure** for local training. Run it on `127.0.0.1` only. Never deploy it publicly.

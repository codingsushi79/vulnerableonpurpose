# SecureCorp Lab Guide

Open the interactive guide in your browser — full walkthrough with step-by-step hint dropdowns:

**http://127.0.0.1:5000/guide**

The `/guide` page is not linked from the portal. Bookmark it while you work.

---

## Overview

Complete **17 checks** on the hidden submission form at `/check`. The guide walks you through 12 phases:

1. Recon · 2. Login & admin · 3. XSS · 4. SSTI · 5. IDOR · 6. Report SQLi · 7. LFI · 8. CMDi · 9. SSRF · 10. Password reset · 11. Profile escalation · 12. Submit

Each phase includes what to collect, when you're done, and expandable step-by-step hints.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
VULNLAB_RESET=1 python app.py
```

Open **http://127.0.0.1:5000** and **http://127.0.0.1:5000/guide**.

---

## New in this version

| Feature | What it teaches |
|---------|-----------------|
| **Company Documents** (`/documents`) | Finding files → LFI path |
| **SSTI** (`/search?q={{ssti_flag}}`) | Server-side template injection |
| **Profile page** (`/profile`) | Hidden field tampering (like login) |
| **Report API** (`/api/reports?dept=`) | Second SQL injection vector |

---

## Safety reminder

This application is **intentionally insecure** for local training. Run it on `127.0.0.1` only. Never deploy it publicly.

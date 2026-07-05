"""Guide hint gates — server-verified progress before unlocking hints in game modes."""

from __future__ import annotations

GUIDE_CHALLENGES: dict[int, dict] = {
    1: {
        "task": "Visit /robots.txt and /backup/config.bak in your browser.",
        "keys": ["robots", "backup_bak"],
        "cop_log": "Recon sweep: robots.txt and backup config downloaded from host",
        "time_cost": 120,
    },
    2: {
        "task": "Reach the administrator dashboard (any auth bypass that shows admin secrets).",
        "keys": ["admin_dashboard"],
        "cop_log": "Privilege escalation: unauthorized admin dashboard access",
        "time_cost": 150,
    },
    3: {
        "task": "Trigger reflected XSS on /search and stored XSS on /feedback.",
        "keys": ["xss_reflected", "xss_stored"],
        "cop_log": "XSS probes: script payloads submitted to search and feedback",
        "time_cost": 90,
    },
    4: {
        "task": "Prove SSTI on /search (server must evaluate template syntax).",
        "keys": ["ssti_probe"],
        "cop_log": "Template injection attempt on directory search endpoint",
        "time_cost": 90,
    },
    5: {
        "task": "Call the user profile API at /api/user/1 (or another ID).",
        "keys": ["idor_api"],
        "cop_log": "IDOR enumeration: sequential user API queried",
        "time_cost": 75,
    },
    6: {
        "task": "Request /api/reports with any department filter parameter.",
        "keys": ["reports_api"],
        "cop_log": "Report API accessed with user-supplied department filter",
        "time_cost": 75,
    },
    7: {
        "task": "Open a file through /files?name=… (not the default readme).",
        "keys": ["lfi_read"],
        "cop_log": "Document viewer used to retrieve archived file content",
        "time_cost": 60,
    },
    8: {
        "task": "Run network diagnostics with command chaining (e.g. 127.0.0.1; id).",
        "keys": ["cmdi_run"],
        "cop_log": "Network tool invoked with shell metacharacters in host field",
        "time_cost": 90,
    },
    9: {
        "task": "Use /fetch so the server requests an internal URL.",
        "keys": ["ssrf_fetch"],
        "cop_log": "Server-side fetch to internal health endpoint triggered",
        "time_cost": 90,
    },
    10: {
        "task": "Generate a password-reset link on /reset for any username.",
        "keys": ["reset_gen"],
        "cop_log": "Password reset workflow invoked for account enumeration",
        "time_cost": 60,
    },
    11: {
        "task": "Submit the profile form at /profile while signed in.",
        "keys": ["profile_post"],
        "cop_log": "Profile update POST with hidden access_level field present",
        "time_cost": 60,
    },
    12: {
        "task": "Open the submission form at /check.",
        "keys": ["check_visit"],
        "cop_log": "Hidden /check submission endpoint accessed",
        "time_cost": 45,
    },
}


def progress_list(session) -> list[str]:
    return list(session.get("guide_progress") or [])


def phase_ready(phase: int, session) -> bool:
    spec = GUIDE_CHALLENGES.get(phase)
    if not spec:
        return False
    done = set(progress_list(session))
    return all(k in done for k in spec["keys"])


def unlocked_list(session) -> list[int]:
    return list(session.get("guide_unlocked") or [])


def is_unlocked(phase: int, session) -> bool:
    return phase in unlocked_list(session)

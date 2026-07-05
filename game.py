"""
Multiplayer game modes for VulnLab (local training only).

COPS_AND_ROBBERS=1 — admins monitor logs and ban the attacker IP (2 guesses).
TIME_TRIAL=1       — timed cooperative extraction, no admins.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

COPS_AND_ROBBERS = False
TIME_TRIAL = False

PERP_WIN_SCORE = 13
ADMIN_BAN_ATTEMPTS = 2
MAX_COP_ADMINS = 4

_lock = threading.Lock()


def configure(cops_and_robbers: bool = False, time_trial: bool = False) -> None:
    global COPS_AND_ROBBERS, TIME_TRIAL
    COPS_AND_ROBBERS = cops_and_robbers
    TIME_TRIAL = time_trial


def game_mode_active() -> bool:
    return COPS_AND_ROBBERS or TIME_TRIAL


@dataclass
class LogEntry:
    ts: str
    ip: str
    method: str
    path: str
    user: str
    detail: str
    fake: bool = False
    alert: bool = False


@dataclass
class GameState:
    phase: str = "lobby"  # lobby | active | finished
    winner: str | None = None  # cops | perps | None
    win_message: str = ""

    # Cops & robbers
    cops_ready: bool = False
    perp_team_ip: str = ""
    perp_player_ips: dict[str, str] = field(default_factory=dict)  # session_id -> ip
    cop_player_ips: dict[str, str] = field(default_factory=dict)
    banned_ips: set[str] = field(default_factory=set)
    ban_attempts_used: int = 0
    alerts: list[str] = field(default_factory=list)
    logs: list[LogEntry] = field(default_factory=list)
    admin_accounts_created: int = 0
    cop_accounts: dict[str, str] = field(default_factory=dict)  # session_id -> adminN
    cop_slots_used: set[int] = field(default_factory=set)
    decoys_seeded: bool = False
    user_ip_map: dict[str, str] = field(default_factory=dict)
    office_ip_pool: list[str] = field(default_factory=list)

    # Shared /check form (multiplayer perps)
    check_draft: dict[str, str] = field(default_factory=dict)
    check_editors: dict[str, str] = field(default_factory=dict)  # field -> player name

    # Time trial
    trial_started_at: float | None = None
    trial_players: int = 1
    trial_best_seconds: float | None = None
    trial_finished_seconds: float | None = None
    trial_penalty_seconds: float = 0.0


_state = GameState()


def get_state() -> GameState:
    return _state


def reset_state() -> None:
    global _state
    with _lock:
        _state = GameState()


def reserve_cop_slot(session_id: str) -> int | None:
    """Return slot 1–4 for a new or returning cop session. None if team is full."""
    with _lock:
        if session_id in _state.cop_accounts:
            username = _state.cop_accounts[session_id]
            return int(username.removeprefix("admin"))
        for slot in range(1, MAX_COP_ADMINS + 1):
            if slot not in _state.cop_slots_used:
                return slot
        return None


def confirm_cop_account(session_id: str, slot: int) -> str:
    username = f"admin{slot}"
    with _lock:
        _state.cop_slots_used.add(slot)
        _state.cop_accounts[session_id] = username
        _state.admin_accounts_created = len(_state.cop_slots_used)
    return username


def cop_username_for_session(session_id: str) -> str | None:
    with _lock:
        return _state.cop_accounts.get(session_id)


    with _lock:
        return sorted(_state.cop_accounts.values(), key=lambda u: int(u.removeprefix("admin")))


def cop_admin_count() -> int:
    with _lock:
        return len(_state.cop_slots_used)


def mark_decoys_seeded() -> None:
    with _lock:
        _state.decoys_seeded = True


def decoys_seeded() -> bool:
    return _state.decoys_seeded


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


LIVE_LOG_PATHS = [
    ("/home", "GET", "Home page"),
    ("/dashboard", "GET", "Dashboard view"),
    ("/documents", "GET", "Document archive"),
    ("/search?q=org+chart", "GET", "Directory search"),
    ("/feedback", "GET", "Feedback portal"),
    ("/api/status", "GET", "Status probe"),
    ("/login", "POST", "Login attempt — success"),
    ("/login", "POST", "Login attempt — invalid password"),
    ("/tools/ping", "GET", "Network tools page"),
    ("/profile", "GET", "Profile view"),
    ("/api/reports?dept=SOC", "GET", "Department report export"),
    ("/files?name=readme.txt", "GET", "Document open"),
    ("/files?name=board_memo.pdf", "GET", "Confidential PDF access"),
    ("/reset", "GET", "Password reset page"),
]


def _ts_sort_key(entry: LogEntry):
    try:
        return datetime.strptime(entry.ts.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def log_entry_to_dict(entry: LogEntry) -> dict:
    return {
        "ts": entry.ts,
        "ip": entry.ip,
        "method": entry.method,
        "path": entry.path,
        "user": entry.user,
        "detail": entry.detail,
        "fake": entry.fake,
        "alert": entry.alert,
    }


def _tick_live_logs_unlocked() -> None:
    if not COPS_AND_ROBBERS or _state.phase != "active":
        return
    usernames = list(_state.user_ip_map.keys()) or ["jdoe"]
    pool = _state.office_ip_pool or [f"192.168.47.{n}" for n in range(100, 128)]
    for _ in range(random.randint(1, 3)):
        user = random.choice(usernames)
        ip = _state.user_ip_map.get(user, random.choice(pool))
        path, method, detail = random.choice(LIVE_LOG_PATHS)
        _state.logs.insert(
            0,
            LogEntry(
                ts=_now(),
                ip=ip,
                method=method,
                path=path,
                user=user,
                detail=detail,
                fake=True,
            ),
        )
    if len(_state.logs) > 300:
        del _state.logs[300:]


def tick_live_logs() -> None:
    with _lock:
        _tick_live_logs_unlocked()


def logs_snapshot(*, tick: bool = True) -> list[dict]:
    with _lock:
        if tick:
            _tick_live_logs_unlocked()
        ordered = sorted(_state.logs, key=_ts_sort_key, reverse=True)
        return [log_entry_to_dict(e) for e in ordered]


def _pick_perp_ip() -> str:
    """Believable LAN address — blends with decoy 192.168.x traffic."""
    return f"192.168.{random.randint(1, 254)}.{random.randint(2, 250)}"


def _fake_log_pool(user_ip_map: dict[str, str] | None = None) -> list[LogEntry]:
    """Generate believable background noise using workforce usernames and office IPs."""
    rnd = random.Random(42)
    user_ip_map = user_ip_map or {}
    usernames = list(user_ip_map.keys()) or [
        "jsmith", "mchen", "ppatel", "klee", "rgarcia", "tdavis", "admin1", "admin2",
    ]
    office_ips = list({ip for ip in user_ip_map.values()}) if user_ip_map else [
        f"192.168.47.{n}" for n in range(100, 128)
    ]
    extra_ips = [
        "192.168.1.10", "192.168.1.11", "192.168.1.45", "192.168.4.22",
        "192.168.10.5", "10.0.0.12", "10.0.1.88",
    ]
    fake_ips = office_ips + extra_ips
    paths = [
        ("/home", "GET", "Home page"),
        ("/dashboard", "GET", "Dashboard view"),
        ("/documents", "GET", "Document archive"),
        ("/search?q=org+chart", "GET", "Directory search"),
        ("/feedback", "GET", "Feedback portal"),
        ("/api/status", "GET", "Status probe"),
        ("/login", "POST", "Login attempt — success"),
        ("/login", "POST", "Login attempt — invalid password"),
        ("/tools/ping", "GET", "Network tools page"),
        ("/profile", "GET", "Profile view"),
        ("/api/reports?dept=SOC", "GET", "Department report export"),
        ("/files?name=readme.txt", "GET", "Document open"),
        ("/reset", "GET", "Password reset page"),
    ]
    entries: list[LogEntry] = []
    base = datetime.now(timezone.utc)
    for i in range(80):
        user = rnd.choice(usernames)
        ip = user_ip_map.get(user, rnd.choice(fake_ips))
        path, method, detail = rnd.choice(paths)
        ts = (base - timedelta(minutes=rnd.randint(5, 480))).strftime("%Y-%m-%d %H:%M:%S UTC")
        entries.append(
            LogEntry(
                ts=ts,
                ip=ip,
                method=method,
                path=path,
                user=user,
                detail=detail,
                fake=True,
            )
        )
    return entries


def start_cops_and_robbers(
    user_ip_map: dict[str, str] | None = None,
    perp_ip: str | None = None,
) -> None:
    with _lock:
        _state.phase = "active"
        if user_ip_map:
            _state.user_ip_map = dict(user_ip_map)
            _state.office_ip_pool = list({ip for ip in user_ip_map.values()})
        if perp_ip:
            _state.perp_team_ip = perp_ip
        elif _state.office_ip_pool:
            _state.perp_team_ip = random.choice(_state.office_ip_pool)
        elif not _state.perp_team_ip:
            _state.perp_team_ip = _pick_perp_ip()
        for sid in list(_state.perp_player_ips.keys()):
            _state.perp_player_ips[sid] = _state.perp_team_ip
        _state.logs = sorted(_fake_log_pool(_state.user_ip_map), key=_ts_sort_key, reverse=True)
        _state.alerts = [
            "Monitoring active. Review access logs for anomalous activity.",
            "Baseline traffic includes internal 192.168.x hosts — not every entry is suspicious.",
        ]


def start_time_trial(players: int) -> None:
    with _lock:
        _state.phase = "active"
        _state.trial_players = max(1, min(5, players))
        _state.trial_started_at = time.time()


def assign_player_ip(session_id: str, team: str) -> str:
    with _lock:
        if team == "perp":
            if not _state.perp_team_ip:
                if _state.office_ip_pool:
                    _state.perp_team_ip = random.choice(_state.office_ip_pool)
                else:
                    _state.perp_team_ip = _pick_perp_ip()
            _state.perp_player_ips[session_id] = _state.perp_team_ip
            return _state.perp_team_ip
        if session_id not in _state.cop_player_ips:
            n = len(_state.cop_player_ips) + 1
            _state.cop_player_ips[session_id] = f"192.168.100.{10 + n}"
        return _state.cop_player_ips[session_id]


def client_ip(session_id: str, team: str | None, remote_addr: str) -> str:
    if not game_mode_active():
        return remote_addr
    forwarded = None  # filled by caller
    if team in ("cop", "perp"):
        return assign_player_ip(session_id, team)
    return remote_addr


def is_ip_banned(ip: str) -> bool:
    return ip in _state.banned_ips


def game_finished() -> bool:
    return _state.phase == "finished"


def finish_game(winner: str, message: str) -> None:
    with _lock:
        _state.phase = "finished"
        _state.winner = winner
        _state.win_message = message


def add_alert(message: str) -> None:
    with _lock:
        _state.alerts.insert(0, message)


def log_request(
    ip: str,
    method: str,
    path: str,
    user: str,
    detail: str,
    *,
    alert: bool = False,
) -> None:
    if not COPS_AND_ROBBERS or _state.phase != "active":
        return
    with _lock:
        _state.logs.insert(
            0,
            LogEntry(
                ts=_now(),
                ip=ip,
                method=method,
                path=path,
                user=user or "—",
                detail=detail,
                fake=False,
                alert=alert,
            ),
        )


def log_admin_intrusion(ip: str, username: str) -> None:
    msg = f"⚠ INTRUSION: Admin session opened as '{username}' from {ip}"
    add_alert(msg)
    log_request(
        ip,
        "POST",
        "/login",
        username,
        "Unauthorized administrator login detected",
        alert=True,
    )


def clear_logs() -> None:
    with _lock:
        _state.logs = [e for e in _state.logs if e.fake]
        _state.logs.sort(key=_ts_sort_key, reverse=True)
        _state.alerts = ["Logs cleared — decoy baseline traffic retained."]


def delete_log(index: int) -> bool:
    with _lock:
        real_logs = [(i, e) for i, e in enumerate(_state.logs) if not e.fake]
        if index < 0 or index >= len(real_logs):
            return False
        real_idx = real_logs[index][0]
        del _state.logs[real_idx]
        return True


def attempt_ban(ip: str) -> dict:
    if not COPS_AND_ROBBERS or _state.phase != "active":
        return {"ok": False, "error": "Game not active"}
    with _lock:
        if _state.ban_attempts_used >= ADMIN_BAN_ATTEMPTS:
            return {"ok": False, "error": "No ban attempts remaining"}
        _state.ban_attempts_used += 1
        _state.banned_ips.add(ip)
        remaining = ADMIN_BAN_ATTEMPTS - _state.ban_attempts_used

        perp_ips = {_state.perp_team_ip} | set(_state.perp_player_ips.values())
        if ip in perp_ips:
            finish_game(
                "cops",
                f"🛡️ COPS WIN — {ip} was the attacker and has been full-banned from the portal.",
            )
            return {"ok": True, "correct": True, "game_over": True, "remaining": remaining}

        if _state.ban_attempts_used >= ADMIN_BAN_ATTEMPTS:
            finish_game(
                "perps",
                f"🏴 PERPS WIN — Admins banned the wrong IP ({ip}). No ban attempts left.",
            )
            return {"ok": True, "correct": False, "game_over": True, "remaining": 0}

        return {
            "ok": True,
            "correct": False,
            "game_over": False,
            "remaining": remaining,
            "message": f"IP {ip} banned. Wrong target — {remaining} attempt(s) left.",
        }


def check_perp_win(score: int, total: int) -> bool:
    if _state.phase != "active":
        return False
    if score >= PERP_WIN_SCORE:
        finish_game(
            "perps",
            f"🏴 PERPS WIN — Submission scored {score}/{total} (need {PERP_WIN_SCORE}+). "
            "Secrets extracted before admins identified the attacker.",
        )
        return True
    return False


def update_check_field(field: str, value: str, player: str) -> None:
    with _lock:
        _state.check_draft[field] = value
        _state.check_editors[field] = player


def get_check_state() -> dict:
    with _lock:
        return {
            "draft": dict(_state.check_draft),
            "editors": dict(_state.check_editors),
        }


def trial_elapsed() -> float | None:
    if _state.trial_started_at is None:
        return None
    return (time.time() - _state.trial_started_at) + _state.trial_penalty_seconds


def add_trial_penalty(seconds: float) -> None:
    with _lock:
        _state.trial_penalty_seconds += seconds


def log_hint_unlock(ip: str, username: str, phase: int, detail: str) -> None:
    add_alert(f"⚠ Hint unlock (phase {phase}) from {ip} — attacker may be stuck on this step")
    log_request(
        ip,
        "POST",
        f"/guide/unlock/{phase}",
        username or "—",
        f"Guide hint unlocked: {detail}",
        alert=True,
    )


def trial_par_seconds() -> float:
    """Target time shrinks as team improves."""
    base = 45 * 60  # 45 min first run
    if _state.trial_best_seconds:
        return max(300, _state.trial_best_seconds * 0.85)
    return base


def record_trial_finish(score: int, total: int) -> dict | None:
    if not TIME_TRIAL or _state.phase != "active":
        return None
    elapsed = trial_elapsed()
    if elapsed is None:
        return None
    with _lock:
        _state.trial_finished_seconds = elapsed
        if score >= PERP_WIN_SCORE:
            if _state.trial_best_seconds is None or elapsed < _state.trial_best_seconds:
                _state.trial_best_seconds = elapsed
            par = trial_par_seconds()
            if elapsed <= par:
                finish_game(
                    "perps",
                    f"⏱ TIME TRIAL CLEAR — {score}/{total} in {elapsed / 60:.1f} min "
                    f"(target was {par / 60:.1f} min).",
                )
            else:
                finish_game(
                    "perps",
                    f"⏱ TIME TRIAL — {score}/{total} in {elapsed / 60:.1f} min. "
                    f"Beat {par / 60:.1f} min next run for a faster tier.",
                )
            return {"elapsed": elapsed, "par": par, "score": score}
    return None


def public_status() -> dict:
    s = _state
    return {
        "mode": "cops_and_robbers" if COPS_AND_ROBBERS else ("time_trial" if TIME_TRIAL else "lab"),
        "phase": s.phase,
        "winner": s.winner,
        "win_message": s.win_message,
        "ban_attempts_remaining": max(0, ADMIN_BAN_ATTEMPTS - s.ban_attempts_used),
        "perp_win_threshold": PERP_WIN_SCORE,
        "cop_admin_count": len(s.cop_slots_used),
        "cop_admin_usernames": sorted(
            {f"admin{i}" for i in s.cop_slots_used},
            key=lambda u: int(u.removeprefix("admin")),
        ),
        "cops_ready": s.cops_ready,
        "trial_elapsed": trial_elapsed(),
        "trial_par_seconds": trial_par_seconds() if TIME_TRIAL else None,
        "trial_penalty_seconds": s.trial_penalty_seconds,
        "trial_players": s.trial_players,
    }

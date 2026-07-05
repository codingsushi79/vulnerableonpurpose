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


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _pick_perp_ip() -> str:
    """Believable LAN address — blends with decoy 192.168.x traffic."""
    return f"192.168.{random.randint(1, 254)}.{random.randint(2, 250)}"


def _fake_log_pool() -> list[LogEntry]:
    """Generate believable background noise including many 192.168 addresses."""
    rnd = random.Random(42)
    fake_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.45",
        "192.168.1.78",
        "192.168.4.22",
        "192.168.4.23",
        "192.168.10.5",
        "192.168.10.6",
        "192.168.47.100",
        "192.168.47.101",
        "192.168.47.102",
        "192.168.47.103",
        "192.168.47.104",
        "192.168.47.105",
        "192.168.47.106",
        "192.168.47.107",
        "192.168.47.108",
        "192.168.47.109",
        "192.168.47.110",
        "10.0.0.12",
        "10.0.0.15",
        "10.0.1.88",
        "172.16.0.4",
        "203.0.113.44",
        "198.51.100.9",
    ]
    users = ["jsmith", "mchen", "ppatel", "klee", "admin1", "admin2", "hr_bot", "—"]
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
    for i in range(55):
        ip = rnd.choice(fake_ips)
        path, method, detail = rnd.choice(paths)
        user = rnd.choice(users)
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


def start_cops_and_robbers(perp_ip: str | None = None) -> None:
    with _lock:
        _state.phase = "active"
        if perp_ip:
            _state.perp_team_ip = perp_ip
        elif not _state.perp_team_ip:
            _state.perp_team_ip = _pick_perp_ip()
        for sid in list(_state.perp_player_ips.keys()):
            _state.perp_player_ips[sid] = _state.perp_team_ip
        _state.logs = _fake_log_pool()
        random.shuffle(_state.logs)
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
        _state.logs.append(
            LogEntry(
                ts=_now(),
                ip=ip,
                method=method,
                path=path,
                user=user or "—",
                detail=detail,
                fake=False,
                alert=alert,
            )
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
        "trial_elapsed": trial_elapsed(),
        "trial_par_seconds": trial_par_seconds() if TIME_TRIAL else None,
        "trial_penalty_seconds": s.trial_penalty_seconds,
        "trial_players": s.trial_players,
    }

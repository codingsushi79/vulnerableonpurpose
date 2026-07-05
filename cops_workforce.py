"""Seed a believable employee roster for Cops & Robbers (decoys + cop admin accounts)."""

from __future__ import annotations

import random
import sqlite3

DECOY_EMPLOYEES: list[tuple[str, str, str]] = [
    ("jsmith", "j.smith@securecorp.local", "Sales"),
    ("mchen", "m.chen@securecorp.local", "Engineering"),
    ("ppatel", "ppatel@securecorp.local", "HR"),
    ("klee", "k.lee@securecorp.local", "Marketing"),
    ("rgarcia", "rgarcia@securecorp.local", "Finance"),
    ("tdavis", "tdavis@securecorp.local", "Support"),
    ("aokonkwo", "aokonkwo@securecorp.local", "SOC"),
    ("bwright", "bwright@securecorp.local", "Legal"),
    ("cjones", "cjones@securecorp.local", "IT"),
    ("dnguyen", "dnguyen@securecorp.local", "Operations"),
    ("ehill", "ehill@securecorp.local", "Sales"),
    ("fwu", "fwu@securecorp.local", "Engineering"),
    ("gadams", "gadams@securecorp.local", "HR"),
    ("hberry", "hberry@securecorp.local", "Support"),
    ("imartinez", "imartinez@securecorp.local", "Finance"),
    ("jkim", "jkim@securecorp.local", "Marketing"),
    ("lbrown", "lbrown@securecorp.local", "SOC"),
    ("mross", "mross@securecorp.local", "IT"),
    ("nwhite", "nwhite@securecorp.local", "Operations"),
    ("oprice", "oprice@securecorp.local", "Legal"),
    ("qking", "qking@securecorp.local", "Engineering"),
    ("rshaw", "rshaw@securecorp.local", "Sales"),
    ("slopez", "slopez@securecorp.local", "Support"),
    ("tng", "tng@securecorp.local", "Finance"),
    ("uwalsh", "uwalsh@securecorp.local", "Marketing"),
]

DECOY_PASSWORD = "Welcome2026!"
OFFICE_IP_POOL = [f"192.168.47.{n}" for n in range(100, 128)]


def _assign_office_ips(usernames: list[str]) -> dict[str, str]:
    rnd = random.Random()
    return {username: rnd.choice(OFFICE_IP_POOL) for username in usernames}


def seed_cops_workforce(
    db: sqlite3.Connection,
    admin_count: int,
    admin_password: str,
) -> dict[str, str]:
    roster: list[tuple[str, str, str, str, str]] = []
    for username, email, dept in DECOY_EMPLOYEES:
        roster.append((username, email, dept, "user", DECOY_PASSWORD))

    for i in range(1, admin_count + 1):
        roster.append(
            (f"admin{i}", f"admin{i}@gmail.com", "IT Security", "admin", admin_password)
        )

    random.shuffle(roster)
    ip_map = _assign_office_ips([r[0] for r in roster])

    for username, email, dept, role, password in roster:
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
                dept,
                f"key_{username}",
                "Standard employee provisioning.",
                ip_map[username],
            ),
        )

    db.commit()
    return ip_map


def pick_perp_ip(user_ip_map: dict[str, str]) -> str:
    ips = list(user_ip_map.values())
    if not ips:
        return random.choice(OFFICE_IP_POOL)
    return random.choice(ips)

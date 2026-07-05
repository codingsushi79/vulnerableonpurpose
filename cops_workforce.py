"""Seed a believable employee roster for Cops & Robbers (decoys + cop admin accounts)."""

from __future__ import annotations

import random
import sqlite3

# (first_name, last_name, department)
EMPLOYEE_NAMES: list[tuple[str, str, str]] = [
    ("John", "Doe", "Sales"),
    ("Maria", "Chen", "Engineering"),
    ("Priya", "Patel", "HR"),
    ("Kevin", "Lee", "Marketing"),
    ("Rosa", "Garcia", "Finance"),
    ("Thomas", "Davis", "Support"),
    ("Amara", "Okonkwo", "SOC"),
    ("Brian", "Wright", "Legal"),
    ("Christina", "Jones", "IT"),
    ("David", "Nguyen", "Operations"),
    ("Emily", "Hill", "Sales"),
    ("Frank", "Wu", "Engineering"),
    ("Grace", "Adams", "HR"),
    ("Hannah", "Berry", "Support"),
    ("Isaac", "Martinez", "Finance"),
    ("Julia", "Kim", "Marketing"),
    ("Lucas", "Brown", "SOC"),
    ("Megan", "Ross", "IT"),
    ("Nathan", "White", "Operations"),
    ("Olivia", "Price", "Legal"),
    ("Quinn", "King", "Engineering"),
    ("Rachel", "Shaw", "Sales"),
    ("Samuel", "Lopez", "Support"),
    ("Tanya", "Ng", "Finance"),
    ("Victor", "Walsh", "Marketing"),
]

DECOY_PASSWORD = "Welcome2026!"
OFFICE_IP_POOL = [f"192.168.47.{n}" for n in range(100, 128)]


def employee_identity(first_name: str, last_name: str) -> tuple[str, str]:
    """Username: first initial + last name (jdoe). Email: first+last@securecorp.local (johndoe@...)."""
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    username = f"{first[0]}{last}"
    email = f"{first}{last}@securecorp.local"
    return username, email


def _unique_identities(
    names: list[tuple[str, str, str]],
) -> list[tuple[str, str, str, str, str]]:
    """Return (username, email, department, first_name, last_name) with collision handling."""
    roster: list[tuple[str, str, str, str, str]] = []
    used_usernames: set[str] = set()

    for first, last, dept in names:
        username, email = employee_identity(first, last)
        if username in used_usernames:
            suffix = 2
            while f"{username}{suffix}" in used_usernames:
                suffix += 1
            username = f"{username}{suffix}"
            email = f"{first.lower()}{last.lower()}{suffix}@securecorp.local"
        used_usernames.add(username)
        roster.append((username, email, dept, first, last))

    return roster


def _assign_office_ips(usernames: list[str]) -> dict[str, str]:
    rnd = random.Random()
    return {username: rnd.choice(OFFICE_IP_POOL) for username in usernames}


def seed_cops_workforce(
    db: sqlite3.Connection,
    admin_count: int,
    admin_password: str,
) -> dict[str, str]:
    roster: list[tuple[str, str, str, str, str, str]] = []
    for username, email, dept, first, last in _unique_identities(EMPLOYEE_NAMES):
        display = f"{first} {last}"
        roster.append((username, email, dept, "user", DECOY_PASSWORD, display))

    for i in range(1, admin_count + 1):
        roster.append(
            (
                f"admin{i}",
                f"admin{i}@gmail.com",
                "IT Security",
                "admin",
                admin_password,
                f"Admin {i}",
            )
        )

    random.shuffle(roster)
    ip_map = _assign_office_ips([r[0] for r in roster])

    for username, email, dept, role, password, display_name in roster:
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
                f"{display_name} — standard employee account.",
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

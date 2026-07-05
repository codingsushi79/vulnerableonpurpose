"""Lab secret values — static in normal mode, random vault in competitive modes."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
VAULT_PATH = APP_DIR / ".lab_flags.json"
EPOCH_PATH = APP_DIR / ".lab_epoch"

DEFAULTS = {
    "admin_password": "Sup3rS3cr3t!",
    "lab_flag": "VULN{1nt3rc3pt_4nd_1nj3ct}",
    "internal_token": "tok_live_7f3a9c2e",
    "xss_flag": "VULN{xss_p4yl0ad_fired}",
    "idor_flag": "VULN{id0r_us3r_l33k}",
    "lfi_flag": "VULN{l0cal_f1le_r3ad}",
    "cmdi_flag": "VULN{c0mm4nd_1nj3ct}",
    "ssrf_flag": "VULN{ssrf_1ntern4l}",
    "backup_flag": "VULN{b4ckup_expos3d}",
    "reset_flag": "VULN{w34k_r3s3t_t0k3n}",
    "ssti_flag": "VULN{ssti_t3mplat3}",
    "profile_flag": "VULN{pr0f1l3_3sc4l4te}",
    "report_flag": "VULN{r3p0rt_sqli}",
}

_vault: dict[str, str] | None = None
_epoch: str | None = None


def get_epoch() -> str:
    """Stable per lab run — bumps on VULNLAB_RESET to invalidate all cookies."""
    global _epoch
    if _epoch is not None:
        return _epoch
    if EPOCH_PATH.exists():
        _epoch = EPOCH_PATH.read_text(encoding="utf-8").strip()
    else:
        _epoch = secrets.token_hex(16)
        EPOCH_PATH.write_text(_epoch, encoding="utf-8")
    return _epoch


def bump_epoch() -> str:
    global _epoch
    _epoch = secrets.token_hex(16)
    EPOCH_PATH.write_text(_epoch, encoding="utf-8")
    return _epoch


def _random_flag() -> str:
    return f"VULN{{{secrets.token_hex(6)}}}"


def regenerate() -> dict[str, str]:
    global _vault
    _vault = {
        "admin_password": secrets.token_urlsafe(10),
        "internal_token": f"tok_{secrets.token_hex(8)}",
        **{k: _random_flag() for k in DEFAULTS if k not in ("admin_password", "internal_token")},
    }
    VAULT_PATH.write_text(json.dumps(_vault, indent=2), encoding="utf-8")
    return _vault


def load(*, use_vault: bool) -> dict[str, str]:
    global _vault
    if not use_vault:
        _vault = dict(DEFAULTS)
        return _vault
    if _vault is not None:
        return _vault
    if VAULT_PATH.exists():
        _vault = json.loads(VAULT_PATH.read_text(encoding="utf-8"))
        return _vault
    return regenerate()


def get(key: str) -> str:
    if _vault is None:
        load(use_vault=VAULT_PATH.exists())
    return _vault[key]  # type: ignore[index]


def all_secrets() -> dict[str, str]:
    if _vault is None:
        load(use_vault=VAULT_PATH.exists())
    return dict(_vault)  # type: ignore[arg-type]

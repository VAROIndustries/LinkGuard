"""
SQLite database layer for LinkGuard.
Stored at %%APPDATA%%/LinkGuard/linkguard.db
"""
import sqlite3
import os
import logging
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "LinkGuard"
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / "linkguard.db"

# Migrate data from old PhishUrl directory if needed
_old_dir = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "PhishUrl"
if not DB_PATH.exists() and (_old_dir / "phishurl.db").exists():
    import shutil
    shutil.copy2(_old_dir / "phishurl.db", DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS whitelist (
    domain      TEXT PRIMARY KEY,
    added_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    domain      TEXT PRIMARY KEY,
    added_at    TEXT NOT NULL,
    reason      TEXT
);

CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    domain      TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT NOT NULL,
    reasons     TEXT,
    action      TEXT,
    checked_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
"""

DEFAULTS = {
    "clipboard_monitoring": "true",
    "protocol_handler":     "false",
    "startup":              "true",
    "risk_threshold":       "suspicious",   # clean | suspicious | phishing
    "google_sbrowsing_key": "",
    "virustotal_key":       "",
    "notify_clean":         "false",
    "real_browser_cmd":     "",             # stored when protocol handler is enabled
}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _connect() as conn:
        conn.executescript(SCHEMA)
        for k, v in DEFAULTS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v)
            )


# ── Settings ──────────────────────────────────────────────────────────────────

def get_setting(key: str) -> str:
    with _connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else DEFAULTS.get(key, "")


def set_setting(key: str, value: str):
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )


def get_all_settings() -> dict:
    with _connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}


# ── Whitelist ─────────────────────────────────────────────────────────────────

def is_whitelisted(domain: str) -> bool:
    domain = _normalize_domain(domain)
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM whitelist WHERE domain=?", (domain,)
        ).fetchone()
        return row is not None


def add_whitelist(domain: str):
    domain = _normalize_domain(domain)
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (domain, added_at) VALUES (?, ?)",
            (domain, _now()),
        )


def remove_whitelist(domain: str):
    domain = _normalize_domain(domain)
    with _connect() as conn:
        conn.execute("DELETE FROM whitelist WHERE domain=?", (domain,))


def get_whitelist() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT domain, added_at FROM whitelist ORDER BY domain"
        ).fetchall()
        return [dict(r) for r in rows]


# ── Blacklist ─────────────────────────────────────────────────────────────────

def is_blacklisted(domain: str) -> bool:
    domain = _normalize_domain(domain)
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM blacklist WHERE domain=?", (domain,)
        ).fetchone()
        return row is not None


def add_blacklist(domain: str, reason: str = ""):
    domain = _normalize_domain(domain)
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blacklist (domain, added_at, reason) VALUES (?, ?, ?)",
            (domain, _now(), reason),
        )


def remove_blacklist(domain: str):
    domain = _normalize_domain(domain)
    with _connect() as conn:
        conn.execute("DELETE FROM blacklist WHERE domain=?", (domain,))


def get_blacklist() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT domain, added_at, reason FROM blacklist ORDER BY domain"
        ).fetchall()
        return [dict(r) for r in rows]


# ── History ───────────────────────────────────────────────────────────────────

def add_history(url: str, domain: str, risk_score: int, risk_level: str,
                reasons: list[str], action: str):
    with _connect() as conn:
        conn.execute(
            """INSERT INTO history (url, domain, risk_score, risk_level, reasons, action, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (url, domain, risk_score, risk_level, "; ".join(reasons), action, _now()),
        )


def get_history(limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """SELECT id, url, domain, risk_score, risk_level, reasons, action, checked_at
               FROM history ORDER BY checked_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def clear_history():
    with _connect() as conn:
        conn.execute("DELETE FROM history")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().lstrip("www.")


def _now() -> str:
    return datetime.now().isoformat(sep=" ", timespec="seconds")

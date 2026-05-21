import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scans.db')


# ── Schema init ───────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)

    # Scan history table (existing)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT NOT NULL,
            filename         TEXT,
            code_type        TEXT NOT NULL,
            decision         TEXT NOT NULL,
            violations_count INTEGER NOT NULL,
            violations_json  TEXT NOT NULL,
            scan_time_ms     INTEGER NOT NULL,
            block_threshold  TEXT NOT NULL DEFAULT 'LOW',
            scanned_by       TEXT DEFAULT NULL
        )
    ''')

    # Users table (RBAC)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            hashed_pw  TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'DEVELOPER',
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'system'
        )
    ''')

    conn.commit()

    # Seed default Super Admin on first boot
    _seed_admin(conn)

    conn.close()


def _seed_admin(conn: sqlite3.Connection):
    """Create the default admin account if no users exist yet."""
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        from api.auth import hash_password
        conn.execute(
            "INSERT INTO users (username, hashed_pw, role, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            (
                "admin",
                hash_password("admin123"),
                "SUPER_ADMIN",
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "system",
            ),
        )
        conn.commit()
        print("[RBAC] Default Super Admin created -> username: admin / password: admin123")
        print("[RBAC] WARNING: Change the admin password after first login!")


# ── Scan history helpers ──────────────────────────────────────────────────────

def save_scan(
    filename: str,
    code_type: str,
    decision: str,
    violations: list,
    scan_time_ms: int,
    block_threshold: str,
    scanned_by: str = None,
):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT INTO scan_history
            (timestamp, filename, code_type, decision, violations_count,
             violations_json, scan_time_ms, block_threshold, scanned_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        filename or 'unknown',
        code_type,
        decision,
        len(violations),
        json.dumps(violations),
        scan_time_ms,
        block_threshold,
        scanned_by,
    ))
    conn.commit()
    conn.close()


def get_history(limit: int = 50, username: str = None) -> List[Dict[str, Any]]:
    """
    Return scan history.
    If username is provided, filter to scans made by that user only.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if username:
        rows = conn.execute(
            'SELECT * FROM scan_history WHERE scanned_by = ? ORDER BY id DESC LIMIT ?',
            (username, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM scan_history ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute('''
        SELECT
            COUNT(*)                                          AS total,
            SUM(CASE WHEN decision="BLOCK" THEN 1 ELSE 0 END) AS blocks,
            SUM(CASE WHEN decision="ALLOW" THEN 1 ELSE 0 END) AS allows
        FROM scan_history
    ''').fetchone()
    conn.close()
    total  = row[0] or 0
    blocks = row[1] or 0
    allows = row[2] or 0
    return {
        'total_requests':     total,
        'total_blocks':       blocks,
        'total_allows':       allows,
        'block_rate_percent': round((blocks / total * 100) if total else 0, 1),
    }


init_db()

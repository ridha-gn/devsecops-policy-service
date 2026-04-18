import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scans.db')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            filename        TEXT,
            code_type       TEXT NOT NULL,
            decision        TEXT NOT NULL,
            violations_count INTEGER NOT NULL,
            violations_json TEXT NOT NULL,
            scan_time_ms    INTEGER NOT NULL,
            block_threshold TEXT NOT NULL DEFAULT 'LOW'
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(filename: str, code_type: str, decision: str,
              violations: list, scan_time_ms: int, block_threshold: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT INTO scan_history
            (timestamp, filename, code_type, decision, violations_count, violations_json, scan_time_ms, block_threshold)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        filename or 'unknown',
        code_type,
        decision,
        len(violations),
        json.dumps(violations),
        scan_time_ms,
        block_threshold,
    ))
    conn.commit()
    conn.close()


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        'SELECT * FROM scan_history ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute('''
        SELECT
            COUNT(*)                                         AS total,
            SUM(CASE WHEN decision="BLOCK" THEN 1 ELSE 0 END) AS blocks,
            SUM(CASE WHEN decision="ALLOW" THEN 1 ELSE 0 END) AS allows
        FROM scan_history
    ''').fetchone()
    conn.close()
    total  = row[0] or 0
    blocks = row[1] or 0
    allows = row[2] or 0
    return {
        'total_requests':    total,
        'total_blocks':      blocks,
        'total_allows':      allows,
        'block_rate_percent': round((blocks / total * 100) if total else 0, 1),
    }


init_db()

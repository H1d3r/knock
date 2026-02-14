from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def _harden_user_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def get_db_path() -> Path:
    custom = os.getenv("KNOCKPY_DB")
    if custom:
        path = Path(custom).expanduser().resolve()
    else:
        path = Path.home() / ".knockpy" / "reports.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_db(db_path: Optional[Path] = None) -> Path:
    """Initialize DB schema and return DB path.

    Called by all storage entrypoints to ensure schema is available.
    """
    path = db_path or get_db_path()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                elapsed_seconds REAL,
                result_count INTEGER NOT NULL,
                results_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    _harden_user_file(path)
    return path


def _normalize_results(results: Union[dict, List[dict], None]) -> List[dict]:
    if results is None:
        return []
    if isinstance(results, dict):
        return [results]
    return results


def save_scan(
    target: str,
    mode: str,
    settings: Dict[str, Any],
    results: Union[dict, List[dict], None],
    elapsed: Optional[timedelta],
    db_path: Optional[Path] = None,
) -> int:
    path = init_db(db_path)
    rows = _normalize_results(results)
    elapsed_seconds = elapsed.total_seconds() if elapsed else None

    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans (target, mode, settings_json, elapsed_seconds, result_count, results_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                mode,
                json.dumps(settings, ensure_ascii=False),
                elapsed_seconds,
                len(rows),
                json.dumps(rows, ensure_ascii=False),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_reports(limit: int = 50, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, created_at, target, mode, result_count, elapsed_seconds
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def count_reports(db_path: Optional[Path] = None) -> int:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def get_report(selector: Optional[str], db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    query = ""
    params: tuple[Any, ...] = ()

    if selector is None or selector == "latest":
        query = "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
    elif isinstance(selector, str) and selector.isdigit():
        query = "SELECT * FROM scans WHERE id = ?"
        params = (int(selector),)
    else:
        selector_text = selector if isinstance(selector, str) else str(selector)
        query = "SELECT * FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1"
        params = (selector_text,)

    try:
        row = conn.execute(query, params).fetchone()
        if not row:
            return None
        data = dict(row)
        data["settings"] = json.loads(data.pop("settings_json"))
        data["results"] = json.loads(data.pop("results_json"))
        return data
    finally:
        conn.close()


def delete_report(report_id: int, db_path: Optional[Path] = None) -> bool:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM scans WHERE id = ?", (report_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def reset_reports(db_path: Optional[Path] = None) -> int:
    """Delete all stored scan reports and return the number of removed rows."""
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM scans")
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def get_setting(key: str, db_path: Optional[Path] = None) -> Optional[str]:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else None
    finally:
        conn.close()


def get_settings(prefix: Optional[str] = None, db_path: Optional[Path] = None) -> Dict[str, Optional[str]]:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        if prefix:
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key LIKE ? ORDER BY key",
                (f"{prefix}%",),
            ).fetchall()
        else:
            rows = conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
        return {str(k): (None if v is None else str(v)) for k, v in rows}
    finally:
        conn.close()


def set_setting(key: str, value: Optional[str], db_path: Optional[Path] = None) -> None:
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')
            """,
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()

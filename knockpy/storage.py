from __future__ import annotations

"""Persistence and report export facade for knockpy.

Public storage API remains stable while implementation is split by concern:
- `knockpy.storage_parts.db`: SQLite persistence and settings
- `knockpy.storage_parts.export`: report row normalization and HTML export
"""

from .storage_parts.db import (
    count_reports,
    delete_report,
    get_db_path,
    get_report,
    get_setting,
    get_settings,
    init_db,
    list_reports,
    reset_reports,
    save_scan,
    set_setting,
)
from .storage_parts.export import export_report

__all__ = [
    "get_db_path",
    "init_db",
    "save_scan",
    "list_reports",
    "count_reports",
    "get_report",
    "delete_report",
    "reset_reports",
    "get_setting",
    "get_settings",
    "set_setting",
    "export_report",
]

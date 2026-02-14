from __future__ import annotations

"""Compatibility facade for knockpy core engine.

Public imports remain stable while implementation lives in `knockpy.engine.runtime`.
"""

from .engine.runtime import *  # noqa: F401,F403
from .engine.runtime import _run_async, _run_coro_sync

__all__ = [
    "ROOT",
    "Bruteforce",
    "Recon",
    "AsyncScanner",
    "KNOCKPY",
    "pick_user_agent",
    "fmt_td",
    "logger",
    "_run_async",
    "_run_coro_sync",
]

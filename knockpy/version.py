"""Version helpers for knockpy."""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple

import httpx

__version__ = "9.0.0"
PYPI_PROJECT = "knock-subdomains"
PYPI_URL = f"https://pypi.org/pypi/{PYPI_PROJECT}/json"


def _version_key(raw: str) -> Tuple[int, ...]:
    """Convert a version string to a numeric tuple for conservative compare.

    Examples:
    - "9.0.0" -> (9, 0, 0)
    - "9.0.0rc1" -> (9, 0, 0, 1)
    """
    parts: list[int] = []
    for token in re.findall(r"\d+", str(raw or "")):
        try:
            parts.append(int(token))
        except Exception:
            continue
    return tuple(parts) if parts else (0,)


def is_newer_version(latest: str, current: str) -> bool:
    a = _version_key(latest)
    b = _version_key(current)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def check_latest_version(current: str = __version__, timeout: float = 2.5) -> Dict[str, Any]:
    """Check latest published version on PyPI.

    Returns a dict to keep caller logic stable and easy to render:
    - ok: bool
    - current: str
    - latest: Optional[str]
    - update_available: bool
    - url: str
    - error: Optional[str]
    """
    result: Dict[str, Any] = {
        "ok": False,
        "current": str(current),
        "latest": None,
        "update_available": False,
        "url": PYPI_URL,
        "error": None,
    }
    try:
        response = httpx.get(
            PYPI_URL,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": f"knockpy/{current}"},
        )
        if int(response.status_code) >= 400:
            result["error"] = f"HTTP {response.status_code}"
            return result
        payload = response.json()
        latest = str((payload.get("info") or {}).get("version") or "").strip()
        if not latest:
            result["error"] = "Missing version in PyPI response"
            return result
        result["ok"] = True
        result["latest"] = latest
        result["update_available"] = is_newer_version(latest, str(current))
        return result
    except Exception as exc:
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        return result

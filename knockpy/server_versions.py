from __future__ import annotations

"""Web-server version catalog and banner assessment helpers.

This module maintains a local catalog (`~/.knockpy/server_versions.json`) and
provides best-effort evaluation of `Server` headers (up-to-date/outdated/advisory).
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

CATALOG_PATH = Path.home() / ".knockpy" / "server_versions.json"
CATALOG_MAX_AGE = timedelta(days=7)


def _harden_user_file(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_catalog() -> Dict[str, Any]:
    return {
        "updated_at": None,
        "products": {
            "apache_http_server": {
                "label": "Apache HTTP Server",
                "latest": None,
                "source": "https://downloads.apache.org/httpd/",
                "check_mode": "strict",
            },
            "nginx": {
                "label": "Nginx",
                "latest": None,
                "source": "https://nginx.org/en/download.html",
                "check_mode": "strict",
            },
            "microsoft_iis": {
                "label": "Microsoft-IIS",
                "latest": "10.0",
                "source": "https://learn.microsoft.com/iis/",
                "check_mode": "advisory",
                "note": "IIS patch state depends on Windows cumulative updates.",
            },
            "microsoft_httpapi": {
                "label": "Microsoft-HTTPAPI",
                "latest": None,
                "source": "https://learn.microsoft.com/windows/win32/http/http-api-start-page",
                "check_mode": "advisory",
                "note": "HTTPAPI patch state is OS-coupled; banner version is not enough.",
            },
            "oracle_application_server": {
                "label": "Oracle-Application-Server",
                "latest": None,
                "source": "https://docs.oracle.com/",
                "check_mode": "advisory",
                "note": "Legacy Oracle AS versions often require lifecycle/support validation, not simple version compare.",
            },
            "securetransport": {
                "label": "SecureTransport",
                "latest": None,
                "source": "https://www.progress.com/",
                "check_mode": "advisory",
                "note": "Version freshness should be validated against vendor advisory/support matrix.",
            },
            "openresty": {
                "label": "OpenResty",
                "latest": None,
                "source": "https://openresty.org/en/download.html",
                "check_mode": "advisory",
            },
            "litespeed": {
                "label": "LiteSpeed",
                "latest": None,
                "source": "https://www.litespeedtech.com/products/litespeed-web-server/download",
                "check_mode": "advisory",
            },
            "caddy": {
                "label": "Caddy",
                "latest": None,
                "source": "https://github.com/caddyserver/caddy/releases",
                "check_mode": "advisory",
            },
            "envoy": {
                "label": "Envoy",
                "latest": None,
                "source": "https://github.com/envoyproxy/envoy/releases",
                "check_mode": "advisory",
            },
            "jetty": {
                "label": "Jetty",
                "latest": None,
                "source": "https://github.com/jetty/jetty.project/releases",
                "check_mode": "advisory",
            },
            "tomcat": {
                "label": "Apache Tomcat",
                "latest": None,
                "source": "https://tomcat.apache.org/whichversion.html",
                "check_mode": "advisory",
            },
            "gunicorn": {
                "label": "Gunicorn",
                "latest": None,
                "source": "https://github.com/benoitc/gunicorn/releases",
                "check_mode": "advisory",
            },
        },
    }


def _read_catalog() -> Dict[str, Any]:
    """Read catalog from disk and merge missing defaults from current release."""
    defaults = _default_catalog()
    if CATALOG_PATH.is_file():
        _harden_user_file(CATALOG_PATH)
        try:
            data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("products"), dict):
                merged = dict(data)
                merged_products = dict(data.get("products") or {})
                default_products = dict(defaults.get("products") or {})
                for name, meta in default_products.items():
                    existing = merged_products.get(name)
                    if not isinstance(existing, dict):
                        merged_products[name] = dict(meta)
                        continue
                    merged_item = dict(meta)
                    merged_item.update(existing)
                    merged_products[name] = merged_item
                merged["products"] = merged_products
                return merged
        except Exception:
            pass
    return defaults


def _write_catalog(data: Dict[str, Any]) -> None:
    CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    _harden_user_file(CATALOG_PATH)


def _parse_version(text: str) -> Tuple[int, ...]:
    nums = [int(p) for p in re.findall(r"\d+", text)]
    return tuple(nums) if nums else (0,)


def _max_version(values: List[str]) -> Optional[str]:
    if not values:
        return None
    unique = sorted(set(values), key=_parse_version)
    return unique[-1] if unique else None


def _fetch_apache_latest(timeout: float = 12.0) -> Optional[str]:
    url = "https://downloads.apache.org/httpd/"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        versions = re.findall(r"httpd-(\d+\.\d+\.\d+)\.tar\.(?:gz|bz2|xz)", response.text or "")
        return _max_version(versions)
    except Exception:
        return None


def _fetch_nginx_latest(timeout: float = 12.0) -> Optional[str]:
    url = "https://nginx.org/en/download.html"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        versions = re.findall(r"nginx-(\d+\.\d+\.\d+)\.tar\.gz", response.text or "")
        return _max_version(versions)
    except Exception:
        return None


def update_server_versions_catalog(timeout: float = 12.0) -> Dict[str, Any]:
    """Refresh known latest versions from upstream sources and persist catalog."""
    catalog = _read_catalog()
    products = dict(catalog.get("products") or {})

    apache_latest = _fetch_apache_latest(timeout=timeout)
    if apache_latest:
        products.setdefault("apache_http_server", {}).update({"latest": apache_latest})

    nginx_latest = _fetch_nginx_latest(timeout=timeout)
    if nginx_latest:
        products.setdefault("nginx", {}).update({"latest": nginx_latest})

    catalog["products"] = products
    catalog["updated_at"] = _now_iso()
    _write_catalog(catalog)
    return catalog


def _catalog_is_stale(catalog: Dict[str, Any]) -> bool:
    raw = catalog.get("updated_at")
    if not raw:
        return True
    try:
        ts = datetime.fromisoformat(str(raw))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        return True
    return datetime.now(timezone.utc) - ts > CATALOG_MAX_AGE


def load_server_versions_catalog(auto_update: bool = True) -> Dict[str, Any]:
    """Load catalog, optionally auto-refreshing stale data."""
    catalog = _read_catalog()
    if auto_update and _catalog_is_stale(catalog):
        try:
            catalog = update_server_versions_catalog()
        except Exception:
            pass
    else:
        if not CATALOG_PATH.is_file():
            _write_catalog(catalog)
    return catalog


def _detect_product_and_version(server_banner: str) -> Tuple[Optional[str], Optional[str]]:
    text = (server_banner or "").strip()
    if not text:
        return None, None
    patterns = [
        ("apache_http_server", r"(?i)\bapache\/(\d+\.\d+(?:\.\d+)*)", None),
        ("nginx", r"(?i)\bnginx\/(\d+\.\d+(?:\.\d+)*)", None),
        ("microsoft_iis", r"(?i)\bmicrosoft-iis\/(\d+\.\d+(?:\.\d+)*)", None),
        ("microsoft_httpapi", r"(?i)\bmicrosoft-httpapi\/(\d+\.\d+(?:\.\d+)*)", None),
        ("oracle_application_server", r"(?i)\boracle-application-server-(11g|12c)\b", None),
        ("securetransport", r"(?i)\bsecuretransport\s+(\d+(?:\.\d+)+)", None),
        ("openresty", r"(?i)\bopenresty\/(\d+\.\d+(?:\.\d+)*)", None),
        ("litespeed", r"(?i)\blitespeed\/(\d+\.\d+(?:\.\d+)*)", None),
        ("caddy", r"(?i)\bcaddy(?:\/|\s+)(\d+\.\d+(?:\.\d+)*)", None),
        ("envoy", r"(?i)\benvoy(?:\/|\s+)(\d+\.\d+(?:\.\d+)*)", None),
        ("jetty", r"(?i)\bjetty(?:\(|/)(\d+\.\d+(?:\.\d+)*)", None),
        ("tomcat", r"(?i)\bcoyote\/(\d+\.\d+(?:\.\d+)*)", None),
        ("gunicorn", r"(?i)\bgunicorn\/(\d+\.\d+(?:\.\d+)*)", None),
    ]
    for product, pattern, fixed_version in patterns:
        match = re.search(pattern, text)
        if match:
            version = match.group(1) if match.groups() else fixed_version
            return product, version
    return None, None


def assess_server_banner(
    server_banner: Optional[str], catalog: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Classify a web-server banner against the local version catalog.

    Used by verbose checks and HTML export enrichment.
    """
    banner = (server_banner or "").strip()
    if not banner:
        return {"status": "unknown", "label": "unknown", "banner": "-", "product": None, "version": None, "latest": None}

    product, version = _detect_product_and_version(banner)
    if not product or not version:
        return {
            "status": "unknown",
            "label": "unknown",
            "banner": banner,
            "product": None,
            "version": None,
            "latest": None,
            "note": "Version not exposed in Server header.",
        }

    data = catalog or load_server_versions_catalog(auto_update=False)
    product_meta = (data.get("products") or {}).get(product) or {}
    latest = product_meta.get("latest")
    check_mode = str(product_meta.get("check_mode") or "strict")
    label = str(product_meta.get("label") or product)
    note = product_meta.get("note")

    if check_mode != "strict":
        return {
            "status": "advisory",
            "label": "advisory",
            "banner": banner,
            "product": product,
            "product_label": label,
            "version": version,
            "latest": latest,
            "note": note or "Patch status may depend on OS/vendor backports.",
        }

    if not latest:
        return {
            "status": "unknown",
            "label": "unknown",
            "banner": banner,
            "product": product,
            "product_label": label,
            "version": version,
            "latest": None,
            "note": "Latest reference not available.",
        }

    cur = _parse_version(version)
    ref = _parse_version(str(latest))
    if cur < ref:
        state = "outdated"
    elif cur == ref:
        state = "up-to-date"
    else:
        state = "newer-than-reference"

    return {
        "status": state,
        "label": state,
        "banner": banner,
        "product": product,
        "product_label": label,
        "version": version,
        "latest": latest,
        "note": "Best-effort check. Distro backports may apply security fixes on older version strings.",
    }

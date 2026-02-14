from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .html_report import _build_html_report, _only_ipv4_list
from ..server_versions import assess_server_banner, load_server_versions_catalog


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "report"


def _rows_for_export(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    catalog = load_server_versions_catalog(auto_update=True)
    for item in results:
        http = item.get("http") or [None, None, None, None]
        https = item.get("https") or [None, None, None, None]
        cert = item.get("cert") or [None, None, None, None]
        ipv4_only = _only_ipv4_list(item.get("ip") or [])
        http_server_assessment = assess_server_banner(http[2] if len(http) > 2 else None, catalog=catalog)
        https_server_assessment = assess_server_banner(https[2] if len(https) > 2 else None, catalog=catalog)
        rows.append(
            {
                "domain": item.get("domain", ""),
                "ip": ipv4_only,
                "http_status": http[0],
                "http_redirect": http[1],
                "http_server": http[2],
                "http_server_status": http_server_assessment.get("status"),
                "http_server_version": http_server_assessment.get("version"),
                "http_server_latest": http_server_assessment.get("latest"),
                "https_status": https[0],
                "https_redirect": https[1],
                "https_server": https[2],
                "https_server_status": https_server_assessment.get("status"),
                "https_server_version": https_server_assessment.get("version"),
                "https_server_latest": https_server_assessment.get("latest"),
                "cert_valid": cert[0],
                "cert_expiry": cert[1],
                "cert_cn": cert[2],
                "tls_versions": cert[3] or [],
            }
        )
    return rows


def export_report(report: Dict[str, Any], export_format: str, output_path: Optional[str] = None) -> str:
    """Export a report to disk.

    Currently supports only HTML and writes a self-contained file.
    """
    if export_format != "html":
        raise ValueError("Only 'html' export is supported.")

    results = report.get("results") or []
    target = _safe_name(report.get("target", "scan"))
    report_id = report.get("id", "unknown")

    if output_path:
        out = Path(output_path)
    else:
        out = Path.cwd() / f"{target}_report_{report_id}.html"

    if out.exists() and out.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {out}")

    out.parent.mkdir(parents=True, exist_ok=True)

    rows = _rows_for_export(results)
    out.write_text(_build_html_report(report, rows, results), encoding="utf-8")
    return str(out)

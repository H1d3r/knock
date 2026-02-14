from __future__ import annotations

"""Terminal rendering helpers for knockpy.

This module contains presentation-only logic for standard and verbose output.
It does not perform network or persistence operations.
"""

from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core import ROOT, fmt_td
from .storage import count_reports, get_db_path

console = Console()
err_console = Console(stderr=True)


# Shared layout constants.
KV_FIELD_WIDTH = 30
SUMMARY_DOMAIN_WIDTH = 26
SUMMARY_IP_WIDTH = 16
SUMMARY_CODE_WIDTH = 6
SUMMARY_CERT_WIDTH = 8
SUMMARY_EXPIRY_WIDTH = 12
SUMMARY_STATUS_WIDTH = 10
COL3_W1 = 22
COL3_W2 = 18


def _table_width() -> int:
    try:
        return max(80, int(console.size.width) - 2)
    except Exception:
        return 100


def _new_table(
    *,
    title: Optional[str] = None,
    box_style: Any = box.SIMPLE,
    show_header: bool = True,
    header_style: Optional[str] = None,
) -> Table:
    return Table(
        title=title,
        box=box_style,
        show_header=show_header,
        header_style=header_style,
        title_justify="left",
        width=_table_width(),
        expand=False,
        pad_edge=False,
    )


def _kv_value_width() -> int:
    # Keep a fixed start point for Value across all 2-column tables.
    # Table border/spacing overhead is intentionally conservative.
    return max(24, _table_width() - KV_FIELD_WIDTH - 8)


def _add_kv_columns(table: Table) -> None:
    value_width = _kv_value_width()
    table.add_column(
        "Field",
        style="cyan",
        width=KV_FIELD_WIDTH,
        min_width=KV_FIELD_WIDTH,
        max_width=KV_FIELD_WIDTH,
        no_wrap=True,
    )
    table.add_column(
        "Value",
        width=value_width,
        min_width=value_width,
        max_width=value_width,
        overflow="fold",
        no_wrap=False,
    )


def _add_3col_columns(table: Table, c1: str, c2: str, c3: str, w1: int = COL3_W1, w2: int = COL3_W2) -> None:
    rem = max(20, _table_width() - w1 - w2 - 8)
    table.add_column(c1, width=w1, min_width=w1, max_width=w1, no_wrap=True, justify="left")
    table.add_column(c2, width=w2, min_width=w2, max_width=w2, no_wrap=True, justify="left")
    table.add_column(c3, width=rem, min_width=rem, max_width=rem, overflow="fold", no_wrap=False, justify="left")


def _parse_http_block(block: List[Any]) -> Dict[str, Any]:
    data = list(block or [])
    return {
        "status": data[0] if len(data) > 0 else None,
        "redirect": data[1] if len(data) > 1 else None,
        "server": data[2] if len(data) > 2 else None,
        "body_len": data[3] if len(data) > 3 else None,
        "app_redirect": data[4] if len(data) > 4 else None,
        "body_preview": data[5] if len(data) > 5 else None,
        "error": data[6] if len(data) > 6 else None,
    }


def _is_weak_tls(version: str) -> bool:
    return version.startswith("SSLv") or version in ("TLS 1.0", "TLS 1.1")


def _fmt_status(code: Any) -> str:
    if code is None:
        return "[red]-[/red]"
    try:
        value = int(code)
    except Exception:
        return str(code)
    if value >= 400:
        return f"[red]{value}[/red]"
    if value >= 300:
        return f"[yellow]{value}[/yellow]"
    return f"[green]{value}[/green]"


def _fmt_http_status(code: Any, https_ok: bool) -> str:
    if code is None:
        return "[red]-[/red]"
    try:
        value = int(code)
    except Exception:
        return str(code)
    if value >= 400:
        if https_ok:
            return f"[yellow]{value}[/yellow]"
        return f"[red]{value}[/red]"
    if value >= 300:
        return f"[yellow]{value}[/yellow]"
    return f"[green]{value}[/green]"


def _fmt_optional(value: Any, failed: bool = False) -> str:
    if value in (None, ""):
        return "[red]-[/red]" if failed else "-"
    return f"[red]{value}[/red]" if failed else str(value)


def _level_tag(level: str) -> str:
    lv = (level or "").lower()
    if lv == "ok":
        return "[green]ok[/green]"
    if lv in {"warning", "critical"}:
        return f"[red]{lv}[/red]"
    return "[yellow]info[/yellow]"


def _status_text(http_data: List[Any], https_data: List[Any], cert_data: List[Any]) -> str:
    has_http = http_data[0] is not None
    has_https = https_data[0] is not None
    cert_ok = bool(cert_data[0])
    tls_versions = cert_data[3] if len(cert_data) > 3 and isinstance(cert_data[3], list) else []
    weak_tls = any(_is_weak_tls(v) for v in tls_versions)

    if not has_http and not has_https:
        return "dns-only"
    if weak_tls:
        return "warning"
    if (has_http or has_https) and not cert_ok:
        return "warning"
    return "ok"


def _tls_label(tls_versions: Optional[List[str]]) -> str:
    if not tls_versions:
        return "-"
    return ", ".join(tls_versions)


def _format_ips_for_cell(values: List[str]) -> str:
    ips = [str(v).strip() for v in values if str(v).strip()]
    if not ips:
        return "-"
    lines: List[str] = []
    current = ""
    max_len = max(8, SUMMARY_IP_WIDTH)
    for ip in ips:
        if not current:
            current = ip
            continue
        candidate = f"{current}, {ip}"
        if len(candidate) <= max_len:
            current = candidate
            continue
        lines.append(current)
        current = ip
    if current:
        lines.append(current)
    return "\n".join(lines)


SECURITY_CHECK_ORDER = [
    ("security_txt", "security.txt"),
    ("headers", "Headers"),
    ("cookies", "Cookies"),
    ("server_version", "Server Version"),
    ("virustotal", "VirusTotal"),
    ("shodan", "Shodan"),
    ("tls_hygiene", "TLS Hygiene"),
    ("mixed_content", "Mixed Content"),
    ("caa", "CAA"),
    ("spf", "SPF"),
    ("dmarc", "DMARC"),
    ("dkim", "DKIM"),
    ("takeover", "Takeover Hint"),
    ("open_redirect", "Open Redirect"),
    ("methods", "HTTP Methods"),
    ("rate_waf", "Rate-limit/WAF"),
    ("emails", "Email Exposure"),
]

METHOD_FOCUS_ORDER = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS"]
DANGEROUS_HTTP_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def _preview(values: List[Any], limit: int = 3) -> str:
    items = [str(v).strip() for v in values if str(v).strip()]
    if not items:
        return "-"
    head = items[:limit]
    tail = len(items) - len(head)
    if tail > 0:
        return f"{', '.join(head)} (+{tail})"
    return ", ".join(head)


def _methods_evidence_lines(methods: Dict[str, Any]) -> List[str]:
    methods_http_obj = methods.get("http") or {}
    methods_https_obj = methods.get("https") or {}
    methods_http = methods_http_obj.get("allow") or []
    methods_https = methods_https_obj.get("allow") or []
    methods_http_cors = methods_http_obj.get("cors_allow") or []
    methods_https_cors = methods_https_obj.get("cors_allow") or []
    inferred_safe = methods.get("inferred_safe") or []

    enabled_union = {
        str(m).strip().upper()
        for m in (
            list(methods_http)
            + list(methods_https)
            + list(methods_http_cors)
            + list(methods_https_cors)
            + list(inferred_safe)
        )
        if str(m).strip()
    }
    enabled_focus = [m for m in METHOD_FOCUS_ORDER if m in enabled_union]
    dangerous = [m for m in METHOD_FOCUS_ORDER + ["CONNECT"] if m in enabled_union and m in DANGEROUS_HTTP_METHODS]

    lines: List[str] = []
    if enabled_focus:
        lines.append(f"Supported Methods: {' '.join(enabled_focus)}")
    else:
        lines.append("Supported Methods: unknown (server does not disclose Allow/CORS methods)")

    if inferred_safe:
        lines.append(f"source=inferred-safe-probe ({' '.join(inferred_safe)})")
    if dangerous:
        lines.append(f"[red]dangerous={', '.join(dangerous)}[/red]")

    lines.append(f"probe_status=http:{methods_http_obj.get('status') or '-'} https:{methods_https_obj.get('status') or '-'}")

    if methods_http or methods_https:
        lines.append(f"http={_preview(methods_http, limit=8)} | https={_preview(methods_https, limit=8)}")
    if methods_http_cors or methods_https_cors:
        lines.append(f"cors_http={_preview(methods_http_cors, limit=8)} | cors_https={_preview(methods_https_cors, limit=8)}")

    lines.append(f"risky={_preview(methods.get('risky_methods') or [], limit=6)}")
    return lines


def _security_evidence_map(verbose: Dict[str, Any]) -> Dict[str, List[str]]:
    security = verbose.get("security") or {}
    tls_info = verbose.get("tls") or {}
    evidence: Dict[str, List[str]] = {}

    def add(key: str, text: Any) -> None:
        value = str(text).strip()
        if not value or value == "-":
            return
        bucket = evidence.setdefault(key, [])
        if value not in bucket:
            bucket.append(value)

    sec_txt = security.get("security_txt") or {}
    add("security_txt", f"url={sec_txt.get('url') or '-'}")
    add("security_txt", f"status={sec_txt.get('status') or '-'}")

    srv = security.get("server_assessment") or {}
    add("server_version", f"banner={srv.get('banner') or '-'}")
    add("server_version", f"product={srv.get('product_label') or '-'}")
    add("server_version", f"detected={srv.get('version') or '-'} latest={srv.get('latest') or '-'}")
    add("server_version", f"catalog_updated={security.get('server_versions_updated_at') or '-'}")

    if tls_info.get("strict_ok") is False:
        add("tls_hygiene", f"strict_error={tls_info.get('strict_error') or '-'}")
    add("tls_hygiene", f"issuer={tls_info.get('issuer') or '-'}")
    add("tls_hygiene", f"protocol={tls_info.get('protocol') or '-'}")
    add("tls_hygiene", f"cipher={tls_info.get('cipher') or '-'}")

    add("mixed_content", f"refs={security.get('mixed_content_count') or 0}")

    caa = security.get("caa") or {}
    add("caa", f"entries={_preview(caa.get('entries') or [], limit=3)}")

    email_auth = security.get("email_auth") or {}
    spf = email_auth.get("spf") or {}
    add("spf", f"policy={spf.get('policy') or '-'}")
    add("spf", f"record={_preview(spf.get('records') or [], limit=1)}")

    dmarc = email_auth.get("dmarc") or {}
    add("dmarc", f"policy={dmarc.get('policy') or '-'}")
    add("dmarc", f"pct={dmarc.get('pct') if dmarc.get('pct') is not None else '-'}")
    add("dmarc", f"rua={dmarc.get('rua') or '-'}")
    add("dmarc", f"record={_preview(dmarc.get('records') or [], limit=1)}")

    dkim = email_auth.get("dkim") or {}
    add("dkim", f"selectors={_preview(dkim.get('selectors_found') or [], limit=4)}")
    add("dkim", f"max_bits={dkim.get('max_key_bits_est') or '-'}")

    takeover = security.get("takeover") or {}
    add("takeover", f"suspects={_preview(takeover.get('suspect_targets') or [], limit=4)}")

    methods = security.get("methods") or {}
    for line in _methods_evidence_lines(methods):
        add("methods", line)

    open_redirect = security.get("open_redirect") or {}
    probes = open_redirect.get("probes") or []
    flagged = [p for p in probes if isinstance(p, dict) and p.get("possible_open_redirect")]
    if flagged:
        add("open_redirect", f"confirmed={len(flagged)}/{len(probes)} probes")
        first = flagged[0]
        add("open_redirect", f"param={first.get('param') or '-'} status={first.get('status') or '-'}")

    rate_waf = security.get("rate_waf") or {}
    add("rate_waf", f"statuses={_preview(rate_waf.get('statuses') or [], limit=8)}")
    add("rate_waf", f"flags={_preview(rate_waf.get('waf_flags') or [], limit=6)}")

    emails = security.get("emails") or []
    add("emails", f"samples={_preview(emails, limit=3)}")

    threat = verbose.get("threat_intel") or security.get("threat_intel") or {}
    vt = threat.get("virustotal") or {}
    if vt.get("enabled") and vt.get("ok"):
        add("virustotal", f"mal={vt.get('malicious', 0)}")
        add("virustotal", f"susp={vt.get('suspicious', 0)}")
        add("virustotal", f"rep={vt.get('reputation', 0)}")

    shodan = threat.get("shodan") or {}
    if shodan.get("enabled") and shodan.get("ok"):
        add("shodan", f"ip={shodan.get('ip') or '-'}")
        add("shodan", f"ports={len(shodan.get('ports') or [])}")
        add("shodan", f"vulns={int(shodan.get('vuln_count') or len(shodan.get('vulns') or []))}")

    return evidence


def _merge_check_summary(
    key: str,
    item: Dict[str, Any],
    evidence_map: Dict[str, List[str]],
) -> str:
    summary = str(item.get("summary") or "-")
    details = evidence_map.get(key) or []
    if not details:
        return summary

    level = str(item.get("level") or "").strip().lower()
    max_parts = 3 if level in {"warning", "critical"} else 1
    if key in {"virustotal", "shodan", "server_version", "tls_hygiene", "methods"}:
        max_parts = max(max_parts, 2)
    compact = details[:max_parts]
    return f"{summary} | {' | '.join(compact)}"


def _print_security_checks_table(verbose: Dict[str, Any]) -> None:
    security = verbose.get("security") or {}
    checks = security.get("checks") or {}
    if not checks:
        return

    evidence_map = _security_evidence_map(verbose)
    table = _new_table(title="Security Checks", box_style=box.SIMPLE_HEAVY)
    _add_3col_columns(table, "Check", "Level", "Summary")

    for key, label in SECURITY_CHECK_ORDER:
        item = checks.get(key)
        if not isinstance(item, dict):
            continue
        summary = _merge_check_summary(key, item, evidence_map)
        table.add_row(label, _level_tag(str(item.get("level") or "info")), summary)

    console.print(table)


def _build_verbose_context(item: Dict[str, Any]) -> Dict[str, Any]:
    http_data = _parse_http_block(item.get("http") or [])
    https_data = _parse_http_block(item.get("https") or [])
    cert = item.get("cert") or [None, None, None, None]

    https_status = https_data.get("status")
    https_ok = isinstance(https_status, int) and 200 <= int(https_status) < 400

    cert_valid = cert[0] if len(cert) > 0 else None
    cert_expiry = cert[1] if len(cert) > 1 else None
    cert_cn = cert[2] if len(cert) > 2 else None
    tls_versions = cert[3] if len(cert) > 3 and cert[3] else []
    weak_tls = [v for v in tls_versions if _is_weak_tls(v)]

    expiry_expired = False
    if cert_expiry:
        try:
            expiry_expired = date.fromisoformat(cert_expiry) < date.today()
        except ValueError:
            expiry_expired = False
    cn_mismatch_probable = cert_valid is False and not expiry_expired

    takeover = item.get("takeover") or {}
    takeover_status = str(takeover.get("status") or "").strip().lower()
    takeover_provider = str(takeover.get("provider") or "-")
    takeover_cname = str(takeover.get("cname") or "-")
    if takeover_status == "likely":
        takeover_text = f"[red]likely[/red] ({takeover_provider}) {takeover_cname}"
    elif takeover_status == "possible":
        takeover_text = f"[yellow]possible[/yellow] ({takeover_provider}) {takeover_cname}"
    else:
        takeover_text = "[green]none[/green]"

    return {
        "http": http_data,
        "https": https_data,
        "https_ok": https_ok,
        "cert_valid": cert_valid,
        "cert_expiry": cert_expiry,
        "cert_cn": cert_cn,
        "tls_versions": tls_versions,
        "weak_tls": weak_tls,
        "expiry_expired": expiry_expired,
        "cn_mismatch_probable": cn_mismatch_probable,
        "takeover_text": takeover_text,
    }


def _print_verbose_check(
    item: Dict[str, Any],
    ctx: Dict[str, Any],
) -> None:
    http_data = ctx["http"]
    https_data = ctx["https"]
    table = _new_table(title=f"Verbose Check: {item.get('domain', '-')}", box_style=box.SIMPLE_HEAVY)
    _add_kv_columns(table)

    table.add_row("IP", ", ".join(item.get("ip") or []) or "[red]-[/red]")
    table.add_row("HTTP Status", _fmt_http_status(http_data.get("status"), https_ok=bool(ctx["https_ok"])))
    table.add_row("HTTPS Status", _fmt_status(https_data.get("status")))
    table.add_row("Redirect (HTTP)", _fmt_optional(http_data.get("redirect") or http_data.get("app_redirect")))
    table.add_row("Redirect (HTTPS)", _fmt_optional(https_data.get("redirect") or https_data.get("app_redirect")))

    http_len = http_data.get("body_len")
    https_len = https_data.get("body_len")
    http_len_text = "-" if http_len is None else str(http_len)
    https_len_text = "-" if https_len is None else str(https_len)
    table.add_row("Body Bytes (HTTP/HTTPS)", f"{http_len_text} / {https_len_text}")

    http_error = http_data.get("error")
    https_error = https_data.get("error")
    if http_error or https_error:
        merged = "; ".join(x for x in [str(http_error or "").strip(), str(https_error or "").strip()] if x)
        table.add_row("Request Errors", merged)

    cert_valid = ctx["cert_valid"]
    if cert_valid is False:
        cert_valid_text = "[red]False[/red]"
    elif cert_valid is True:
        cert_valid_text = "[green]True[/green]"
    else:
        cert_valid_text = "[red]-[/red]"

    table.add_row("Cert Valid", cert_valid_text)
    table.add_row("Cert Expiry", _fmt_optional(ctx["cert_expiry"], failed=bool(ctx["expiry_expired"])))
    table.add_row("Cert CN", _fmt_optional(ctx["cert_cn"], failed=bool(ctx["cn_mismatch_probable"])))

    tls_versions = ctx["tls_versions"]
    tls_text = ", ".join(tls_versions) if tls_versions else "[red]-[/red]"
    if ctx["weak_tls"]:
        tls_text = f"[red]{tls_text}[/red]"
    table.add_row("TLS Supported", tls_text)
    table.add_row("Takeover", str(ctx["takeover_text"]))

    console.print(table)


def _print_dns_axfr_group(verbose: Dict[str, Any], axfr: Dict[str, Any]) -> None:
    dns_info = verbose.get("dns") or {}

    table = _new_table(title="DNS + AXFR", box_style=box.SIMPLE)
    _add_kv_columns(table)

    table.add_row("DNS A", ", ".join(dns_info.get("a") or []) or "-")
    table.add_row("DNS AAAA", ", ".join(dns_info.get("aaaa") or []) or "-")
    table.add_row("DNS CNAME", ", ".join(dns_info.get("cname") or []) or "-")
    table.add_row("DNS TTL", ", ".join(f"{k}:{v}" for k, v in (dns_info.get("ttl") or {}).items()) or "-")
    table.add_row("DNS Errors", ", ".join(f"{k}:{v}" for k, v in (dns_info.get("errors") or {}).items()) or "-")

    if isinstance(axfr, dict) and axfr:
        table.add_row("AXFR Status", str(axfr.get("status") or "-"))
        table.add_row("AXFR Allowed NS", str(axfr.get("allowed_ns") or "-"))
        table.add_row("AXFR Record Count", str(axfr.get("record_count") or "-"))
        checks = axfr.get("checks") or []
        table.add_row("AXFR NS Checked", str(len(checks)))
        if checks:
            details = ", ".join(
                f"{c.get('ns')}:{c.get('status')}" for c in checks if isinstance(c, dict) and c.get("ns")
            )
            table.add_row("AXFR Per-NS", details or "-")
        if axfr.get("error"):
            table.add_row("AXFR Error", str(axfr.get("error")))

    console.print(table)


def _print_tls_handshake(verbose: Dict[str, Any]) -> None:
    tls_info = verbose.get("tls") or {}

    table = _new_table(title="TLS Handshake", box_style=box.SIMPLE)
    _add_kv_columns(table)

    strict_ok = tls_info.get("strict_ok")
    table.add_row("Strict Verify", "[green]True[/green]" if strict_ok else "[red]False[/red]")
    table.add_row("Strict Error", tls_info.get("strict_error") or "-")
    table.add_row("ALPN", tls_info.get("alpn") or "-")
    table.add_row("TLS Protocol", tls_info.get("protocol") or "-")
    table.add_row("Cipher", tls_info.get("cipher") or "-")
    table.add_row("SAN DNS", ", ".join(tls_info.get("san") or []) or "-")
    table.add_row("Issuer", str(tls_info.get("issuer") or "-"))

    console.print(table)


def _print_redirect_tls(verbose: Dict[str, Any]) -> None:
    redirect_tls = verbose.get("redirect_tls") or {}
    if not redirect_tls:
        return

    r_port = redirect_tls.get("port")
    r_handshake = redirect_tls.get("handshake") or {}
    r_versions = redirect_tls.get("versions") or []

    table = _new_table(title="Redirected TLS Port", box_style=box.SIMPLE)
    _add_kv_columns(table)

    table.add_row("Port", str(r_port or "-"))
    table.add_row("Strict Verify", "[green]True[/green]" if r_handshake.get("strict_ok") else "[red]False[/red]")
    table.add_row("Strict Error", str(r_handshake.get("strict_error") or "-"))
    table.add_row("TLS Protocol", str(r_handshake.get("protocol") or "-"))
    table.add_row("Cipher", str(r_handshake.get("cipher") or "-"))
    table.add_row("ALPN", str(r_handshake.get("alpn") or "-"))
    table.add_row("Supported Versions", ", ".join(r_versions) if r_versions else "-")

    console.print(table)

    weak_redirect = [v for v in r_versions if _is_weak_tls(v)]
    if weak_redirect:
        err_console.print(
            f"[yellow]Warning:[/yellow] Redirected port {r_port} supports legacy TLS: {', '.join(weak_redirect)}"
        )


def output(results: Union[dict, List[dict], None], elapsed: Optional[timedelta] = None) -> None:
    """Render the compact summary table shown after a scan."""
    if not results:
        err_console.print("[yellow]No results to display.[/yellow]")
        return

    items = [results] if isinstance(results, dict) else results
    notes: List[str] = []

    table = _new_table(box_style=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Domain", style="cyan", width=SUMMARY_DOMAIN_WIDTH, min_width=SUMMARY_DOMAIN_WIDTH, max_width=SUMMARY_DOMAIN_WIDTH, no_wrap=True, overflow="ellipsis")
    table.add_column(
        "IP",
        style="white",
        width=SUMMARY_IP_WIDTH,
        min_width=SUMMARY_IP_WIDTH,
        max_width=SUMMARY_IP_WIDTH,
        no_wrap=False,
        overflow="fold",
    )
    table.add_column("HTTP", justify="center", width=SUMMARY_CODE_WIDTH, min_width=SUMMARY_CODE_WIDTH, max_width=SUMMARY_CODE_WIDTH, no_wrap=True)
    table.add_column("HTTPS", justify="center", width=SUMMARY_CODE_WIDTH, min_width=SUMMARY_CODE_WIDTH, max_width=SUMMARY_CODE_WIDTH, no_wrap=True)
    table.add_column("Cert", justify="center", width=SUMMARY_CERT_WIDTH, min_width=SUMMARY_CERT_WIDTH, max_width=SUMMARY_CERT_WIDTH, no_wrap=True)
    table.add_column("Expiry", justify="center", width=SUMMARY_EXPIRY_WIDTH, min_width=SUMMARY_EXPIRY_WIDTH, max_width=SUMMARY_EXPIRY_WIDTH, no_wrap=True)
    table.add_column("TLS", overflow="fold", no_wrap=False)
    table.add_column("Status", justify="center", width=SUMMARY_STATUS_WIDTH, min_width=SUMMARY_STATUS_WIDTH, max_width=SUMMARY_STATUS_WIDTH, no_wrap=True)

    for item in items:
        for note in (item.get("scan_notes") or []):
            if isinstance(note, str) and note and note not in notes:
                notes.append(note)

        ips = _format_ips_for_cell(item.get("ip") or [])

        http = item.get("http") or [None, None, None, None]
        https = item.get("https") or [None, None, None, None]
        cert = item.get("cert") or [None, None, None, None]

        http_code = "-" if len(http) < 1 or http[0] is None else str(http[0])
        https_code = "-" if len(https) < 1 or https[0] is None else str(https[0])

        cert_ok = cert[0]
        cert_text = "-"
        if cert_ok is True:
            cert_text = "[green]valid[/green]"
        elif cert_ok is False:
            cert_text = "[red]invalid[/red]"

        status = _status_text(http, https, cert)
        takeover = item.get("takeover") or {}
        takeover_status = str(takeover.get("status") or "").strip().lower()
        if takeover_status in {"possible", "likely"} and status == "ok":
            status = "warning"

        if status == "ok":
            status_text = "[green]ok[/green]"
        elif status == "warning":
            status_text = "[yellow]warning[/yellow]"
        else:
            status_text = "[magenta]dns-only[/magenta]"

        table.add_row(
            item.get("domain", "-"),
            ips,
            http_code,
            https_code,
            cert_text,
            cert[1] or "-",
            _tls_label(cert[3] if len(cert) > 3 else None),
            status_text,
        )

    console.print(table)
    for note in notes:
        console.print(f"[yellow]Note:[/yellow] {note}")
    console.print(Panel.fit(f"[bold]Domains:[/bold] {len(items)}  [bold]Elapsed:[/bold] {fmt_td(elapsed)}", border_style="cyan"))


def print_scan_status(
    timeout: float,
    threads: Optional[int],
    dns: str,
    useragent: str,
    recon: bool,
    brute: bool,
    wordlist: Optional[str] = None,
    target_count: Optional[int] = None,
) -> None:
    if threads is None:
        if target_count is None:
            threads_value = "auto (dynamic: min(300, max(20, targets)))"
        else:
            auto_threads = min(300, max(20, target_count))
            threads_value = f"auto ({auto_threads})"
    else:
        threads_value = str(threads)

    default_wordlist = ROOT / "wordlist" / "wordlist.txt"
    default_wordlist_status = "present" if default_wordlist.is_file() else "missing"
    wordlist_mode = "custom" if wordlist else "default"

    table = _new_table(title="Scan Status", box_style=box.MINIMAL_DOUBLE_HEAD)
    _add_kv_columns(table)

    table.add_row("Timeout", str(timeout))
    table.add_row("Threads", threads_value)
    table.add_row("DNS", dns)
    table.add_row("User-Agent", useragent)
    table.add_row("Recon", str(recon))
    table.add_row("Bruteforce", str(brute))
    table.add_row("Wordlist Mode", wordlist_mode)
    table.add_row("Default Wordlist", f"{default_wordlist} ({default_wordlist_status})")
    table.add_row("Reports DB", str(get_db_path()))
    table.add_row("Reports Count", str(count_reports()))

    console.print(table)


def show_reports_catalog(reports: List[Dict[str, Any]]) -> None:
    if not reports:
        err_console.print("[yellow]No reports found in database.[/yellow]")
        return

    table = _new_table(title="Stored Reports", box_style=box.SIMPLE_HEAVY)
    table.add_column("ID", justify="right", style="cyan", width=5, min_width=5, max_width=5, no_wrap=True)
    table.add_column("Created", width=19, min_width=19, max_width=19, no_wrap=True)
    table.add_column("Target", overflow="fold", no_wrap=False)
    table.add_column("Mode", width=12, min_width=12, max_width=12, no_wrap=True)
    table.add_column("Results", justify="right", width=8, min_width=8, max_width=8, no_wrap=True)
    table.add_column("Elapsed", justify="right", width=10, min_width=10, max_width=10, no_wrap=True)

    for report in reports:
        elapsed = "-"
        if report.get("elapsed_seconds") is not None:
            elapsed = fmt_td(timedelta(seconds=float(report["elapsed_seconds"])))
        table.add_row(
            str(report.get("id")),
            str(report.get("created_at")),
            str(report.get("target")),
            str(report.get("mode")),
            str(report.get("result_count")),
            elapsed,
        )

    console.print(table)


def output_verbose(results: Union[dict, List[dict], None]) -> None:
    """Render deep protocol/security diagnostics for `--verbose` mode."""
    if not results:
        err_console.print("[yellow]No results to inspect.[/yellow]")
        return

    items = [results] if isinstance(results, dict) else results

    for item in items:
        verbose = item.get("verbose") or {}
        if not verbose:
            continue

        ctx = _build_verbose_context(item)

        # 3 columns with compact evidence.
        _print_security_checks_table(verbose)

        # 2 columns.
        _print_verbose_check(item=item, ctx=ctx)

        axfr = item.get("axfr") if isinstance(item.get("axfr"), dict) else {}
        _print_dns_axfr_group(verbose, axfr or {})
        _print_tls_handshake(verbose)
        _print_redirect_tls(verbose)

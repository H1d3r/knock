from __future__ import annotations

import sys
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from rich.panel import Panel
from rich.table import Table

from ..output import console, err_console, output, show_reports_catalog
from ..storage import delete_report, export_report, get_report, list_reports, reset_reports
from ..storage_parts.export import _rows_for_export
from ..storage_parts.html_report import _detail_issues


def _parse_report_ids(raw_ids: str) -> List[int]:
    ids: List[int] = []
    seen: set[int] = set()
    for chunk in raw_ids.split(","):
        value = chunk.strip()
        if not value:
            continue
        if not value.isdigit():
            raise ValueError(f"Invalid report id: {value}")
        report_id = int(value)
        if report_id not in seen:
            seen.add(report_id)
            ids.append(report_id)
    if not ids:
        raise ValueError("No report IDs provided")
    return ids


def _show_single_report(report: dict) -> None:
    elapsed = None
    if report.get("elapsed_seconds") is not None:
        elapsed = timedelta(seconds=float(report["elapsed_seconds"]))

    console.print(
        Panel.fit(
            f"[bold]Report[/bold] #{report['id']}  [bold]Target:[/bold] {report['target']}  "
            f"[bold]Created:[/bold] {report['created_at']}  [bold]Mode:[/bold] {report['mode']}",
            border_style="blue",
        )
    )
    output(report.get("results"), elapsed)


def _describe_report_findings(report: dict) -> None:
    results = report.get("results") or []
    if not results:
        console.print("[yellow]No results in this report.[/yellow]")
        return

    rows = _rows_for_export(results)
    results_by_domain = {str(item.get("domain") or ""): item for item in results}
    findings: Dict[str, List[Tuple[str, str]]] = {}

    def _build_evidence(detail_obj: Dict[str, Any], row: Dict[str, Any]) -> str:
        takeover = detail_obj.get("takeover") or {}
        takeover_status = str(takeover.get("status") or "").strip().lower()
        takeover_provider = str(takeover.get("provider") or "-").strip()
        takeover_cname = str(takeover.get("cname") or "-").strip()
        http = detail_obj.get("http") or []
        https = detail_obj.get("https") or []
        cert = detail_obj.get("cert") or []
        http_status = http[0] if len(http) > 0 else row.get("http_status")
        https_status = https[0] if len(https) > 0 else row.get("https_status")
        cert_expiry = cert[1] if len(cert) > 1 else row.get("cert_expiry")
        tls_versions = cert[3] if len(cert) > 3 else row.get("tls_versions")
        parts: List[str] = []

        if http_status is not None or https_status is not None:
            parts.append(f"HTTP={http_status if http_status is not None else '-'} HTTPS={https_status if https_status is not None else '-'}")
        if takeover_status in {"likely", "possible"}:
            parts.append(f"takeover={takeover_status} provider={takeover_provider} cname={takeover_cname}")
        if cert_expiry:
            parts.append(f"cert_expiry={cert_expiry}")
        if isinstance(tls_versions, list) and tls_versions:
            parts.append(f"tls={', '.join(str(v) for v in tls_versions)}")

        return " | ".join(parts) if parts else "-"

    for row in rows:
        domain = str(row.get("domain") or "").strip()
        detail_obj = results_by_domain.get(domain, {})
        issues = _detail_issues(detail_obj, row)
        for level, text in issues:
            if str(level).strip().lower() == "ok":
                continue
            evidence = _build_evidence(detail_obj, row)
            findings.setdefault(str(text), []).append((domain, evidence))

    console.print(
        Panel.fit(
            f"[bold]Findings[/bold] report #{report['id']}  "
            f"[bold]Target:[/bold] {report['target']}  "
            f"[bold]Created:[/bold] {report['created_at']}",
            border_style="magenta",
        )
    )
    if not findings:
        console.print("- No critical confirmed issue detected.")
        return

    ordered = sorted(findings.items(), key=lambda item: len(item[1]), reverse=True)
    for issue_text, entries in ordered:
        uniq_entries: List[Tuple[str, str]] = []
        seen_domains: set[str] = set()
        for domain, evidence in entries:
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            uniq_entries.append((domain, evidence))

        console.print(
            Panel.fit(
                f"[bold red]Problem:[/bold red] {issue_text}\n"
                f"[bold]Affected domains:[/bold] {len(uniq_entries)}",
                border_style="red",
            )
        )
        table = Table(box=None, show_header=True, header_style="bold cyan")
        table.add_column("Domain", overflow="fold")
        table.add_column("Evidence", overflow="fold")
        for domain, evidence in uniq_entries:
            table.add_row(domain, evidence)
        console.print(table)


def report_mode(report_selector: Optional[str]) -> None:
    """Interactive report manager used by `--report`.

    It supports listing, searching, showing, deleting, exporting and findings,
    including multi-selection for delete/export operations.
    """
    # Keep non-interactive behavior available for direct selectors.
    if not sys.stdin.isatty():
        if report_selector and report_selector not in {"choose", "list"}:
            report = get_report(report_selector)
            if not report:
                err_console.print(f"[red]Report not found:[/red] {report_selector}")
                return
            _show_single_report(report)
            return
        show_reports_catalog(list_reports(limit=100))
        err_console.print("[yellow]Interactive report menu requires a TTY.[/yellow]")
        return

    search_term = ""
    try:
        while True:
            reports = list_reports(limit=100)
            if search_term:
                filtered_reports = [r for r in reports if search_term in str(r.get("target", "")).lower()]
            else:
                filtered_reports = reports

            show_reports_catalog(filtered_reports)

            console.print("1 show")
            console.print("2 delete")
            console.print("3 export")
            console.print("4 search")
            console.print("5 findings")
            console.print("99 reset db")
            action_choice = input("Select action [1-5,99] (Enter to exit): ").strip()
            if action_choice == "":
                return
            action_map = {"99": "reset", "1": "show", "2": "delete", "3": "export", "4": "search", "5": "findings"}
            action = action_map.get(action_choice)
            if action is None:
                err_console.print("[red]Invalid action.[/red] Use: 1, 2, 3, 4, 5, 99.")
                continue

            if action == "reset":
                confirm = input("Type RESET to confirm DB reset (all reports will be deleted): ").strip()
                if confirm != "RESET":
                    console.print("[yellow]Reset cancelled.[/yellow]")
                    continue
                deleted = reset_reports()
                console.print(f"[green]DB reset completed.[/green] Removed reports: {deleted}")
                continue

            if action == "search":
                term = input("Search domain (partial, empty = reset): ").strip().lower()
                search_term = term
                continue

            if action == "show":
                selector = input("Report ID or target [latest]: ").strip() or "latest"
                report = get_report(selector)
                if not report:
                    err_console.print(f"[red]Report not found:[/red] {selector}")
                    continue
                _show_single_report(report)
                continue

            if action == "findings":
                selector = input("Report ID or target [latest]: ").strip() or "latest"
                report = get_report(selector)
                if not report:
                    err_console.print(f"[red]Report not found:[/red] {selector}")
                    continue
                _describe_report_findings(report)
                continue

            if action == "delete":
                raw_ids = input("Report IDs (comma-separated): ").strip()
                try:
                    report_ids = _parse_report_ids(raw_ids)
                except ValueError as exc:
                    err_console.print(f"[red]{exc}[/red]")
                    continue

                deleted_count = 0
                for report_id in report_ids:
                    if delete_report(report_id):
                        deleted_count += 1
                        console.print(f"[green]Report deleted:[/green] #{report_id}")
                    else:
                        err_console.print(f"[red]Report not found:[/red] {report_id}")
                console.print(f"[cyan]Delete summary:[/cyan] {deleted_count}/{len(report_ids)} deleted")
                continue

            if action == "export":
                fmt = "html"
                console.print("[cyan]Export format:[/cyan] html")
                raw_ids = input("Report IDs (comma-separated): ").strip()
                try:
                    report_ids = _parse_report_ids(raw_ids)
                except ValueError as exc:
                    err_console.print(f"[red]{exc}[/red]")
                    continue

                exported_count = 0
                for report_id in report_ids:
                    report = get_report(str(report_id))
                    if not report:
                        err_console.print(f"[red]Report not found:[/red] {report_id}")
                        continue
                    try:
                        export_file = export_report(report, fmt)
                        console.print(f"[green]Export completed:[/green] {export_file}")
                        exported_count += 1
                    except Exception as exc:
                        err_console.print(f"[red]Export failed for #{report_id}:[/red] {exc}")
                console.print(f"[cyan]Export summary:[/cyan] {exported_count}/{len(report_ids)} exported")
    except KeyboardInterrupt:
        console.print("\n[yellow]Report mode interrupted.[/yellow]")
        return

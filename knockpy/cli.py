from __future__ import annotations

"""Command-line interface for knockpy.

This module translates CLI flags into runtime settings, executes scans through
`knockpy.core`, and handles setup/report workflows backed by local storage.
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .core import AsyncScanner, Bruteforce, KNOCKPY, _run_async, _run_coro_sync, pick_user_agent
from .cli_parts.report import report_mode as _report_mode
from .cli_parts.scan_flow import (
    apply_exclude_rules as _apply_exclude_rules,
    parse_exclude_rules as _parse_exclude_rules,
    print_json_output as _print_json_output,
    print_server_versions_catalog as _print_server_versions_catalog,
    render_recon_test_table as _render_recon_test_table,
    run_recon_test as _run_recon_test,
    wildcard_consistent_length as _wildcard_consistent_length,
    wildcard_exclude_suggestions as _wildcard_exclude_suggestions,
)
from .cli_parts.setup import load_saved_runtime_settings as _load_saved_runtime_settings, setup_mode as _setup_mode
from .cli_parts.status import render_runtime_status_panel as _render_runtime_status_panel, wordlist_start_message as _wordlist_start_message
from .output import console, err_console, output, output_verbose, print_scan_status
from .storage import save_scan
from .server_versions import update_server_versions_catalog
from .version import __version__, check_latest_version


def _load_domains_from_file(file_path: str) -> List[str]:
    with Path(file_path).open("r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def _normalize_domain_input(value: str) -> Optional[str]:
    raw = (value or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip().lower()
        if host.startswith("www."):
            host = host[4:]
        return AsyncScanner._normalize_domain(host)
    return AsyncScanner._normalize_domain(raw)


def _normalize_domain_list(values: List[str]) -> List[str]:
    normalized: List[str] = []
    seen: set[str] = set()
    for raw in values:
        domain = _normalize_domain_input(raw)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        normalized.append(domain)
    return normalized


def _run_with_rich_progress(
    domains: List[str],
    dns: Optional[str],
    useragent: Optional[str],
    timeout: Optional[float],
    threads: Optional[int],
    recon: bool,
    bruteforce: bool,
    wordlist: Optional[str],
    verbose: bool = False,
    enable_axfr: bool = True,
    api_key_virustotal: Optional[str] = None,
    api_key_shodan: Optional[str] = None,
):
    """Execute scanning with a Rich progress bar bound to async callbacks."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning domains", total=max(len(domains), 1))

        def cb(done: int, total: int) -> None:
            progress.update(task_id, total=max(total, 1), completed=done)

        return _run_coro_sync(
            _run_async(
                domains,
                dns,
                useragent,
                timeout,
                threads,
                recon,
                bruteforce,
                wordlist,
                verbose=verbose,
                enable_axfr=enable_axfr,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
                progress_callback=cb,
            )
        )


def _should_save_scan(recon: bool, bruteforce: bool) -> bool:
    return recon or bruteforce


def main() -> None:
    """CLI entrypoint.

    This function is responsible for argument parsing, config layering
    (CLI > saved setup > built-in defaults), mode dispatch and result handling.
    """
    stdin_domain_sentinel = "__stdin_domain__"
    parser = argparse.ArgumentParser(
        prog="KNOCKPY",
        description=(
            f"knockpy v.{__version__} - Subdomain discovery and security checks\n"
            "CLI options > saved setup (--setup) > built-in defaults.\n"
            "https://github.com/guelfoweb/knockpy"
        ),
    )
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d",
        "--domain",
        nargs="?",
        const=stdin_domain_sentinel,
        help="Domain to analyze. If used without value, reads from stdin.",
    )
    target_group.add_argument("-f", "--file", help="File with domains, one per line.")

    mode_group = parser.add_argument_group("Scan Modes")
    mode_group.add_argument("--recon", help="Enable reconnaissance.", action="store_true")
    mode_group.add_argument("--bruteforce", "--brute", help="Enable bruteforce.", action="store_true")
    mode_group.add_argument("--wildcard", help="Test wildcard and exit.", action="store_true")
    mode_group.add_argument(
        "--exclude",
        nargs=2,
        action="append",
        metavar=("TYPE", "VALUE"),
        help="Exclude matches. TYPE=status, length/lenght (e.g. 275), or body. Repeatable.",
    )
    mode_group.add_argument(
        "--verbose",
        help="Verbose checks for single-domain scan only (without --recon/--bruteforce).",
        action="store_true",
    )
    mode_group.add_argument(
        "--test",
        help="With --recon, test each recon service and show which fails or returns data.",
        action="store_true",
    )

    setup_group = parser.add_argument_group("Setup and Reports")
    setup_group.add_argument(
        "--setup",
        help="Interactive setup: save runtime defaults and API keys in the local DB.",
        action="store_true",
    )
    setup_group.add_argument(
        "--report",
        nargs="?",
        const="choose",
        help="Report mode. In interactive terminals it opens the menu (show/delete/export/search/findings).",
    )
    setup_group.add_argument(
        "--update-versions",
        help="Update local web server versions catalog and show latest references.",
        action="store_true",
    )
    setup_group.add_argument(
        "--check-update",
        help="Check if a newer Knockpy version is available online (PyPI).",
        action="store_true",
    )

    runtime_group = parser.add_argument_group("Runtime Overrides (Advanced)")
    runtime_group.add_argument("--dns", help="DNS server (overrides saved setup).", dest="dns", required=False)
    runtime_group.add_argument(
        "--useragent",
        help="User-Agent string or 'random' (overrides saved setup).",
        dest="useragent",
        required=False,
    )
    runtime_group.add_argument(
        "--timeout",
        help="Timeout in seconds (overrides saved setup).",
        dest="timeout",
        type=float,
        required=False,
    )
    runtime_group.add_argument(
        "--threads",
        help="Concurrent workers (overrides saved setup).",
        dest="threads",
        type=int,
        required=False,
    )
    runtime_group.add_argument("--wordlist", help="Wordlist path (overrides saved setup).", dest="wordlist", required=False)

    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--silent", help="Silent mode (hide progress).", action="store_true")
    output_group.add_argument("--json", help="JSON-only output (forces --silent).", action="store_true")
    output_group.add_argument("--status", help="Print effective runtime status (including saved setup) and continue.", action="store_true")
    args = parser.parse_args()
    if args.json:
        args.silent = True

    if args.domain == stdin_domain_sentinel:
        args.domain = None

    if args.setup:
        _setup_mode()
        return
    if args.update_versions:
        catalog = update_server_versions_catalog()
        _print_server_versions_catalog(catalog)
        return
    if args.check_update:
        info = check_latest_version(current=__version__)
        if info.get("ok"):
            latest = str(info.get("latest") or __version__)
            if info.get("update_available"):
                console.print(
                    f"[yellow]Update available:[/yellow] current={__version__} latest={latest} "
                    "[cyan](pip install -U knock-subdomains)[/cyan]"
                )
            else:
                console.print(f"[green]You are up-to-date:[/green] v{__version__}")
        else:
            reason = str(info.get("error") or "unknown error")
            err_console.print(f"[yellow]Update check failed:[/yellow] {reason}")
        return

    if not args.domain and not args.file and not sys.stdin.isatty() and args.report is None:
        lines = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
        if len(lines) == 1:
            if Path(lines[0]).is_file():
                args.file = lines[0]
            else:
                args.domain = lines[0]
        elif len(lines) > 1:
            args.domain = lines

    if isinstance(args.domain, str):
        normalized_domain = _normalize_domain_input(args.domain)
        if not normalized_domain:
            err_console.print(f"[red]Invalid domain input:[/red] {args.domain}")
            return
        args.domain = normalized_domain
    elif isinstance(args.domain, list):
        normalized_domains = _normalize_domain_list([str(d) for d in args.domain])
        if not normalized_domains:
            err_console.print("[red]No valid domains found in input.[/red]")
            return
        args.domain = normalized_domains

    saved = _load_saved_runtime_settings()
    try:
        exclude_rules = _parse_exclude_rules(args.exclude)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        return
    timeout = args.timeout if args.timeout is not None else float(saved["timeout"])
    threads = args.threads if args.threads is not None else saved["threads"]
    dns = args.dns or saved["dns"] or "8.8.8.8"
    useragent = args.useragent or saved["useragent"] or "random"
    effective_useragent = pick_user_agent(useragent)
    wordlist_path = args.wordlist if args.wordlist is not None else saved["wordlist"]
    api_key_virustotal = saved["api_key_virustotal"]
    api_key_shodan = saved["api_key_shodan"]

    if args.report is not None:
        _report_mode(args.report)
        return

    status_target_count: Optional[int] = None
    if args.domain:
        status_target_count = 1 if isinstance(args.domain, str) else len(args.domain)
    elif args.file and Path(args.file).is_file():
        try:
            status_target_count = len(_load_domains_from_file(args.file))
        except Exception:
            status_target_count = None

    if args.status and not args.json:
        print_scan_status(
            timeout,
            threads,
            dns,
            effective_useragent,
            args.recon,
            args.bruteforce,
            wordlist_path,
            status_target_count,
        )

    if not args.domain and not args.file:
        if args.status:
            return
        parser.print_help(sys.stderr)
        return

    if args.test and not args.recon:
        if not args.json:
            err_console.print("[yellow]--test works with --recon; ignoring.[/yellow]")
        args.test = False

    if args.domain:
        domain_input: Union[str, List[str]] = args.domain
        verbose_enabled = (
            args.verbose
            and isinstance(domain_input, str)
            and not args.recon
            and not args.bruteforce
            and not args.wildcard
        )
        if args.verbose and not verbose_enabled and not args.json:
            err_console.print(
                "[yellow]--verbose works only with single-domain scan without --recon/--bruteforce/--wildcard.[/yellow]"
            )
        settings = {
            "dns": dns,
            "useragent": effective_useragent,
            "timeout": timeout,
            "threads": threads,
            "recon": args.recon,
            "bruteforce": args.bruteforce,
            "wordlist": wordlist_path,
            "wildcard": args.wildcard,
            "api_key_virustotal": bool(api_key_virustotal),
            "api_key_shodan": bool(api_key_shodan),
        }

        mode = "domain"
        scan_target = domain_input if isinstance(domain_input, str) else "multi-domain"
        recon_test_rows: Optional[List[Dict[str, Union[str, int, bool, None]]]] = None
        recon_test_domain: Optional[str] = domain_input if isinstance(domain_input, str) else (domain_input[0] if domain_input else None)
        if args.test and args.recon and recon_test_domain:
            recon_test_rows = _run_recon_test(
                recon_test_domain,
                timeout=timeout,
                useragent=effective_useragent,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
            )
            if not args.json:
                _render_recon_test_table(recon_test_domain, recon_test_rows)

        if args.wildcard and isinstance(domain_input, str):
            wildcard_domain = Bruteforce(domain_input).wildcard()
            mode = "wildcard"
            scan_target = wildcard_domain
            if not args.silent:
                _render_runtime_status_panel(
                target=str(scan_target),
                mode=mode,
                source="domain",
                timeout=timeout,
                threads=threads,
                target_count=1,
                dns=dns,
                    useragent=effective_useragent,
                    recon=False,
                    bruteforce=False,
                    wildcard=True,
                    wordlist=wordlist_path,
                    silent=args.silent,
                    api_key_virustotal=api_key_virustotal,
                    api_key_shodan=api_key_shodan,
                )
            start_time = datetime.now()
            results = KNOCKPY(
                wildcard_domain,
                dns=dns,
                useragent=effective_useragent,
                timeout=timeout,
                threads=threads,
                recon=False,
                bruteforce=False,
                wordlist=None,
                silent=True,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
            )
            elapsed = datetime.now() - start_time
            if results:
                if not args.json:
                    err_console.print("[yellow]Wildcard seems active for this domain.[/yellow]")
                    for suggestion in _wildcard_exclude_suggestions(results if isinstance(results, dict) else None):
                        console.print(f"[cyan]{suggestion}[/cyan]")
                    consistent_len = _wildcard_consistent_length(
                        domain_input,
                        results,
                        dns=dns,
                        useragent=effective_useragent,
                        timeout=timeout,
                        threads=threads,
                        api_key_virustotal=api_key_virustotal,
                        api_key_shodan=api_key_shodan,
                    )
                    if consistent_len is not None:
                        console.print(f"[cyan]Try excluding wildcard body length: --exclude lenght {consistent_len}[/cyan]")
                    else:
                        console.print(
                            "[yellow]Wildcard body length is not consistent across random probes; skipping length suggestion.[/yellow]"
                        )
            if args.json:
                _print_json_output(results)
            else:
                output(results, elapsed)
            return

        start_time = datetime.now()
        domains = [domain_input] if isinstance(domain_input, str) else list(domain_input)
        if not args.silent:
            _render_runtime_status_panel(
                target=", ".join(domains[:3]) + (" ..." if len(domains) > 3 else ""),
                mode=(
                    "recon+bruteforce"
                    if args.recon and args.bruteforce
                    else "recon"
                    if args.recon
                    else "bruteforce"
                    if args.bruteforce
                    else "domain"
                ),
                source="domain",
                timeout=timeout,
                threads=threads,
                target_count=len(domains),
                dns=dns,
                useragent=effective_useragent,
                recon=args.recon,
                bruteforce=args.bruteforce,
                wildcard=args.wildcard,
                wordlist=wordlist_path,
                silent=args.silent,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
            )
        if args.bruteforce and not args.json:
            console.print(f"[cyan]{_wordlist_start_message(wordlist_path)}[/cyan]")

        if args.silent:
            results = _run_coro_sync(
                _run_async(
                    domains,
                    dns,
                    effective_useragent,
                    timeout,
                    threads,
                    args.recon,
                    args.bruteforce,
                    wordlist_path,
                    verbose=verbose_enabled,
                    enable_axfr=True,
                    api_key_virustotal=api_key_virustotal,
                    api_key_shodan=api_key_shodan,
                )
            )
        else:
            results = _run_with_rich_progress(
                domains,
                dns,
                effective_useragent,
                timeout,
                threads,
                args.recon,
                args.bruteforce,
                wordlist_path,
                verbose=verbose_enabled,
                enable_axfr=True,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
            )

        elapsed = datetime.now() - start_time
        results, excluded_count = _apply_exclude_rules(results, exclude_rules)
        if excluded_count > 0 and not args.silent and not args.json:
            console.print(f"[yellow]Excluded results:[/yellow] {excluded_count}")
        if args.recon and args.bruteforce:
            mode = "recon+bruteforce"
        elif args.recon:
            mode = "recon"
        elif args.bruteforce:
            mode = "bruteforce"

        if _should_save_scan(args.recon, args.bruteforce):
            report_id = save_scan(str(scan_target), mode, settings, results, elapsed)
            if not args.silent and not args.json:
                console.print(f"[green]Saved report #[/green]{report_id}")
        if args.json:
            if recon_test_rows is not None:
                _print_json_output({"recon_test": recon_test_rows, "results": results})
            else:
                _print_json_output(results)
            return
        output(results, elapsed)
        if verbose_enabled and not args.json:
            output_verbose(results)
        return

    if args.file:
        if not Path(args.file).is_file():
            err_console.print(f"[red]File not found:[/red] {args.file}")
            return

        try:
            domains = _load_domains_from_file(args.file)
        except Exception as exc:
            err_console.print(f"[red]Cannot read file:[/red] {args.file} ({exc})")
            return

        domains = _normalize_domain_list(domains)
        if not domains:
            err_console.print(f"[yellow]No domains found in file:[/yellow] {args.file}")
            return

        settings = {
            "dns": dns,
            "useragent": effective_useragent,
            "timeout": timeout,
            "threads": threads,
            "recon": False,
            "bruteforce": False,
            "source_file": args.file,
        }

        start_time = datetime.now()
        if not args.silent:
            _render_runtime_status_panel(
                target=f"{len(domains)} domains",
                mode="file",
                source=args.file,
                timeout=timeout,
                threads=threads,
                target_count=len(domains),
                dns=dns,
                useragent=effective_useragent,
                recon=False,
                bruteforce=False,
                wildcard=False,
                wordlist=None,
                silent=args.silent,
                api_key_virustotal=api_key_virustotal,
                api_key_shodan=api_key_shodan,
            )
        if args.silent:
            results = _run_coro_sync(
                _run_async(
                    domains,
                    dns,
                    effective_useragent,
                    timeout,
                    threads,
                    recon=False,
                    bruteforce=False,
                    wordlist=None,
                    verbose=False,
                    enable_axfr=False,
                )
            )
        else:
            results = _run_with_rich_progress(
                domains,
                dns,
                effective_useragent,
                timeout,
                threads,
                recon=False,
                bruteforce=False,
                wordlist=None,
                verbose=False,
                enable_axfr=False,
            )

        elapsed = datetime.now() - start_time
        results, excluded_count = _apply_exclude_rules(results, exclude_rules)
        if excluded_count > 0 and not args.silent and not args.json:
            console.print(f"[yellow]Excluded results:[/yellow] {excluded_count}")
        if args.json:
            _print_json_output(results)
        else:
            output(results, elapsed)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted[/yellow]")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

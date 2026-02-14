from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from rich import box
from rich.table import Table

from ..core import Bruteforce, KNOCKPY, Recon, _run_coro_sync
from ..output import console
from ..server_versions import CATALOG_PATH


def _compact_home(path: Path) -> str:
    home = Path.home().resolve()
    resolved = path.expanduser().resolve()
    try:
        rel = resolved.relative_to(home)
        return f"~/{rel.as_posix()}" if str(rel) != "." else "~"
    except ValueError:
        return str(resolved)


def parse_exclude_rules(excludes: Optional[List[List[str]]]) -> Dict[str, Union[Set[int], List[str]]]:
    """Validate and normalize `--exclude` rules for fast runtime filtering."""
    rules: Dict[str, Union[Set[int], List[str]]] = {"status": set(), "body": [], "length": set()}
    if not excludes:
        return rules

    for raw_type, raw_value in excludes:
        rule_type = str(raw_type or "").strip().lower()
        value = str(raw_value or "").strip()
        if rule_type == "status":
            for part in value.split(","):
                part = part.strip()
                if not part:
                    continue
                if not part.isdigit():
                    raise ValueError(f"Invalid status in --exclude: {part}")
                status_code = int(part)
                if status_code < 100 or status_code > 599:
                    raise ValueError(f"Out-of-range status in --exclude: {status_code}")
                cast_set: Set[int] = rules["status"]  # type: ignore[assignment]
                cast_set.add(status_code)
        elif rule_type in {"length", "lenght"}:
            for part in value.split(","):
                part = part.strip().lower()
                if not part:
                    continue
                match = re.search(r"(\d+)", part)
                if not match:
                    raise ValueError(f"Invalid length in --exclude: {part}")
                length_value = int(match.group(1))
                if length_value < 0:
                    raise ValueError(f"Invalid length in --exclude: {part}")
                cast_len: Set[int] = rules["length"]  # type: ignore[assignment]
                cast_len.add(length_value)
        elif rule_type == "body":
            if not value:
                raise ValueError("--exclude body requires non-empty text")
            cast_list: List[str] = rules["body"]  # type: ignore[assignment]
            cast_list.append(value.lower())
        else:
            raise ValueError(f"Unsupported --exclude type: {rule_type} (use 'status', 'length', or 'body')")
    return rules


def _result_matches_exclude(item: dict, rules: Dict[str, Union[Set[int], List[str]]]) -> bool:
    status_rules: Set[int] = rules["status"]  # type: ignore[assignment]
    body_rules: List[str] = rules["body"]  # type: ignore[assignment]
    length_rules: Set[int] = rules["length"]  # type: ignore[assignment]

    http = item.get("http") or []
    https = item.get("https") or []
    http_status = http[0] if len(http) > 0 and isinstance(http[0], int) else None
    https_status = https[0] if len(https) > 0 and isinstance(https[0], int) else None
    if status_rules and (http_status in status_rules or https_status in status_rules):
        return True

    http_len = http[3] if len(http) > 3 and isinstance(http[3], int) else None
    https_len = https[3] if len(https) > 3 and isinstance(https[3], int) else None
    if length_rules and (http_len in length_rules or https_len in length_rules):
        return True

    if body_rules:
        http_body = str(http[5]).lower() if len(http) > 5 and http[5] is not None else ""
        https_body = str(https[5]).lower() if len(https) > 5 and https[5] is not None else ""
        for needle in body_rules:
            if needle in http_body or needle in https_body:
                return True
    return False


def apply_exclude_rules(
    results: Union[dict, List[dict], None],
    rules: Dict[str, Union[Set[int], List[str]]],
) -> tuple[Union[dict, List[dict], None], int]:
    if not results:
        return results, 0

    if isinstance(results, dict):
        return (None, 1) if _result_matches_exclude(results, rules) else (results, 0)

    filtered: List[dict] = []
    excluded = 0
    for item in results:
        if _result_matches_exclude(item, rules):
            excluded += 1
        else:
            filtered.append(item)
    return filtered, excluded


def print_json_output(results: Union[dict, List[dict], None]) -> None:
    try:
        sys.stdout.write(json.dumps(results, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
    except BrokenPipeError:
        # Preserve CLI behavior on piped output (e.g. `| head`) without traceback noise.
        return


def run_recon_test(
    domain: str,
    timeout: float,
    useragent: str,
    api_key_virustotal: Optional[str],
    api_key_shodan: Optional[str],
) -> List[Dict[str, Union[str, int, bool, None]]]:
    """Probe all enabled recon providers and return per-provider diagnostics."""
    engine = Recon(
        domain,
        timeout=timeout,
        max_concurrency=40,
        useragent=useragent,
        virustotal_key=api_key_virustotal,
        shodan_key=api_key_shodan,
    )
    return _run_coro_sync(engine.test_services())


def render_recon_test_table(domain: str, rows: List[Dict[str, Union[str, int, bool, None]]]) -> None:
    table = Table(title=f"Recon Services Test: {domain}", box=box.SIMPLE_HEAVY)
    table.add_column("Service", style="cyan")
    table.add_column("HTTP", justify="right")
    table.add_column("Parsed", justify="right")
    table.add_column("Status")
    table.add_column("Error", overflow="fold")

    ok_count = 0
    data_count = 0
    for row in rows:
        status_code = row.get("status_code")
        parsed_count = int(row.get("parsed_count") or 0)
        ok = bool(row.get("ok"))
        error = str(row.get("error") or "-")
        if ok:
            ok_count += 1
        if parsed_count > 0:
            data_count += 1

        if parsed_count > 0:
            status_text = "[green]data[/green]"
        elif ok:
            status_text = "[yellow]empty[/yellow]"
        else:
            status_text = "[red]failed[/red]"
        http_text = str(status_code if status_code is not None else "-")
        table.add_row(str(row.get("service") or "-"), http_text, str(parsed_count), status_text, error)

    console.print(table)
    console.print(f"[cyan]Recon test summary:[/cyan] reachable={ok_count}/{len(rows)} | with_data={data_count}/{len(rows)}")


def print_server_versions_catalog(catalog: Dict[str, Any]) -> None:
    products = catalog.get("products") or {}
    table = Table(title="Web Server Versions Catalog", box=box.SIMPLE_HEAVY)
    table.add_column("Product", style="cyan")
    table.add_column("Latest")
    table.add_column("Mode")
    table.add_column("Source", overflow="fold")
    for key, item in products.items():
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or key)
        latest = str(item.get("latest") or "-")
        mode = str(item.get("check_mode") or "strict")
        source = str(item.get("source") or "-")
        table.add_row(label, latest, mode, source)
    console.print(table)
    updated_at = catalog.get("updated_at") or "-"
    console.print(f"[cyan]Catalog path:[/cyan] {_compact_home(CATALOG_PATH)}")
    console.print(f"[cyan]Updated at:[/cyan] {updated_at}")


def wildcard_exclude_suggestions(result: Optional[dict]) -> List[str]:
    if not result:
        return []
    suggestions: List[str] = []
    http = result.get("http") or []
    https = result.get("https") or []
    status_codes: List[int] = []
    for candidate in (http[0] if len(http) > 0 else None, https[0] if len(https) > 0 else None):
        if isinstance(candidate, int) and candidate not in status_codes:
            status_codes.append(candidate)
    if status_codes:
        status_csv = ",".join(str(s) for s in status_codes)
        suggestions.append(f"Try excluding by status: --exclude status {status_csv}")

    return suggestions


def _preferred_body_length(result: Optional[Union[dict, List[dict]]]) -> Optional[int]:
    if not isinstance(result, dict):
        return None
    http = result.get("http") or []
    https = result.get("https") or []
    https_len = https[3] if len(https) > 3 and isinstance(https[3], int) else None
    http_len = http[3] if len(http) > 3 and isinstance(http[3], int) else None
    return https_len if https_len is not None else http_len


def wildcard_consistent_length(
    base_domain: str,
    first_result: Optional[Union[dict, List[dict]]],
    dns: str,
    useragent: str,
    timeout: float,
    threads: Optional[int],
    api_key_virustotal: Optional[str],
    api_key_shodan: Optional[str],
    extra_samples: int = 3,
) -> Optional[int]:
    first_len = _preferred_body_length(first_result)
    if first_len is None:
        return None

    lengths: List[int] = [first_len]
    for _ in range(extra_samples):
        probe_domain = Bruteforce(base_domain).wildcard()
        probe_result = KNOCKPY(
            probe_domain,
            dns=dns,
            useragent=useragent,
            timeout=timeout,
            threads=threads,
            recon=False,
            bruteforce=False,
            wordlist=None,
            silent=True,
            api_key_virustotal=api_key_virustotal,
            api_key_shodan=api_key_shodan,
        )
        probe_len = _preferred_body_length(probe_result)
        if probe_len is None:
            return None
        lengths.append(probe_len)

    return first_len if all(value == first_len for value in lengths) else None

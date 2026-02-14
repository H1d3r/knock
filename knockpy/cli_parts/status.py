from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from ..core import ROOT
from ..output import console
from ..storage import get_db_path
from ..version import __version__


def _compact_home(path: Path) -> str:
    home = Path.home().resolve()
    resolved = path.expanduser().resolve()
    try:
        rel = resolved.relative_to(home)
        return f"~/{rel.as_posix()}" if str(rel) != "." else "~"
    except ValueError:
        return str(resolved)


def render_runtime_status_panel(
    target: str,
    mode: str,
    source: str,
    timeout: float,
    threads: Optional[int],
    target_count: Optional[int],
    dns: str,
    useragent: str,
    recon: bool,
    bruteforce: bool,
    wildcard: bool,
    wordlist: Optional[str],
    silent: bool,
    api_key_virustotal: Optional[str] = None,
    api_key_shodan: Optional[str] = None,
) -> None:
    """Render the startup header with runtime, scan modes and API-key status."""
    term_width = console.size.width
    runtime_width = 80
    half_width = 40
    card_height = 13

    key_col_width = 11
    value_col_width = runtime_width - key_col_width - 6

    def _fit_value(value: object) -> str:
        text = str(value)
        # Keep cells on one line so all cards remain visually aligned.
        max_len = max(20, value_col_width)
        if len(text) <= max_len:
            return text
        if max_len <= 3:
            return "." * max_len
        return f"{text[: max_len - 3]}..."

    default_wordlist = ROOT / "wordlist" / "wordlist.txt"
    wordlist_display = wordlist or _compact_home(default_wordlist)

    if threads is None:
        if target_count is None:
            threads_value = "auto (dynamic)"
        else:
            threads_value = f"auto ({min(300, max(20, target_count))})"
    else:
        threads_value = str(threads)

    status = Table(box=box.MINIMAL, show_header=False, pad_edge=False, expand=False)
    status.add_column("Key", width=key_col_width, no_wrap=True)
    status.add_column("Value", width=value_col_width, no_wrap=True, overflow="crop")
    status.add_row("Target", _fit_value(target))
    status.add_row("Mode", _fit_value(mode))
    status.add_row("Timeout", _fit_value(timeout))
    status.add_row("Threads", _fit_value(threads_value))
    status.add_row("DNS", _fit_value(dns))
    status.add_row("User-Agent", _fit_value(useragent))
    status.add_row("Wordlist", _fit_value(wordlist_display))
    status.add_row("Reports DB", _fit_value(_compact_home(get_db_path())))
    status.add_row("Silent", _fit_value(silent))

    scan_modes = Table(title="Scans", box=box.SIMPLE_HEAVY)
    scan_modes.add_column("Mode", style="cyan")
    scan_modes.add_column("Status", style="white")
    scan_modes.add_row("Recon", "✅ enabled" if recon else "❌ disabled")
    scan_modes.add_row("Bruteforce", "✅ enabled" if bruteforce else "❌ disabled")
    scan_modes.add_row("Wildcard", "✅ enabled" if wildcard else "❌ disabled")

    api_keys = Table(title="API Keys", box=box.SIMPLE_HEAVY)
    api_keys.add_column("Provider", style="cyan")
    api_keys.add_column("Status", style="white")
    vt_enabled = bool(api_key_virustotal or os.getenv("API_KEY_VIRUSTOTAL"))
    shodan_enabled = bool(api_key_shodan or os.getenv("API_KEY_SHODAN"))
    api_keys.add_row("VirusTotal", "✅ enabled" if vt_enabled else "❌ disabled")
    api_keys.add_row("Shodan", "✅ enabled" if shodan_enabled else "❌ disabled")

    # Fixed dimensions: Runtime 80, Scans 40 + API Keys 40.
    status_panel = Panel(status, title="Runtime", border_style="cyan", width=runtime_width, height=card_height)
    scans_panel = Panel(scan_modes, title="Scans", border_style="cyan", width=half_width, height=card_height)
    keys_panel = Panel(api_keys, title="API Keys", border_style="cyan", width=half_width, height=card_height)

    if term_width >= 90:
        # No horizontal gap so bottom row width is exactly 40 + 40 = 80.
        content = Group(status_panel, Columns([scans_panel, keys_panel], equal=True, expand=False, padding=0))
    else:
        content = Group(status_panel, scans_panel, keys_panel)

    outer_width = runtime_width + 4
    console.print(Panel(content, title=f"Knockpy v{__version__}", border_style="blue", width=outer_width, expand=False))


def wordlist_start_message(wordlist: Optional[str]) -> str:
    default_wordlist = ROOT / "wordlist" / "wordlist.txt"
    if wordlist:
        return f"Wordlist selected: custom ({wordlist})"
    return f"Wordlist selected: default ({_compact_home(default_wordlist)})"

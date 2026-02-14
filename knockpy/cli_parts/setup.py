from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table

from ..core import ROOT
from ..output import console, err_console
from ..storage import get_settings, set_setting


def _compact_home(path: Path) -> str:
    home = Path.home().resolve()
    resolved = path.expanduser().resolve()
    try:
        rel = resolved.relative_to(home)
        return f"~/{rel.as_posix()}" if str(rel) != "." else "~"
    except ValueError:
        return str(resolved)


def _normalize_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = value.strip()
    return text if text else None


def load_saved_runtime_settings() -> dict:
    saved = get_settings()

    def _parse_float(value: Optional[str], default: float) -> float:
        if value is None:
            return default
        try:
            return float(value)
        except ValueError:
            return default

    def _parse_int(value: Optional[str]) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except ValueError:
            return None

    return {
        "dns": saved.get("runtime.dns") or "8.8.8.8",
        "useragent": saved.get("runtime.useragent") or "random",
        "timeout": _parse_float(saved.get("runtime.timeout"), 3.0),
        "threads": _parse_int(saved.get("runtime.threads")) or 250,
        "wordlist": _normalize_optional(saved.get("runtime.wordlist")),
        "api_key_virustotal": _normalize_optional(saved.get("apikey.virustotal")),
        "api_key_shodan": _normalize_optional(saved.get("apikey.shodan")),
    }


def setup_mode() -> None:
    """Interactive setup editor for persisted runtime defaults and API keys."""
    if not sys.stdin.isatty():
        err_console.print("[red]--setup requires interactive terminal.[/red]")
        return

    current = load_saved_runtime_settings()
    config = {
        "dns": current["dns"],
        "useragent": current["useragent"],
        "timeout": float(current["timeout"]),
        "threads": current["threads"],
        "wordlist": current["wordlist"],
        "api_key_virustotal": current["api_key_virustotal"],
        "api_key_shodan": current["api_key_shodan"],
    }
    default_wordlist_path = _compact_home(ROOT / "wordlist" / "wordlist.txt")
    console.print(Panel.fit("Knockpy Setup", border_style="blue"))
    console.print("Select ID 1-7 to edit a single field. Use 0 to save and exit.")
    console.print("Use '-' to clear optional values (wordlist/API keys, or threads=auto).")

    def _render_table(title: str) -> None:
        table = Table(title=title, box=box.SIMPLE_HEAVY)
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        table.add_row("1", "DNS", str(config["dns"]))
        table.add_row(
            "2",
            "User-Agent",
            "random (browser)" if str(config["useragent"]).strip().lower() == "random" else str(config["useragent"]),
        )
        table.add_row("3", "Timeout", str(config["timeout"]))
        table.add_row("4", "Threads", str(config["threads"]) if config["threads"] is not None else "auto")
        table.add_row(
            "5",
            "Wordlist",
            str(config["wordlist"]) if config["wordlist"] else f"default ({default_wordlist_path})",
        )
        table.add_row("6", "VirusTotal API", str(config["api_key_virustotal"] or ""))
        table.add_row("7", "Shodan API", str(config["api_key_shodan"] or ""))
        console.print(table)

    def _ask_text(label: str, current_value: Optional[str], optional: bool = False) -> Optional[str]:
        prompt = f"{label} [{current_value if current_value is not None else ''}]: "
        raw = input(prompt).strip()
        if raw == "":
            return current_value
        if optional and raw == "-":
            return None
        return raw

    while True:
        _render_table("Current Setup")
        console.print("0 save and exit")
        choice = input("Select field [1-7] or 0 to save: ").strip()
        if choice == "0":
            break
        if choice == "1":
            config["dns"] = _ask_text("DNS server", str(config["dns"])) or "8.8.8.8"
            continue
        if choice == "2":
            config["useragent"] = _ask_text("User-Agent (or 'random')", str(config["useragent"])) or "random"
            continue
        if choice == "3":
            raw_timeout = input(f"Timeout seconds [{config['timeout']}]: ").strip()
            if raw_timeout:
                try:
                    config["timeout"] = float(raw_timeout)
                except ValueError:
                    err_console.print("[yellow]Invalid timeout, value unchanged.[/yellow]")
            continue
        if choice == "4":
            raw_threads = input(f"Threads [{config['threads'] if config['threads'] is not None else 'auto'}]: ").strip()
            if raw_threads:
                if raw_threads == "-":
                    config["threads"] = None
                else:
                    try:
                        config["threads"] = int(raw_threads)
                    except ValueError:
                        err_console.print("[yellow]Invalid threads, value unchanged.[/yellow]")
            continue
        if choice == "5":
            config["wordlist"] = _ask_text("Wordlist path", config["wordlist"], optional=True)
            continue
        if choice == "6":
            config["api_key_virustotal"] = _ask_text("API key VirusTotal", config["api_key_virustotal"], optional=True)
            continue
        if choice == "7":
            config["api_key_shodan"] = _ask_text("API key Shodan", config["api_key_shodan"], optional=True)
            continue
        err_console.print("[red]Invalid selection.[/red] Use 0-7.")

    set_setting("runtime.dns", str(config["dns"]))
    set_setting("runtime.useragent", str(config["useragent"]))
    set_setting("runtime.timeout", str(config["timeout"]))
    set_setting("runtime.threads", None if config["threads"] is None else str(config["threads"]))
    set_setting("runtime.wordlist", config["wordlist"])
    set_setting("apikey.virustotal", config["api_key_virustotal"])
    set_setting("apikey.shodan", config["api_key_shodan"])

    _render_table("Saved Setup")

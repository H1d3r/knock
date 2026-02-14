#!/usr/bin/env python3
"""Compatibility module exposing imports expected by legacy users.

This module re-exports CLI entrypoint and public APIs so external scripts can
`import knockpy.knockpy` without depending on internal file structure.
"""

from .cli import main
from .core import AsyncScanner, Bruteforce, KNOCKPY, Recon, fmt_td
from .output import output, print_scan_status, show_reports_catalog
from .storage import export_report, get_report, list_reports, save_scan
from .version import __version__

__all__ = [
    "__version__",
    "AsyncScanner",
    "Bruteforce",
    "KNOCKPY",
    "Recon",
    "fmt_td",
    "main",
    "output",
    "print_scan_status",
    "show_reports_catalog",
    "save_scan",
    "list_reports",
    "get_report",
    "export_report",
]

#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Top-level executable and import-compatible shim.

Purpose:
- `python knockpy.py ...` command execution
- backward-compatible imports for users that import from repository root
"""

import os
import sys

from knockpy.knockpy import (
    AsyncScanner,
    Bruteforce,
    KNOCKPY,
    Recon,
    __version__,
    export_report,
    fmt_td,
    get_report,
    list_reports,
    main,
    output,
    print_scan_status,
    save_scan,
    show_reports_catalog,
)

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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

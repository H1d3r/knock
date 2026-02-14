from datetime import timedelta
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knockpy.core import fmt_td
from knockpy.output import _merge_check_summary, _security_evidence_map, _status_text, _tls_label


def test_fmt_td_formats_hhmmss():
    assert fmt_td(timedelta(hours=1, minutes=2, seconds=3)) == "01:02:03"


def test_fmt_td_none():
    assert fmt_td(None) == "-"


def test_tls_label_empty():
    assert _tls_label(None) == "-"
    assert _tls_label([]) == "-"


def test_tls_label_values():
    assert _tls_label(["TLS 1.2", "TLS 1.3"]) == "TLS 1.2, TLS 1.3"


def test_status_dns_only():
    assert _status_text([None], [None], [None]) == "dns-only"


def test_status_warning_for_http_without_cert():
    assert _status_text([200], [None], [False]) == "warning"


def test_status_ok():
    assert _status_text([200], [200], [True]) == "ok"


def test_security_evidence_map_compacts_key_details():
    verbose = {
        "tls": {"strict_ok": False, "strict_error": "CERT_FAIL", "protocol": "TLSv1.3", "cipher": "AES256"},
        "security": {
            "mixed_content_count": 2,
            "server_versions_updated_at": "2026-02-11",
            "server_assessment": {
                "banner": "Apache/2.4.49",
                "product_label": "Apache HTTP Server",
                "version": "2.4.49",
                "latest": "2.4.62",
            },
            "methods": {
                "http": {"allow": ["GET", "HEAD"]},
                "https": {"allow": ["GET", "HEAD", "OPTIONS"]},
                "risky_methods": [],
                "inferred_safe": [],
            },
        },
    }
    evidence = _security_evidence_map(verbose)
    assert "mixed_content" in evidence
    assert evidence["mixed_content"][0] == "refs=2"
    assert "server_version" in evidence
    assert any("detected=2.4.49 latest=2.4.62" in part for part in evidence["server_version"])
    assert "methods" in evidence
    assert evidence["methods"][0] == "Supported Methods: GET HEAD OPTIONS"


def test_merge_check_summary_limits_details_by_level():
    evidence_map = {"headers": ["a=1", "b=2", "c=3", "d=4"]}
    warning_item = {"level": "warning", "summary": "Header issues"}
    info_item = {"level": "info", "summary": "Header baseline"}
    assert _merge_check_summary("headers", warning_item, evidence_map) == "Header issues | a=1 | b=2 | c=3"
    assert _merge_check_summary("headers", info_item, evidence_map) == "Header baseline | a=1"


def test_merge_check_summary_methods_keeps_enabled_and_risky():
    evidence_map = {"methods": ["Supported Methods: GET HEAD OPTIONS", "risky=-", "x=ignored"]}
    item = {"level": "ok", "summary": "No risky HTTP methods exposed"}
    assert (
        _merge_check_summary("methods", item, evidence_map)
        == "No risky HTTP methods exposed | Supported Methods: GET HEAD OPTIONS | risky=-"
    )


def test_security_evidence_map_methods_flags_dangerous():
    verbose = {
        "security": {
            "methods": {
                "http": {"allow": ["GET", "TRACE"]},
                "https": {"allow": ["POST", "DELETE"]},
                "risky_methods": ["DELETE", "TRACE"],
                "inferred_safe": [],
            },
        }
    }
    evidence = _security_evidence_map(verbose)
    assert evidence["methods"][0] == "Supported Methods: GET POST DELETE TRACE"
    assert evidence["methods"][1] == "[red]dangerous=DELETE, TRACE[/red]"


def test_security_evidence_map_methods_unknown_without_allow():
    verbose = {
        "security": {
            "methods": {
                "http": {"status": 405, "allow": []},
                "https": {"status": 405, "allow": []},
                "risky_methods": [],
                "inferred_safe": [],
            },
        }
    }
    evidence = _security_evidence_map(verbose)
    assert evidence["methods"][0] == "Supported Methods: unknown (server does not disclose Allow/CORS methods)"
    assert evidence["methods"][1] == "probe_status=http:405 https:405"


def test_security_evidence_map_methods_from_cors_allow():
    verbose = {
        "security": {
            "methods": {
                "http": {"status": 200, "allow": [], "cors_allow": ["GET", "HEAD", "POST", "OPTIONS"]},
                "https": {"status": 200, "allow": [], "cors_allow": []},
                "risky_methods": [],
                "inferred_safe": [],
            },
        }
    }
    evidence = _security_evidence_map(verbose)
    assert evidence["methods"][0] == "Supported Methods: GET HEAD POST OPTIONS"


def test_security_evidence_map_methods_from_inferred_probe():
    verbose = {
        "security": {
            "methods": {
                "http": {"status": 200, "allow": [], "cors_allow": []},
                "https": {"status": 200, "allow": [], "cors_allow": []},
                "risky_methods": [],
                "inferred_safe": ["GET", "HEAD", "POST", "OPTIONS"],
            },
        }
    }
    evidence = _security_evidence_map(verbose)
    assert evidence["methods"][0] == "Supported Methods: GET HEAD POST OPTIONS"

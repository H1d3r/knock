from __future__ import annotations

from pathlib import Path

from knockpy.cli import _load_domains_from_file, _normalize_domain_input, _normalize_domain_list, _should_save_scan


def test_load_domains_from_file_strips_empty_lines(tmp_path: Path):
    source = tmp_path / "domains.txt"
    source.write_text("\nexample.com\n\nwww.test.org\n", encoding="utf-8")
    assert _load_domains_from_file(str(source)) == ["example.com", "www.test.org"]


def test_normalize_domain_input_accepts_url_and_plain_domain():
    assert _normalize_domain_input("https://www.Example.com/path?q=1") == "example.com"
    assert _normalize_domain_input("sub.example.com") == "sub.example.com"
    assert _normalize_domain_input("not a domain") is None


def test_normalize_domain_list_deduplicates_and_filters_invalid():
    values = [
        "https://www.example.com",
        "example.com",
        "sub.example.com",
        "bad domain",
        "",
    ]
    assert _normalize_domain_list(values) == ["example.com", "sub.example.com"]


def test_should_save_scan_only_for_recon_or_bruteforce():
    assert _should_save_scan(recon=False, bruteforce=False) is False
    assert _should_save_scan(recon=True, bruteforce=False) is True
    assert _should_save_scan(recon=False, bruteforce=True) is True

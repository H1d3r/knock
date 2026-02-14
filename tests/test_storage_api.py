from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from knockpy.storage import (
    count_reports,
    delete_report,
    get_report,
    get_setting,
    get_settings,
    init_db,
    list_reports,
    reset_reports,
    save_scan,
    set_setting,
)


def test_storage_scan_lifecycle_roundtrip(tmp_path: Path):
    db_path = tmp_path / "reports.db"
    init_db(db_path)
    assert db_path.exists()

    report_id = save_scan(
        target="example.com",
        mode="domain",
        settings={"timeout": 3.0, "threads": 50},
        results={"domain": "example.com", "ip": ["93.184.216.34"]},
        elapsed=timedelta(seconds=4),
        db_path=db_path,
    )
    assert report_id > 0
    assert count_reports(db_path) == 1

    reports = list_reports(limit=10, db_path=db_path)
    assert len(reports) == 1
    assert reports[0]["id"] == report_id
    assert reports[0]["target"] == "example.com"

    by_latest = get_report("latest", db_path=db_path)
    assert by_latest is not None
    assert by_latest["id"] == report_id
    assert by_latest["target"] == "example.com"
    assert by_latest["mode"] == "domain"
    assert isinstance(by_latest["results"], list)
    assert by_latest["results"][0]["domain"] == "example.com"

    by_id = get_report(str(report_id), db_path=db_path)
    assert by_id is not None
    assert by_id["id"] == report_id

    by_target = get_report("example.com", db_path=db_path)
    assert by_target is not None
    assert by_target["id"] == report_id

    assert delete_report(report_id, db_path=db_path) is True
    assert count_reports(db_path) == 0
    assert delete_report(report_id, db_path=db_path) is False


def test_storage_settings_roundtrip(tmp_path: Path):
    db_path = tmp_path / "reports.db"
    init_db(db_path)

    set_setting("runtime.timeout", "4", db_path=db_path)
    set_setting("runtime.threads", "120", db_path=db_path)
    set_setting("api.shodan", None, db_path=db_path)

    assert get_setting("runtime.timeout", db_path=db_path) == "4"
    assert get_setting("runtime.threads", db_path=db_path) == "120"
    assert get_setting("api.shodan", db_path=db_path) is None
    assert get_setting("missing", db_path=db_path) is None

    all_settings = get_settings(db_path=db_path)
    assert all_settings["runtime.timeout"] == "4"
    assert all_settings["runtime.threads"] == "120"
    assert "api.shodan" in all_settings

    runtime_only = get_settings(prefix="runtime.", db_path=db_path)
    assert sorted(runtime_only.keys()) == ["runtime.threads", "runtime.timeout"]


def test_storage_reset_reports_returns_deleted_count(tmp_path: Path):
    db_path = tmp_path / "reports.db"
    init_db(db_path)
    for idx in range(3):
        save_scan(
            target=f"example-{idx}.com",
            mode="domain",
            settings={},
            results=[],
            elapsed=None,
            db_path=db_path,
        )
    assert count_reports(db_path) == 3
    assert reset_reports(db_path) == 3
    assert count_reports(db_path) == 0

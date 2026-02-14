from __future__ import annotations

import knockpy.version as version


class _DummyResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_version_key_and_compare():
    assert version._version_key("9.0.0") == (9, 0, 0)
    assert version._version_key("9.0.0rc1") == (9, 0, 0, 1)
    assert version.is_newer_version("9.1.0", "9.0.9") is True
    assert version.is_newer_version("9.0.0", "9.0.0") is False
    assert version.is_newer_version("9.0", "9.0.0") is False


def test_check_latest_version_update_available(monkeypatch):
    monkeypatch.setattr(
        version.httpx,
        "get",
        lambda *args, **kwargs: _DummyResponse(200, {"info": {"version": "9.1.0"}}),
    )
    info = version.check_latest_version(current="9.0.0")
    assert info["ok"] is True
    assert info["latest"] == "9.1.0"
    assert info["update_available"] is True


def test_check_latest_version_no_update(monkeypatch):
    monkeypatch.setattr(
        version.httpx,
        "get",
        lambda *args, **kwargs: _DummyResponse(200, {"info": {"version": "9.0.0"}}),
    )
    info = version.check_latest_version(current="9.0.0")
    assert info["ok"] is True
    assert info["update_available"] is False


def test_check_latest_version_handles_http_error(monkeypatch):
    monkeypatch.setattr(
        version.httpx,
        "get",
        lambda *args, **kwargs: _DummyResponse(503, {"info": {"version": "9.1.0"}}),
    )
    info = version.check_latest_version(current="9.0.0")
    assert info["ok"] is False
    assert "HTTP 503" in str(info["error"])


def test_check_latest_version_handles_exception(monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(version.httpx, "get", _boom)
    info = version.check_latest_version(current="9.0.0")
    assert info["ok"] is False
    assert "RuntimeError" in str(info["error"])

from __future__ import annotations

from datetime import timedelta

import knockpy.engine.runtime as runtime


def test_pick_user_agent_respects_explicit_value():
    assert runtime.pick_user_agent("MyAgent/1.0") == "MyAgent/1.0"


def test_pick_user_agent_random_uses_pool(monkeypatch):
    monkeypatch.setattr(runtime.random, "choice", lambda items: items[0])
    assert runtime.pick_user_agent("random") == runtime.USER_AGENTS[0]
    assert runtime.pick_user_agent(None) == runtime.USER_AGENTS[0]


def test_www_fallback_domain_only_when_needed():
    assert runtime._www_fallback_domain("example.com") == "www.example.com"
    assert runtime._www_fallback_domain("www.example.com") is None
    assert runtime._www_fallback_domain("not a domain") is None


def test_fmt_td_expected_format():
    assert runtime.fmt_td(timedelta(hours=2, minutes=3, seconds=4)) == "02:03:04"
    assert runtime.fmt_td(None) == "-"

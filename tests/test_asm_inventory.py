"""Tests for the Continuous ASM endpoint inventory pure helpers (docs §16)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory as a  # noqa: E402


def test_normalize_path_templates_volatile_ids():
    assert a.normalize_path("/users/42") == "/users/{id}"
    assert a.normalize_path("/u/550e8400-e29b-41d4-a716-446655440000/x") == "/u/{uuid}/x"
    assert a.normalize_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"
    assert a.normalize_path("/rest/products/search") == "/rest/products/search"


def test_parse_worklist_entry_shapes():
    assert a.parse_worklist_entry("GET /rest/products/1?q=x&id=2") == ("GET", "/rest/products/1", "id,q")
    assert a.parse_worklist_entry("POST /login form:email=1&password=1") == ("POST", "/login", "email,password")
    assert a.parse_worklist_entry('POST /api json:{"a":1,"b":2}') == ("POST", "/api", "a,b")
    assert a.parse_worklist_entry("/ftp") == ("GET", "/ftp", "")
    assert a.parse_worklist_entry("GET rel/path") == ("GET", "/rel/path", "")
    assert a.parse_worklist_entry("") is None
    assert a.parse_worklist_entry(None) is None


def test_fingerprint_collapses_volatile_ids():
    f1 = a.endpoint_fingerprint("GET", "/users/42", "id")
    f2 = a.endpoint_fingerprint("GET", "/users/43", "id")
    assert f1 == f2  # same logical endpoint
    # method, path, and param set all matter
    assert a.endpoint_fingerprint("POST", "/users/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/orders/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id,extra") != f1


def test_priority_score_ranks_high_value_and_params():
    admin = a.priority_score("POST", "/admin/login", "user,pass")
    static = a.priority_score("GET", "/assets/style.css", "")
    api_param = a.priority_score("GET", "/api/items", "id")
    assert admin > api_param > static
    assert admin == 10 + 20 + 15 + 5  # high-value + param + write method


def test_to_custom_endpoint_roundtrips_params():
    assert a.to_custom_endpoint("POST", "/login", "email,password") == "POST /login?email=1&password=1"
    assert a.to_custom_endpoint("GET", "/ftp", "") == "GET /ftp"


def test_normalize_worklist_dedupes_by_fingerprint():
    wl = ["GET /a/1?x=1", "GET /a/2?x=1", "GET /b", "GET /b", 123, None]
    out = a.normalize_worklist(wl)
    # /a/1 and /a/2 collapse (same fingerprint); /b dedupes; non-strings dropped
    assert out == [("GET", "/a/1", "x"), ("GET", "/b", "")]


def test_normalize_worklist_respects_limit():
    wl = [f"GET /e{i}?x=1" for i in range(100)]
    assert len(a.normalize_worklist(wl, limit=10)) == 10


# ---- Continuous dispatcher policy (Phase 3/4) -----------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402


def _utc(y=2026, mo=6, d=15, h=12, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc)


def test_merge_asm_config_defaults_and_clamping():
    cfg = a.merge_asm_config(None)
    assert cfg["batch_size"] == a.DEFAULT_ASM_CONFIG["batch_size"]
    # clamps out-of-range and ignores junk, keeps valid overrides
    cfg = a.merge_asm_config({"batch_size": 99999, "stale_days": -5, "exploit_depth": 1, "bogus": "x"})
    assert cfg["batch_size"] == 1000          # clamped to max
    assert cfg["stale_days"] == 0             # clamped to min
    assert cfg["exploit_depth"] is True
    assert "bogus" not in cfg


def test_merge_asm_config_window_days():
    cfg = a.merge_asm_config({"window_days": [0, 1, 7, "x", 4]})
    assert cfg["window_days"] == [0, 1, 4]    # dedup, drop invalid (7, "x")
    assert a.merge_asm_config({"window_days": []})["window_days"] is None


def test_within_window():
    # no window config -> always allowed
    assert a.within_window(_utc(h=3), {}) is True
    # 2:00-6:00 window
    win = {"window_start_hour": 2, "window_end_hour": 6}
    assert a.within_window(_utc(h=3), win) is True
    assert a.within_window(_utc(h=7), win) is False
    # wraps midnight 22:00-04:00
    wrap = {"window_start_hour": 22, "window_end_hour": 4}
    assert a.within_window(_utc(h=23), wrap) is True
    assert a.within_window(_utc(h=2), wrap) is True
    assert a.within_window(_utc(h=12), wrap) is False
    # 2026-06-15 is a Monday (weekday 0); restrict to Tue/Wed
    assert a.within_window(_utc(), {"window_days": [1, 2]}) is False
    assert a.within_window(_utc(), {"window_days": [0]}) is True


def test_decide_action_recon_when_due():
    d = a.decide_asm_action(
        now=_utc(), last_test_at=None, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 168},
    )
    assert d["action"] == "recon"


def test_decide_action_test_when_recon_not_due():
    d = a.decide_asm_action(
        now=_utc(), last_test_at=None,
        last_recon_at=_utc() - timedelta(hours=1),  # recent recon
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 168},
    )
    assert d["action"] == "test"


def test_decide_action_skips():
    base = dict(now=_utc(), last_test_at=None, last_recon_at=_utc(),
                has_active_scan=False, claimable=100, tested_today=0,
                config={"recon_interval_hours": 0})  # recon off -> consider test
    # active scan blocks everything
    assert a.decide_asm_action(**{**base, "has_active_scan": True})["action"] == "none"
    # nothing claimable
    assert a.decide_asm_action(**{**base, "claimable": 0})["action"] == "none"
    # within min interval
    assert a.decide_asm_action(**{**base, "last_test_at": _utc() - timedelta(minutes=5),
                                  "config": {"recon_interval_hours": 0, "min_interval_minutes": 60}})["action"] == "none"
    # daily cap reached
    assert a.decide_asm_action(**{**base, "tested_today": 5000,
                                  "config": {"recon_interval_hours": 0, "daily_endpoint_cap": 2000}})["action"] == "none"
    # per-domain rate limit
    assert a.decide_asm_action(**{**base, "domain_rate_exceeded": True})["action"] == "none"
    # outside time window
    assert a.decide_asm_action(**{**base, "config": {"recon_interval_hours": 0,
                                  "window_start_hour": 2, "window_end_hour": 6}})["action"] == "none"

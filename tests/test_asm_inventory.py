"""Tests for the Continuous ASM endpoint inventory pure helpers (docs §16)."""

import os
import sys
import asyncio
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory as a  # noqa: E402


class _FakeRedis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def eval(self, _script, _numkeys, key, amount, cap, _ttl, all_or_nothing="0"):
        current = int(self.values.get(key) or 0)
        amount = int(amount)
        cap = int(cap)
        if amount <= 0:
            return 0
        if cap <= 0:
            return 0
        if current >= cap:
            return 0
        if str(all_or_nothing) == "1" and current + amount > cap:
            return 0
        granted = min(amount, cap - current)
        self.values[key] = current + granted
        return granted


def test_domain_rate_reservation_zero_remaining_cap_denies():
    redis = _FakeRedis()

    assert a.reserve_domain_rate(redis, "example.test", 0, 1) == 0
    assert a.reserved_domain_rate_count(redis, "example.test") == 0


def test_normalize_path_templates_volatile_ids():
    assert a.normalize_path("/users/42") == "/users/{id}"
    assert a.normalize_path("/u/550e8400-e29b-41d4-a716-446655440000/x") == "/u/{uuid}/x"
    assert a.normalize_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"
    assert a.normalize_path("/rest/products/search") == "/rest/products/search"


def test_parse_worklist_entry_shapes():
    assert a.parse_worklist_entry("GET /rest/products/1?q=x&id=2") == ("GET", "/rest/products/1", "id,q")
    assert a.parse_worklist_entry("POST /login form:email=1&password=1") == ("POST", "/login", "email,password")
    assert a.parse_worklist_entry('POST /api json:{"a":1,"b":2}') == ("POST", "/api", "a,b")
    assert a.parse_worklist_entry('POST /api json:{"user":{"id":1},"qty":2}') == ("POST", "/api", "qty,user.id")
    assert a.parse_worklist_entry("/ftp") == ("GET", "/ftp", "")
    assert a.parse_worklist_entry("GET rel/path") == ("GET", "/rel/path", "")
    assert a.parse_worklist_entry("") is None
    assert a.parse_worklist_entry(None) is None


def test_parse_worklist_entry_detail_preserves_replay_context():
    form = a.parse_worklist_entry_detail("POST /login form:email=1&password=1")
    assert form is not None
    assert form.param_location == "form"
    assert form.content_type == "application/x-www-form-urlencoded"
    assert form.replay_spec == "POST /login form:email=1&password=1"

    json_body = a.parse_worklist_entry_detail('POST /api json:{"a":1,"b":2}')
    assert json_body is not None
    assert json_body.param_location == "json"
    assert json_body.content_type == "application/json"
    assert json_body.replay_spec == 'POST /api json:{"a":1,"b":2}'

    query = a.parse_worklist_entry_detail("GET rel/path?x=seed")
    assert query is not None
    assert query.replay_spec == "GET /rel/path?x=seed"


def test_fingerprint_collapses_volatile_ids():
    f1 = a.endpoint_fingerprint("GET", "/users/42", "id")
    f2 = a.endpoint_fingerprint("GET", "/users/43", "id")
    assert f1 == f2  # same logical endpoint
    # method, path, and param set all matter
    assert a.endpoint_fingerprint("POST", "/users/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/orders/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id,extra") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id", auth_state="user1") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id", param_location="form") != f1


def test_auth_state_from_options_prefers_explicit_and_primary_auth():
    assert a.auth_state_from_options({}) == "anonymous"
    assert a.auth_state_from_options({"auth_header": "Bearer x"}) == "user1"
    assert a.auth_state_from_options({"auth_state": "user2", "auth_header": "Bearer x"}) == "user2"
    assert a.auth_state_from_options({"auth_state": "invalid"}) == "anonymous"


def test_priority_score_ranks_high_value_and_params():
    admin = a.priority_score("POST", "/admin/login", "user,pass")
    static = a.priority_score("GET", "/assets/style.css", "")
    api_param = a.priority_score("GET", "/api/items", "id")
    assert admin > api_param > static
    assert admin == 10 + 20 + 15 + 5  # high-value + param + write method


def test_to_custom_endpoint_roundtrips_params():
    assert a.to_custom_endpoint("POST", "/login", "email,password") == "POST /login?email=1&password=1"
    assert (
        a.to_custom_endpoint("POST", "/login", "email,password", param_location="form")
        == "POST /login form:email=1&password=1"
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "a,b", param_location="json")
        == 'POST /api json:{"a":1,"b":1}'
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "qty,user.id", param_location="json")
        == 'POST /api json:{"qty":1,"user":{"id":1}}'
    )
    assert (
        a.to_custom_endpoint("POST", "/api", "a,b", replay_spec='POST /api json:{"a":"seed","b":2}')
        == 'POST /api json:{"a":"seed","b":2}'
    )
    assert a.to_custom_endpoint("GET", "/ftp", "") == "GET /ftp"


def test_normalize_worklist_dedupes_by_fingerprint():
    wl = ["GET /a/1?x=1", "GET /a/2?x=1", "GET /b", "GET /b", 123, None]
    out = a.normalize_worklist(wl)
    # /a/1 and /a/2 collapse (same fingerprint); /b dedupes; non-strings dropped
    assert out == [("GET", "/a/1", "x"), ("GET", "/b", "")]


def test_normalize_worklist_respects_limit():
    wl = [f"GET /e{i}?x=1" for i in range(100)]
    assert len(a.normalize_worklist(wl, limit=10)) == 10


class _CoverageConn:
    def __init__(self, status_row, attempt_rows):
        self.rows = [status_row]
        self.attempt_rows = attempt_rows
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append((query, args))
        return self.rows.pop(0)

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self.attempt_rows


def test_coverage_summary_defaults_to_endpoint_status_without_attempts():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 4,
            "tested": 1,
            "untested": 2,
            "in_progress": 0,
            "stale": 1,
            "gone": 0,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 1,
        },
        [],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "endpoint_status"
    assert summary["tested"] == 1
    assert summary["coverage"] == 0.25
    assert summary["status_coverage"]["tested"] == 1
    assert summary["attempt_coverage"]["attempted"] == 0


def test_coverage_summary_uses_latest_attempt_ledger_when_present():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 5,
            "tested": 1,
            "untested": 4,
            "in_progress": 0,
            "stale": 0,
            "gone": 1,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 0,
        },
        [
            {"status": "completed", "scanner_telemetry_json": {"per_endpoint_telemetry": True}},
            {"status": "completed", "scanner_telemetry_json": {"per_endpoint_telemetry": True}},
            {"status": "partial", "scanner_telemetry_json": {"per_endpoint_telemetry": False}},
        ],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "attempt_ledger"
    assert summary["total"] == 5
    assert summary["tested"] == 2
    assert summary["untested"] == 1  # one non-gone endpoint has no attempt
    assert summary["partial"] == 1
    assert summary["coverage"] == 0.5  # completed / non-gone endpoints
    assert summary["status_coverage"]["coverage"] == 0.25
    assert summary["attempt_coverage"] == {
        "total": 4,
        "attempted": 3,
        "completed": 2,
        "tested": 2,
        "untested": 1,
        "partial": 1,
        "auth_blocked": 0,
        "rate_limited": 0,
        "error": 0,
        "coverage": 0.5,
        "basis": "latest_attempt_per_endpoint",
    }


def test_coverage_summary_treats_completed_without_endpoint_telemetry_as_partial():
    target_id = uuid.uuid4()
    conn = _CoverageConn(
        {
            "total": 1,
            "tested": 1,
            "untested": 0,
            "in_progress": 0,
            "stale": 0,
            "gone": 0,
            "expired_leases": 0,
            "auth_blocked": 0,
            "partial": 0,
        },
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
            }
        ],
    )

    summary = asyncio.run(a.coverage_summary(conn, str(target_id)))

    assert summary["coverage_basis"] == "attempt_ledger"
    assert summary["tested"] == 0
    assert summary["partial"] == 1
    assert summary["coverage"] == 0.0
    assert summary["attempt_coverage"]["completed"] == 0
    assert summary["attempt_coverage"]["partial"] == 1
    assert summary["status_coverage"]["tested"] == 1


class _CampaignAttemptConn:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self.rows


def test_campaign_attempt_summary_uses_expected_denominator_and_telemetry_guard():
    campaign_id = uuid.uuid4()
    conn = _CampaignAttemptConn(
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True},
                "attempted_params_count": 3,
                "completed_params_count": 3,
            },
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True},
                "attempted_params_count": 2,
                "completed_params_count": 2,
            },
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
            {
                "status": "auth_missing",
                "scanner_telemetry_json": {"per_endpoint_telemetry": False},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
        ]
    )

    summary = asyncio.run(a.campaign_attempt_summary(conn, str(campaign_id), expected_total=6))

    assert summary == {
        "total": 6,
        "attempted": 4,
        "completed": 2,
        "tested": 2,
        "untested": 2,
        "partial": 1,
        "auth_blocked": 1,
        "rate_limited": 0,
        "error": 0,
        "attempted_params": 7,
        "completed_params": 5,
        "coverage": 0.333,
        "basis": "campaign_attempt_ledger",
        "coverage_denominator": "assigned_auth_scoped_endpoints",
    }
    assert conn.queries[0][1] == (campaign_id, None)


def test_campaign_attempt_summary_can_count_endpoint_family_attempts():
    campaign_id = uuid.uuid4()
    conn = _CampaignAttemptConn(
        [
            {
                "status": "completed",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True},
                "attempted_params_count": 1,
                "completed_params_count": 1,
            },
            {
                "status": "partial",
                "scanner_telemetry_json": {"per_endpoint_telemetry": True},
                "attempted_params_count": 1,
                "completed_params_count": 0,
            },
        ]
    )

    summary = asyncio.run(
        a.campaign_attempt_summary(
            conn,
            str(campaign_id),
            expected_total=6,
            check_families=["all", "sqli", "xss"],
            family_aware=True,
        )
    )

    assert summary["basis"] == "campaign_family_attempt_ledger"
    assert summary["coverage_denominator"] == "assigned_endpoint_family_attempts"
    assert summary["total"] == 6
    assert summary["attempted"] == 2
    assert summary["completed"] == 1
    assert summary["partial"] == 1
    query, args = conn.queries[0]
    assert "DISTINCT ON (aea.endpoint_id, COALESCE(aea.check_family, 'all'))" in query
    assert args == (campaign_id, ["all", "sqli", "xss"])


# ---- Allocator helpers -----------------------------------------------------

class _AsyncTx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _ClaimConn:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []
        self.fetchrow_calls = []
        self.fetch_calls = []

    def transaction(self):
        return _AsyncTx()

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "UPDATE 0" if "lease_expired" in query else f"UPDATE {len(self.rows)}"

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        return {"auth_state": "anonymous"} if self.rows else None

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return self.rows


def test_claim_test_batch_sets_durable_lease_fields():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    conn = _ClaimConn([
        {
            "id": endpoint_id,
            "method": "GET",
            "path": "/api/orders",
            "param_shape": "id",
            "auth_state": "anonymous",
            "param_location": "query",
            "replay_spec": "GET /api/orders?id=1",
            "content_type": None,
            "campaign_id": None,
            "lease_owner": None,
            "lease_expires_at": None,
            "attempt_count": 0,
        }
    ])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            limit=10,
            stale_days=7,
            lease_owner="worker-a:job",
            lease_ttl_seconds=120,
            campaign_id=str(campaign_id),
        )
    )

    assert claimed[0]["id"] == endpoint_id
    update_query, update_args = conn.executed[-1]
    assert "lease_owner = $2" in update_query
    assert "lease_expires_at = NOW() + ($3 || ' seconds')::interval" in update_query
    assert "attempt_count = COALESCE(attempt_count, 0) + 1" in update_query
    assert update_args[1] == "worker-a:job"
    assert update_args[2] == "120"
    assert update_args[3] == campaign_id


def test_claim_test_batch_can_scope_to_campaign_inventory():
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    conn = _ClaimConn([])

    asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_id=str(campaign_id),
            campaign_only=True,
            check_family="sqli",
        )
    )

    first_query, first_args = conn.fetchrow_calls[0]
    assert "NOT EXISTS" in first_query
    assert "COALESCE(aea.check_family, 'all') = $3" in first_query
    assert first_args[1] == campaign_id
    assert first_args[2] == "sqli"
    assert "completed" in first_args[3]


def test_claim_test_batch_campaign_only_without_campaign_fails_closed():
    target_id = uuid.uuid4()
    conn = _ClaimConn([{"id": uuid.uuid4(), "auth_state": "anonymous"}])

    claimed = asyncio.run(
        a.claim_test_batch(
            conn,
            str(target_id),
            campaign_only=True,
        )
    )

    assert claimed == []
    assert conn.fetchrow_calls == []
    assert conn.fetch_calls == []


class _RecordAttemptConn:
    def __init__(self, endpoint_id):
        self.endpoint_id = endpoint_id
        self.executemany_calls = []
        self.executed = []

    async def fetch(self, query, *args):
        return [{
            "id": self.endpoint_id,
            "param_shape": "id,sort",
            "auth_state": "user1",
            "campaign_id": None,
        }]

    async def executemany(self, query, records):
        self.executemany_calls.append((query, list(records)))

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "DELETE 1"


def test_record_endpoint_attempts_defaults_completed_param_counts():
    endpoint_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    written = asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            scan_id=str(scan_id),
            worker_id="worker-a",
            status="completed",
            scanner_telemetry_json={"per_endpoint_telemetry": True},
        )
    )

    assert written == 1
    query, records = conn.executemany_calls[0]
    assert "INSERT INTO asm_endpoint_attempts" in query
    record = records[0]
    assert record[0] == endpoint_id
    assert record[1] == scan_id
    assert record[5] == "user1"
    assert record[6] == "all"
    assert record[9] == "completed"
    assert record[10] == 2
    assert record[11] == 2


def test_record_endpoint_attempts_allows_conservative_partial_counts():
    endpoint_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            status="timeout",
            attempted_params_count=0,
            completed_params_count=0,
            error_summary="partial_timeout",
        )
    )

    record = conn.executemany_calls[0][1][0]
    assert record[6] == "all"
    assert record[9] == "timeout"
    assert record[10] == 0
    assert record[11] == 0
    assert record[13] == "partial_timeout"


def test_record_endpoint_attempts_can_replace_existing_for_idempotent_merge():
    endpoint_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    parent_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    conn = _RecordAttemptConn(endpoint_id)

    asyncio.run(
        a.record_endpoint_attempts(
            conn,
            [endpoint_id],
            scan_id=str(scan_id),
            parent_scan_id=str(parent_id),
            campaign_id=str(campaign_id),
            check_family="xss",
            status="completed",
            replace_existing=True,
        )
    )

    assert conn.executed
    query, args = conn.executed[0]
    assert "DELETE FROM asm_endpoint_attempts" in query
    assert "COALESCE(check_family, 'all') = $5" in query
    assert args == ([endpoint_id], scan_id, parent_id, campaign_id, "xss")


class _EndpointIdsConn:
    def __init__(self, target_id, rows):
        self.target_id = target_id
        self.rows = rows
        self.fetch_args = None

    async def fetch(self, query, *args):
        self.fetch_args = args
        return self.rows


def test_endpoint_ids_for_worklist_resolves_existing_inventory_rows_in_input_order():
    target_id = uuid.uuid4()
    first_id = uuid.uuid4()
    second_id = uuid.uuid4()
    first_fp = a.endpoint_fingerprint("GET", "/a", "x", auth_state="user1")
    second_fp = a.endpoint_fingerprint(
        "POST",
        "/b",
        "name",
        param_location="form",
        auth_state="user1",
    )
    conn = _EndpointIdsConn(
        target_id,
        [
            {"id": second_id, "fingerprint": second_fp},
            {"id": first_id, "fingerprint": first_fp},
        ],
    )

    ids = asyncio.run(
        a.endpoint_ids_for_worklist(
            conn,
            str(target_id),
            ["GET /a?x=1", "POST /b form:name=alice"],
            auth_state="user1",
        )
    )

    assert ids == [first_id, second_id]
    assert conn.fetch_args[0] == target_id
    assert conn.fetch_args[1] == [first_fp, second_fp]


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


def test_decide_action_handles_mixed_datetime_awareness():
    # Regression: the dispatcher passes a NAIVE now (utc_now()) but last_test_at
    # comes from a TIMESTAMPTZ column (tz-aware). Subtracting the two must not
    # raise "can't subtract offset-naive and offset-aware".
    naive_now = datetime(2026, 6, 16, 13, 0)  # naive
    aware_recent = datetime(2026, 6, 16, 12, 55, tzinfo=timezone.utc)  # aware, 5 min ago
    d = a.decide_asm_action(
        now=naive_now, last_test_at=aware_recent, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 0, "min_interval_minutes": 60},
    )
    assert d["action"] == "none"  # within min interval (5 < 60), no crash
    # naive now + aware OLD last_test_at -> test fires
    aware_old = datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc)  # 3h ago
    d2 = a.decide_asm_action(
        now=naive_now, last_test_at=aware_old, last_recon_at=None,
        has_active_scan=False, claimable=100, tested_today=0,
        config={"recon_interval_hours": 0, "min_interval_minutes": 60},
    )
    assert d2["action"] == "test"


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

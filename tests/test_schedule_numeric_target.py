import asyncio
from datetime import datetime, timezone
import uuid

import pytest

import schedules.router as schedules_router
from schedules.router import (
    _parse_time_of_day,
    _resolve_asm_schedule_options,
    _resolve_normal_schedule_options,
    calculate_next_run,
    handle_schedule_target_failure,
    ScheduleUpdate,
    ScheduleTargetResolutionError,
    ScheduleTargetSafetyError,
    validate_schedule_target_destination,
)


def _records(*addresses: str):
    return [(None, None, None, None, (address, 443)) for address in addresses]


def test_schedule_rejects_ambiguous_integer_host_after_resolution():
    async def resolver(_host, _port):
        return _records("169.254.169.254")

    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(
            "http://2852039166/", resolver=resolver,
        ))


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/",
    "http://[::ffff:169.254.169.254]/",
    "http://127.0.0.1/",
])
def test_schedule_rejects_visible_non_public_addresses(url):
    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(url))


def test_schedule_accepts_only_fully_public_resolution():
    async def resolver(_host, _port):
        return _records(
            "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
        )

    assert asyncio.run(validate_schedule_target_destination(
        "https://example.test/", resolver=resolver,
    )) == ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")


def test_schedule_rejects_mixed_public_and_private_dns_answers():
    async def resolver(_host, _port):
        return _records("93.184.216.34", "10.0.0.2")

    with pytest.raises(ScheduleTargetSafetyError, match="must not resolve"):
        asyncio.run(validate_schedule_target_destination(
            "https://example.test/", resolver=resolver,
        ))


def test_schedule_distinguishes_retryable_dns_failure_from_unsafe_destination():
    async def resolver(_host, _port):
        raise OSError("temporary resolver failure")

    with pytest.raises(ScheduleTargetResolutionError) as exc:
        asyncio.run(validate_schedule_target_destination(
            "https://example.test/", resolver=resolver,
        ))

    assert exc.value.retryable is True
    assert ScheduleTargetSafetyError("unsafe").retryable is False


@pytest.mark.parametrize("value", ["2:00", "02:0", "02:00:00", "24:00", "00:60"])
def test_schedule_time_parser_requires_exact_valid_hhmm(value):
    with pytest.raises(ValueError, match="HH:MM"):
        _parse_time_of_day(value)


def test_schedule_jitter_never_moves_next_run_into_the_past(monkeypatch):
    now = datetime(2026, 9, 1, 2, 10)
    monkeypatch.setattr(schedules_router, "utc_now", lambda: now)
    monkeypatch.setattr(schedules_router.random, "randint", lambda _low, _high: -30)

    next_run = calculate_next_run("daily", None, "02:20", "UTC", 30)

    assert next_run > now


@pytest.mark.parametrize("options", [
    {"policy": {"active_testing": True}, "approval_receipt_id": str(uuid.uuid4())},
    {"credential_profile_ids": [str(uuid.uuid4())]},
    {"request_collections": [{"id": str(uuid.uuid4())}]},
    {"ai_api_key": "secret"},
    {"unknown_option": True},
])
def test_recurring_normal_scan_rejects_authority_it_cannot_revalidate(options):
    with pytest.raises(ValueError):
        _resolve_normal_schedule_options(options)


def test_recurring_normal_scan_accepts_validated_passive_options():
    contract, options = _resolve_normal_schedule_options({
        "budget_profile": "fast",
        "policy": {"active_testing": False},
        "placement": {"node_scope": "local"},
    })

    assert contract.policy.active_testing is False
    assert options.budget_profile == "fast"
    assert options.placement == {"node_scope": "local"}


@pytest.mark.parametrize("options", [
    {},
    {"approval_receipt_id": "not-a-uuid"},
    {"batch_size": 0, "approval_receipt_id": str(uuid.uuid4())},
    {"batch_size": True, "approval_receipt_id": str(uuid.uuid4())},
    {"stale_days": 3651, "approval_receipt_id": str(uuid.uuid4())},
    {"exploit_depth": "true", "approval_receipt_id": str(uuid.uuid4())},
    {"check_family": "not-a-family", "approval_receipt_id": str(uuid.uuid4())},
    {"check_family": "auth", "approval_receipt_id": str(uuid.uuid4())},
    {"check_family": "bola", "approval_receipt_id": str(uuid.uuid4())},
    {"endpoint_filter": "everything", "approval_receipt_id": str(uuid.uuid4())},
])
def test_scheduled_asm_rejects_unbounded_or_unknown_options(options):
    with pytest.raises(ValueError):
        _resolve_asm_schedule_options(options)


def test_scheduled_asm_normalizes_supported_options():
    approval_receipt_id = str(uuid.uuid4())
    assert _resolve_asm_schedule_options({
        "batch_size": 25,
        "stale_days": 7,
        "exploit_depth": True,
        "check_family": "xss",
        "endpoint_filter": "api-only",
        "approval_receipt_id": approval_receipt_id,
    }) == {
        "batch_size": 25,
        "stale_days": 7,
        "exploit_depth": True,
        "check_family": "xss",
        "endpoint_filter": "api",
        "approval_receipt_id": approval_receipt_id,
    }


def test_schedule_pause_bypasses_target_resolution_and_clears_next_run(monkeypatch):
    schedule_id = uuid.uuid4()
    existing = {
        "id": schedule_id,
        "target_url": "https://temporarily-unresolvable.example.test",
        "schedule_kind": "normal_scan",
        "scan_options": {"budget_profile": "fast"},
        "frequency": "daily",
        "day_of_week": None,
        "time_of_day": "02:00",
        "timezone": "UTC",
        "jitter_minutes": 0,
    }

    class Connection:
        def __init__(self):
            self.update = None

        async def fetchrow(self, _query, *_args):
            return existing

        async def fetchval(self, query, *args):
            self.update = (query, args)
            return schedule_id

    connection = Connection()

    class Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return None

    class Pool:
        @staticmethod
        def acquire():
            return Acquire()

    async def should_not_resolve(_url):
        raise AssertionError("pausing must not depend on DNS")

    monkeypatch.setattr(schedules_router, "_pool_provider", lambda: Pool())
    monkeypatch.setattr(
        schedules_router, "validate_schedule_target_destination", should_not_resolve,
    )

    result = asyncio.run(schedules_router.update_schedule(
        str(schedule_id), ScheduleUpdate(is_active=False),
    ))

    assert result["status"] == "updated"
    assert "is_active = $1" in connection.update[0]
    assert "next_run_at = NULL" in connection.update[0]


def test_daily_schedule_cannot_transition_to_weekly_without_a_day(monkeypatch):
    schedule_id = uuid.uuid4()
    existing = {
        "id": schedule_id,
        "target_url": "https://example.test",
        "schedule_kind": "normal_scan",
        "scan_options": {"budget_profile": "fast"},
        "frequency": "daily",
        "day_of_week": None,
        "time_of_day": "02:00",
        "timezone": "UTC",
        "jitter_minutes": 0,
    }

    class Connection:
        async def fetchrow(self, _query, *_args):
            return existing

    class Acquire:
        async def __aenter__(self):
            return Connection()

        async def __aexit__(self, *_args):
            return None

    class Pool:
        @staticmethod
        def acquire():
            return Acquire()

    async def safe(_url):
        return ("93.184.216.34",)

    monkeypatch.setattr(schedules_router, "_pool_provider", lambda: Pool())
    monkeypatch.setattr(schedules_router, "validate_schedule_target_destination", safe)

    with pytest.raises(schedules_router.HTTPException) as exc:
        asyncio.run(schedules_router.update_schedule(
            str(schedule_id), ScheduleUpdate(frequency="weekly"),
        ))

    assert exc.value.status_code == 400
    assert "day_of_week is required" in str(exc.value.detail)


def test_transient_dns_retry_does_not_reactivate_a_concurrently_paused_schedule():
    state = {"is_active": False, "next_run_at": None}

    class Connection:
        async def execute(self, query, *args):
            if "AND is_active=true" in query:
                if state["is_active"]:
                    state["next_run_at"] = args[0]
                return "UPDATE 0"
            # Model the former unconditional retry update so this behavioral
            # test fails if it is ever reintroduced.
            if "is_active=($1::timestamptz IS NOT NULL)" in query:
                state["is_active"] = args[0] is not None
                state["next_run_at"] = args[0]
                return "UPDATE 1"
            raise AssertionError(query)

    class Acquire:
        async def __aenter__(self):
            return Connection()

        async def __aexit__(self, *_args):
            return None

    class Pool:
        @staticmethod
        def acquire():
            return Acquire()

    asyncio.run(handle_schedule_target_failure(
        Pool(),
        schedule_id="schedule-1",
        error=ScheduleTargetResolutionError("temporary DNS outage"),
        now=datetime(2026, 9, 1, tzinfo=timezone.utc),
    ))

    assert state == {"is_active": False, "next_run_at": None}

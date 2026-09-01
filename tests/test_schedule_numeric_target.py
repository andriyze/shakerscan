import asyncio
from datetime import datetime, timezone

import pytest

from schedules.router import (
    handle_schedule_target_failure,
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

"""Gateway transport fixtures, not live scheduled execution acceptance."""

import asyncio

import httpx
import pytest
from schedules.managed_dispatch import ManagedScheduleDispatcher, occurrence_key

SCHEDULE = "11111111-1111-4111-8111-111111111111"
OCCURRENCE = "22222222-2222-4222-8222-222222222222"
SCAN = "33333333-3333-4333-8333-333333333333"


def test_retry_keeps_identity_and_never_follows_redirects():
    seen = []

    def gateway(request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(307, headers={"location": "https://other.test/scans"})
        return httpx.Response(200, json={"scan_id": SCAN, "status": "queued"})

    dispatcher = ManagedScheduleDispatcher(
        "https://tenant.test", "fixture-only", transport=httpx.MockTransport(gateway)
    )
    first = asyncio.run(dispatcher.dispatch(SCHEDULE, OCCURRENCE, {}))
    second = asyncio.run(dispatcher.dispatch(SCHEDULE, OCCURRENCE, {}))
    assert first.state == "retry"
    assert second.scan_id == SCAN
    assert len(seen) == 2
    assert {str(r.url) for r in seen} == {"https://tenant.test/scans"}
    assert {r.headers["idempotency-key"] for r in seen} == {
        occurrence_key(SCHEDULE, OCCURRENCE)
    }


@pytest.mark.parametrize("status", [401, 403, 409, 422, 429, 500, 503])
def test_denial_or_uncertainty_never_becomes_success(status):
    dispatcher = ManagedScheduleDispatcher(
        "https://tenant.test",
        "fixture-only",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, text="secret fixture")
        ),
    )
    outcome = asyncio.run(dispatcher.dispatch(SCHEDULE, OCCURRENCE, {}))
    assert outcome.state == ("denied" if status in {401, 403, 422} else "retry")
    assert outcome.scan_id is None
    assert "secret" not in repr(outcome)


@pytest.mark.parametrize(
    "origin",
    [
        "http://tenant.test",
        "https://user:secret@tenant.test",
        "https://tenant.test/path",
        "https://tenant.test?token=x",
    ],
)
def test_refuses_unsafe_origin(origin):
    with pytest.raises(ValueError):
        ManagedScheduleDispatcher(origin, "fixture-only")


@pytest.mark.parametrize("status,body,expected", [
    (200, {"schema_version": "schedule-admission/v1", "state": "accepted", "scan_id": SCAN}, "accepted"),
    (200, {"schema_version": "schedule-admission/v1", "state": "denied"}, "denied"),
    (200, {"schema_version": "schedule-admission/v1", "state": "unknown"}, "retry"),
    (200, {"schema_version": "schedule-admission/v1", "state": "accepted", "scan_id": "invalid"}, "retry"),
    (200, {"state": "denied"}, "retry"),
    (404, {}, "retry"), (401, {}, "retry"), (403, {}, "retry"),
    (503, {}, "retry"), (307, {}, "retry"),
])
def test_lookup_never_posts_or_treats_missing_receipt_as_denial(status, body, expected):
    seen = []

    def gateway(request):
        seen.append(request)
        return httpx.Response(status, json=body, headers={"location": "https://other.test"})

    dispatcher = ManagedScheduleDispatcher(
        "https://tenant.test", "fixture-only", transport=httpx.MockTransport(gateway)
    )
    result = asyncio.run(dispatcher.lookup(SCHEDULE, OCCURRENCE))
    assert result.state == expected
    assert len(seen) == 1 and seen[0].method == "GET"
    assert str(seen[0].url) == (
        "https://tenant.test/_hosted/schedule-dispatches/" + occurrence_key(SCHEDULE, OCCURRENCE)
    )

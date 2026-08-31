import asyncio
from datetime import datetime, timezone

import pytest

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.models import TargetBinding
from api.runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from api.runtime.request_replay_executor import (
    ReplayTransportResult,
    execute_replay_plan,
    replay_reservation_budget,
)
from scanner.scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


class _SuccessTransport:
    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        return ReplayTransportResult(
            status_code=200,
            connected_address=target.allowed_addresses[0],
            attempted_addresses=(target.allowed_addresses[0],),
            final_url=request.url,
            response_headers={"Content-Type": "text/plain"},
            response_body=b"ok",
            elapsed_ms=1,
        )


def _plan(url: str = "https://example.test/private?token=secret"):
    return build_replay_plan(
        [{
            "id": "request-1",
            "method": "GET",
            "url": url,
            "headers": {"Authorization": "Bearer worker-only"},
            "body": b"",
        }],
        allowed_origins=["https://example.test"],
        default_origin="https://example.test",
    )


def test_executor_resumes_owner_held_reservation_and_settles_all_dimensions():
    async def drive():
        plan = _plan()
        requested_budget = replay_reservation_budget(
            plan, {"agent_actions": 1, "tool_wall_seconds": 60},
        )
        requested = DurableBudgetReservation.request(
            owner_kind="hunt",
            owner_id="hunt-1",
            capability_name="collections.replay",
            amounts=requested_budget,
            now=datetime.now(timezone.utc),
            reservation_id="reservation-1",
        )
        limits = {"http_requests": 10, "agent_actions": 10, "tool_wall_seconds": 600}
        reserved, held = requested.reserve_against(limits=limits, consumed={
            "http_requests": 0, "agent_actions": 0, "tool_wall_seconds": 0,
        })
        transitions = []
        settlements = []

        async def persist_transition(record, ledger):
            transitions.append((record.status, record.version, dict(ledger)))

        async def persist_settlement(record, receipt, ledger):
            settlements.append((record, receipt, dict(ledger)))

        outcome = await execute_replay_plan(
            plan,
            target=TargetBinding(
                target_id="target-1",
                target_kind="web",
                canonical_host="example.test",
                allowed_origins=("https://example.test",),
                allowed_addresses=("192.0.2.10",),
            ),
            owner_kind="hunt",
            owner_id="hunt-1",
            worker_id="worker-1",
            limits=limits,
            consumed=held,
            transport=_SuccessTransport(),
            reservation_id="reservation-1",
            initial_reservation=reserved,
            additional_budget={"agent_actions": 1, "tool_wall_seconds": 60},
            on_reservation=persist_transition,
            on_settlement=persist_settlement,
            require_durable_persistence=True,
        )
        return outcome, transitions, settlements

    outcome, transitions, settlements = asyncio.run(drive())
    assert [item[0] for item in transitions] == ["running"]
    assert outcome.reservation.status == "committed"
    assert outcome.reservation.actual["http_requests"] == 1
    assert outcome.reservation.actual["agent_actions"] == 1
    assert 0 <= outcome.reservation.actual["tool_wall_seconds"] <= 60
    assert settlements[0][1].input_digest == _plan().input_digest
    assert settlements[0][2]["http_requests"] == 1
    assert outcome.receipt.observations[0]["attempted_addresses"] == [
        "192.0.2.10",
    ]


def test_pinned_transport_preserves_exact_headers_and_body_without_dns():
    async def drive():
        captured = {}

        async def serve(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            headers, body_start = head.split(b"\r\n\r\n", 1)
            content_length = 0
            for line in headers.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":", 1)[1].strip())
            body = body_start
            if len(body) < content_length:
                body += await reader.readexactly(content_length - len(body))
            captured["wire"] = headers + b"\r\n\r\n" + body
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Content-Type: text/plain\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            server = await asyncio.start_server(serve, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("test sandbox does not permit a loopback listener")
        port = server.sockets[0].getsockname()[1]
        origin = f"http://replay.test:{port}"
        plan = build_replay_plan(
            [{
                "id": "exact-post",
                "method": "POST",
                "url": f"{origin}/submit?token=worker-only",
                "headers": {
                    "Authorization": "Bearer exact-secret",
                    "Content-Type": "application/json",
                    "X-Exact": "preserved",
                },
                "body": b'{"secret":"body-value"}',
            }],
            allowed_origins=[origin],
            default_origin=origin,
            authorization=ReplayAuthorization(
                active_testing=True,
                allow_state_changing_http=True,
                approval_receipt_id="approval-1",
            ),
        )
        target = TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="replay.test",
            allowed_origins=(origin,),
            allowed_addresses=("127.0.0.1",),
        )
        try:
            result = await PinnedAiohttpReplayTransport().send(
                plan.requests[0], target=target, timeout_seconds=2, follow_redirects=False,
            )
        finally:
            server.close()
            await server.wait_closed()
        return result, captured["wire"]

    result, wire = asyncio.run(drive())
    assert result.status_code == 200
    assert result.connected_address == "127.0.0.1"
    assert result.attempted_addresses == ("127.0.0.1",)
    assert b"Authorization: Bearer exact-secret" in wire
    assert b"X-Exact: preserved" in wire
    assert wire.endswith(b'{"secret":"body-value"}')


def test_pinned_replay_fails_over_in_stable_order_and_reports_the_real_peer():
    async def drive():
        async def serve(_reader, writer):
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nok"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            server = await asyncio.start_server(serve, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("test sandbox does not permit a loopback listener")
        port = server.sockets[0].getsockname()[1]
        origin = f"http://replay.test:{port}"
        plan = build_replay_plan(
            [{"id": "request-1", "method": "GET", "url": origin + "/"}],
            allowed_origins=[origin], default_origin=origin,
        )
        target = TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="replay.test",
            allowed_origins=(origin,),
            allowed_addresses=("127.0.0.1", "127.0.0.0"),
        )
        try:
            return await PinnedAiohttpReplayTransport().send(
                plan.requests[0], target=target,
                timeout_seconds=3, follow_redirects=False,
            )
        finally:
            server.close()
            await server.wait_closed()

    result = asyncio.run(drive())
    assert result.status_code == 200
    assert result.connected_address == "127.0.0.1"
    assert result.attempted_addresses == ("127.0.0.0", "127.0.0.1")


def test_hunt_api_never_decrypts_collection_replay_payloads():
    replay_helper = definition_source("_enqueue_hunt_replay_capability")
    assert "decrypt_secret" not in replay_helper
    assert '"type": "request_collection_replay"' in replay_helper
    assert "expected_payload_sha256" in replay_helper
    assert '"credential_profile_id"' in replay_helper
    assert "principal_profile_version" not in replay_helper


def test_worker_replay_uses_durable_store_and_exact_plan():
    source = open("api/worker.py", encoding="utf-8").read()
    start = source.index("async def process_request_collection_replay_job")
    end = source.index("\n\nasync def process_canonical_network_capability_job", start)
    handler = source[start:end]
    assert "decrypt_secret" in handler
    assert 'collection["encrypted_environment"]' in handler
    assert "expected_selection_digest" in handler
    assert "request_collection_selection_digest" in handler
    assert "queued_allowed_origins" in handler
    assert "select_requests(payload, stored_runtime_selector)" in handler
    assert "build_selected_replay_plan" in handler
    assert "create_requested" in handler
    assert "persist_transition" in handler
    assert "persist_terminal" in handler
    assert "Pinn" in handler and "ReplayTransport" in handler
    assert "validate_worker_credential_authority" in handler
    assert "WorkerCredentialResolver" in handler
    assert 'capability="collections.replay_safe"' in handler
    assert 'capability="request.replay"' not in handler
    assert "bind_replay_credential_headers" in handler
    assert '"receipt_context": receipt_context' in handler
    assert "ReplayExecutionAdapter(" in handler
    assert "_dispatch_registered_hunt_adapter(" in handler
    assert "adapter_managed_cancellation=True" in handler
    assert "cancelled=lambda: bool(redis_client.exists(cancel_key))" in handler

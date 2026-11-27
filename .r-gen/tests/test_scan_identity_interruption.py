"""Real loopback transport stops through the ordinary Scan adapter callback."""
import asyncio
from dataclasses import replace
from uuid import uuid4

from runtime.models import TargetBinding, ScanPolicy
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanActionPlan
from scan.worker_action_executor import ReceiptScanActionExecutor
from tests.test_scan_action_adapter import _action, _lease, Backend


def test_authority_loss_closes_inflight_http_connection_without_waiting_for_response():
    async def run():
        entered, closed = asyncio.Event(), asyncio.Event()
        calls = 0

        async def handler(reader, writer):
            nonlocal calls
            try:
                await reader.readuntil(b"\r\n\r\n")
                calls += 1
                entered.set()
                assert await reader.read() == b""
                closed.set()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(handler, "127.0.0.1", 0) as server:
            origin = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            target = TargetBinding(target_id="target-1", target_kind="web", canonical_host="127.0.0.1",
                allowed_origins=(origin,), allowed_addresses=("127.0.0.1",), environment="lab")
            action = replace(_action("baseline.http", "http.request", 0), target_binding_digest=target.digest, action_digest=None)
            plan = ScanActionPlan(scan_id=str(uuid4()), execution_plan_digest="a" * 64,
                target_binding_digest=target.digest, actions=(action,))
            async def forbidden(*args, **kwargs):
                raise AssertionError("No subprocess is part of this fixture")

            dispatcher = DatabaseNeutralScanActionDispatcher(target_url=origin, target=target,
                options={}, policy=ScanPolicy(), scan_id=plan.scan_id, job_id="fixture", worker_id="broker:worker-1",
                plan=plan, backend=Backend(), process_runner=forbidden, cancelled=lambda: False)

            async def authority(_action):
                return "authentication_uncertain" if entered.is_set() else None

            executor = ReceiptScanActionExecutor(scan_id=plan.scan_id, target_id=target.target_id,
                worker_id="broker:worker-1", dispatcher=dispatcher, credential_check=authority)
            async with asyncio.timeout(3):
                receipt = await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
                await closed.wait()
            assert calls == 1
            assert receipt.status == "partial" and receipt.partial
            assert receipt.errors == ("authentication_uncertain",)
            assert receipt.budget_consumed["http_requests"] == 1
            assert receipt.redacted_execution["identity_interruption"]["continuous_identity_proven"] is False

    asyncio.run(run())

"""Installed probe acceptance, using synthetic loopback targets and no product jobs."""
import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
import worker

pytestmark = pytest.mark.skipif(not Path("/opt/tools/httpx").is_file() or not hasattr(os, "memfd_create"),
    reason="requires the installed Linux probe")


@pytest.mark.parametrize("cancel", [False, True])
def test_worker_probe_keeps_identity_out_of_argv_and_stops_at_exact_destination(monkeypatch, cancel):
    monkeypatch.setenv("SHAKERSCAN_BROKER_LEASE", "1")
    launch = asyncio.create_subprocess_exec
    descriptors, argv_clean = [], []
    secrets = ["fixture-probe-identity-one", "fixture-probe-identity-two"]

    async def capture(*args, **kwargs):
        argv_clean.append(all(secret not in " ".join(args) for secret in secrets))
        descriptors.extend(kwargs.get("pass_fds", ()))
        return await launch(*args, **kwargs)

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", capture)

    async def run():
        seen, leaked = [], []
        entered, stop, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def forbidden(reader, writer):
            leaked.append(True)
            writer.close()
            await writer.wait_closed()

        async with await asyncio.start_server(forbidden, "127.0.0.1", 0) as decoy:
            other_port = decoy.sockets[0].getsockname()[1]
            async def serve(reader, writer):
                try:
                    request = await reader.readuntil(b"\r\n\r\n")
                    seen.append(request)
                    entered.set()
                    if cancel:
                        await reader.read()
                        closed.set()
                        return
                    secret = next(value for value in secrets if value.encode() in request)
                    body = ("<title>" + secret + "</title>").encode()
                    writer.write((f"HTTP/1.1 302 Found\r\nLocation: http://other.example.test:{other_port}/leak\r\n"
                        f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            async with await asyncio.start_server(serve, "127.0.0.1", 0) as target:
                port = target.sockets[0].getsockname()[1]
                async def execute(index):
                    origin = f"http://identity-{index}.example.test:{port}"
                    return await worker._execute_agent_scanner_process({
                        "job_id": str(uuid4()), "tool_name": "httpx", "execution_target": origin + "/",
                        "registered_target": origin, "scanner_options": {}, "pinned_address": "127.0.0.1",
                        "authorized_addresses": ["127.0.0.1"], "trusted_headers": {"X-Fixture-Key": secrets[index]},
                        "_reserved_budget": {"http_requests": 1, "tool_wall_seconds": 15},
                        "_cancelled": stop.is_set})
                if cancel:
                    task = asyncio.create_task(execute(0))
                    await asyncio.wait_for(entered.wait(), 12)
                    stop.set()
                    value = await asyncio.wait_for(task, 4)
                    await asyncio.wait_for(closed.wait(), 2)
                    assert value["status"] == "cancelled"
                    results = [value]
                else:
                    results = await asyncio.wait_for(asyncio.gather(execute(0), execute(1)), 25)
                    assert all(value["status"] == "success" for value in results)
                assert not leaked
                assert len(seen) == len(results)
                assert all(sum(secret.encode() in request for secret in secrets) == 1 for request in seen)
                assert all(secret not in json.dumps(results) for secret in secrets)
                assert all(value["network_telemetry"]["connections_opened"] == 1 for value in results)
        assert argv_clean and all(argv_clean) and len(descriptors) == len(results)
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    asyncio.run(run())

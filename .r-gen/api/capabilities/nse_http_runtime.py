"""Local-only lifecycle for NSE's canonical HTTP transport, including cleanup."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, replace
import hmac
import json
from pathlib import Path
import secrets
import tempfile
from typing import Any
from urllib.parse import urlsplit

from runtime.models import TargetBinding
from .nse_http_transport import NseHttpTransport, HTTP_SCRIPT_LIMITS


@dataclass
class NseCommandResult:
    process: Any
    nse_http: NseHttpTransport | None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.process, name)


@asynccontextmanager
async def command_transport(prepared, command, *, heartbeat, cancelled):
    data = prepared.redacted_execution
    scripts = tuple(name for name in data.get("scripts", ()) if name in HTTP_SCRIPT_LIMITS)
    if not scripts:
        yield command, None
        return
    target = TargetBinding(**{**data["http_target"], "allowed_addresses": (command.destination_address,)})
    bridge = NseHttpTransport(target=target, ports=tuple(data["ports"]), scripts=scripts,
                             allow_write=data.get("allow_state_changing_http") is True,
                             heartbeat=heartbeat, cancelled=cancelled)
    token = secrets.token_urlsafe(32)
    tasks: set[asyncio.Task] = set()

    async def handle(reader, writer):
        task = asyncio.current_task()
        if len(tasks) >= 16:
            writer.close()
            return
        tasks.add(task)
        authenticated = False
        try:
            async with asyncio.timeout(60):
                line = await reader.readline()
                request = json.loads(line)
                if (not isinstance(request, dict) or not isinstance(request.get("token"), str)
                        or not hmac.compare_digest(request["token"], token)):
                    return
                authenticated = True
                response = await bridge.request(request)
                response = {key: value for key, value in response.items() if value is not None}
                writer.write(json.dumps(response, ensure_ascii=True).encode("ascii") + b"\n")
                await writer.drain()
        except asyncio.CancelledError:
            raise
        except (TimeoutError, ValueError, OSError):
            if authenticated:
                bridge._error("nse_http_bridge_incomplete")
        finally:
            writer.close()
            with suppress(OSError, asyncio.CancelledError):
                await writer.wait_closed()
            tasks.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0, limit=8192)
    try:
        with tempfile.TemporaryDirectory(prefix="shakerscan-nse-") as directory:
            args = Path(directory) / "args"
            args.write_text(f'shakerscan.port={server.sockets[0].getsockname()[1]},'
                            f'shakerscan.token="{token}",shakerscan.scripts="{"|".join(scripts)}"', encoding="ascii")
            args.chmod(0o600)
            argv = list(command.argv)
            argv[-1:-1] = ["--script-args-file", str(args)]
            yield replace(command, argv=tuple(argv)), bridge
    finally:
        bridge.closed = True
        server.close()
        await server.wait_closed()
        pending = list(tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


def decorate_observations(observations, bridge: NseHttpTransport | None):
    if bridge is None:
        return list(observations)
    grouped: dict[tuple[int, str], list[dict]] = {}
    for exchange in bridge.exchanges:
        grouped.setdefault((exchange["requested_port"], exchange["script_id"]), []).append(dict(exchange))
    result = []
    for item in observations:
        item = dict(item)
        key = (item["port"], item["script_id"])
        gaps = [dict(gap) for gap in bridge.coverage_gaps
                if (gap["port"], gap["script_id"]) == key]
        if gaps:
            item["coverage_gaps"] = gaps
        exchanges = grouped.pop(key, [])
        if exchanges:
            item["http_exchanges"] = exchanges
            item["requested_port"] = key[0]
            actual = [e for e in exchanges if e.get("status_code") is not None and e["phase"] == "script"]
            if actual and item["script_id"] in {"http-security-headers", "http-trace"}:
                final = urlsplit(actual[-1]["url"])
                item.update(port=final.port or (443 if final.scheme == "https" else 80),
                            service_origin=f"{final.scheme}://{final.netloc}",
                            evidence_url=actual[-1]["url"])
        result.append(item)
    # TRACE's positive-only output may be nil; do not discard its real wire evidence.
    for (port, script), exchanges in grouped.items():
        result.append({"kind": "nse_observation", "address": bridge.target.allowed_addresses[0],
                       "port": port, "transport": "tcp", "script_id": script, "status": "inconclusive",
                       "signals": {}, "proof_state": "observation_only", "http_exchanges": exchanges})
    return result

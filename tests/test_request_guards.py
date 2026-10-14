"""Server guards: request classes, heavy-read admission, the response byte budget and the
process ceilings (api/request_guards.py)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import JSONResponse, StreamingResponse  # noqa: E402

import request_guards as rg  # noqa: E402

SETTINGS = rg.GuardSettings(
    default_timeout_ms=30_000, interactive_timeout_ms=5_000, heavy_timeout_ms=31_000,
    export_timeout_ms=120_000, heavy_concurrency=2, admission_wait_seconds=0.05,
    retry_after_seconds=7, response_max_bytes=1_000, export_response_max_bytes=100_000,
    limit_concurrency=256,
)


# --- Classification ----------------------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "query", "kind", "group"), [
    ("GET", "/dashboard", "", "heavy", "dashboard"),
    ("GET", "/dashboard/", "", "heavy", "dashboard"),
    ("GET", "/exposure/assets", "limit=1000", "heavy", "exposure"),
    ("GET", "/exposure/graph", "", "heavy", "exposure"),
    ("GET", "/targets/grouped", "", "heavy", "inventory"),
    ("GET", "/targets/inventory", "include_facets=true", "heavy", "inventory"),
    ("GET", "/targets/inventory", "group_by=domain&limit=40", "heavy", "inventory"),
    ("GET", "/targets/inventory", "sort=risk", "heavy", "inventory"),
    ("GET", "/targets/inventory", "sort=name&include_facets=false", "interactive", None),
    ("GET", "/evidence/export-bundle", "scan_id=x", "export", "exports"),
    ("GET", "/evidence/export-manifest", "", "export", "exports"),
    ("GET", "/model-intake/scans/abc/evidence-export", "", "export", "exports"),
    ("GET", "/scans/abc/ai-redteam-report", "format=pdf", "export", "exports"),
    ("GET", "/ai/test-cases/export", "format=pyrit", "export", "exports"),
    # Archive exports and Hunt records take their own export slots: timeout class only.
    ("GET", "/scans/abc/http-transactions", "format=har", "export", None),
    ("GET", "/hunts/abc/record", "", "export", None),
    ("HEAD", "/findings", "", "interactive", None),
    ("GET", "/findings", "limit=50", "interactive", None),
    ("POST", "/dashboard", "", "default", None),
    ("POST", "/scans", "", "default", None),
    ("DELETE", "/exposure/assets", "", "default", None),
])
def test_classification(method, path, query, kind, group):
    assert rg.classify_request(method, path, query.encode()) == rg.RequestClass(kind, group)


def test_settings_from_environment(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_API_READ_STATEMENT_TIMEOUT_MS", "2500")
    monkeypatch.setenv("SHAKERSCAN_API_HEAVY_CONCURRENCY", "3")
    monkeypatch.setenv("SHAKERSCAN_API_RESPONSE_MAX_BYTES", "0")
    monkeypatch.setenv("SHAKERSCAN_API_LIMIT_CONCURRENCY", "junk")
    monkeypatch.setenv("DB_STATEMENT_TIMEOUT_MS", "-5")
    settings = rg.GuardSettings.from_env()
    assert settings.interactive_timeout_ms == 2500
    assert settings.heavy_concurrency == 3
    assert settings.response_max_bytes == 0
    assert settings.limit_concurrency == 256
    assert settings.default_timeout_ms == 0
    assert rg.GuardSettings() == rg.GuardSettings(
        default_timeout_ms=30_000, interactive_timeout_ms=5_000, heavy_timeout_ms=30_000,
        export_timeout_ms=120_000, heavy_concurrency=2, admission_wait_seconds=1.0,
        retry_after_seconds=5, response_max_bytes=50 * 1024 * 1024,
        export_response_max_bytes=512 * 1024 * 1024, limit_concurrency=256,
    )


# --- The middleware on an app ------------------------------------------------------------------


def _app(settings: rg.GuardSettings = SETTINGS) -> tuple[FastAPI, dict]:
    app = FastAPI()
    state: dict = {"release": None, "entered": 0, "timeouts": {}}

    async def hold():
        state["entered"] += 1
        await state["release"].wait()

    @app.get("/dashboard")
    async def dashboard():
        await hold()
        return {"ok": True}

    @app.get("/exposure/assets")
    async def exposure():
        await hold()
        return {"ok": True}

    @app.api_route("/timeout/{name}", methods=["GET", "POST"])
    async def timeout(name: str):
        return {"timeout": rg._statement_timeout_ms.get()}

    @app.get("/scans/{scan_id}/http-transactions")
    async def export(scan_id: str, size: int = 10):
        return JSONResponse({"pad": "x" * size, "timeout": rg._statement_timeout_ms.get()})

    @app.get("/sized")
    async def sized(size: int = 10):
        return JSONResponse({"pad": "x" * size})

    @app.get("/stream")
    async def stream(chunks: int = 3, media: str = "application/json"):
        async def body():
            for _ in range(chunks):
                yield b"x" * 400
        return StreamingResponse(body(), media_type=media)

    @app.get("/cancelled")
    async def cancelled():
        asyncpg = pytest.importorskip("asyncpg")
        raise asyncpg.exceptions.QueryCanceledError("canceling statement due to statement timeout")

    rg.configure_request_guards(app, settings)
    return app, state


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api")


def test_heavy_reads_get_two_slots_per_group_then_429_with_retry_after():
    async def run():
        app, state = _app()
        state["release"] = asyncio.Event()
        async with _client(app) as client:
            held = [asyncio.create_task(client.get("/dashboard")) for _ in range(2)]
            while state["entered"] < 2:
                await asyncio.sleep(0.01)
            refused = await client.get("/dashboard")
            # Another group is not blocked by a full dashboard group.
            other = asyncio.create_task(client.get("/exposure/assets"))
            while state["entered"] < 3:
                await asyncio.sleep(0.01)
            # Ordinary reads never wait for a slot.
            plain = await client.get("/timeout/x")
            state["release"].set()
            done = await asyncio.gather(*held, other)
            again = await client.get("/dashboard")
        return refused, done, plain, again

    refused, done, plain, again = asyncio.run(run())
    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "7"
    assert refused.json()["detail"]["error"] == "server_busy"
    assert [r.status_code for r in done] == [200, 200, 200]
    assert plain.status_code == 200
    assert again.status_code == 200  # the slots were returned


def test_a_waiting_request_takes_a_slot_freed_within_the_admission_wait():
    async def run():
        app, state = _app(rg.GuardSettings(**{**SETTINGS.__dict__, "admission_wait_seconds": 5.0}))
        state["release"] = asyncio.Event()
        async with _client(app) as client:
            held = [asyncio.create_task(client.get("/dashboard")) for _ in range(2)]
            while state["entered"] < 2:
                await asyncio.sleep(0.01)
            waiting = asyncio.create_task(client.get("/dashboard"))
            await asyncio.sleep(0.05)
            assert not waiting.done()
            state["release"].set()
            return await asyncio.gather(*held, waiting)

    assert [r.status_code for r in asyncio.run(run())] == [200, 200, 200]


def test_a_failing_heavy_request_returns_its_slot():
    gate = rg.AdmissionGate(1, 0.01)

    async def boom(scope, receive, send):
        raise RuntimeError("boom")

    async def run():
        middleware = rg.RequestGuardMiddleware(boom, settings=SETTINGS, gate=gate)
        scope = {"type": "http", "method": "GET", "path": "/dashboard", "query_string": b""}
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await middleware(scope, None, None)
        return gate.active("dashboard")

    assert asyncio.run(run()) == 0


@pytest.mark.parametrize(("method", "path", "expected"), [
    ("GET", "/timeout/x", 5_000),
    ("GET", "/scans/abc/http-transactions", 120_000),
    ("POST", "/timeout/x", None),  # writes keep the pool's session default
])
def test_each_request_class_acquires_with_its_statement_timeout(method, path, expected):
    async def run():
        app, _ = _app()
        async with _client(app) as client:
            return (await client.request(method, path)).json()["timeout"]

    assert asyncio.run(run()) == expected
    assert rg._statement_timeout_ms.get() is None


def test_pool_setup_sets_only_a_timeout_that_differs_from_the_session_default():
    options = rg.statement_timeout_pool_options(30_000)
    assert options["server_settings"] == {"statement_timeout": "30000"}
    executed: list[str] = []

    class Conn:
        async def execute(self, sql):
            executed.append(sql)

    async def run():
        await options["setup"](Conn())                 # background loop: session default
        with rg.statement_timeout(30_000):
            await options["setup"](Conn())             # same as default: no round trip
        with rg.statement_timeout(5_000):
            await options["setup"](Conn())
        with rg.unbounded_statements():
            await options["setup"](Conn())

    asyncio.run(run())
    assert executed == ["SET statement_timeout = 5000", "SET statement_timeout = 0"]


def test_response_budget_refuses_a_declared_oversize_json_body():
    async def run():
        app, _ = _app()
        async with _client(app) as client:
            small = await client.get("/sized?size=500")
            big = await client.get("/sized?size=5000")
            export = await client.get("/scans/abc/http-transactions?size=50000")
            export_big = await client.get("/scans/abc/http-transactions?size=200000")
        return small, big, export, export_big

    small, big, export, export_big = asyncio.run(run())
    assert small.status_code == 200
    assert big.status_code == 500
    assert big.json()["detail"] == {
        "error": "response_too_large", "max_bytes": 1_000,
        "message": ("The response exceeds this server's per-request budget; request a smaller "
                    "page, fewer fields or a narrower filter."),
    }
    assert export.status_code == 200  # exports have their own, larger budget
    assert export_big.status_code == 500 and export_big.json()["detail"]["max_bytes"] == 100_000


def test_response_budget_aborts_a_streamed_json_body_and_spares_event_streams():
    async def run():
        app, _ = _app()
        async with _client(app) as client:
            ok = await client.get("/stream?chunks=2")
            sse = await client.get("/stream", params={"chunks": 10, "media": "text/event-stream"})
            with pytest.raises(rg.ResponseBudgetExceeded):
                await client.get("/stream?chunks=3")
        return ok, sse

    ok, sse = asyncio.run(run())
    assert ok.status_code == 200 and len(ok.content) == 800
    assert sse.status_code == 200 and len(sse.content) == 4_000


def test_a_disabled_budget_and_admission_pass_everything():
    settings = rg.GuardSettings(**{**SETTINGS.__dict__, "response_max_bytes": 0, "heavy_concurrency": 0})

    async def run():
        app, state = _app(settings)
        state["release"] = asyncio.Event()
        state["release"].set()
        async with _client(app) as client:
            big = await client.get("/sized?size=5000")
            many = await asyncio.gather(*(client.get("/dashboard") for _ in range(5)))
        return big, many

    big, many = asyncio.run(run())
    assert big.status_code == 200
    assert [r.status_code for r in many] == [200] * 5


def test_a_cancelled_statement_answers_504():
    pytest.importorskip("asyncpg")

    async def run():
        app, _ = _app()
        async with _client(app) as client:
            return await client.get("/cancelled")

    response = asyncio.run(run())
    assert response.status_code == 504
    assert response.json()["detail"]["error"] == "statement_timeout"


# --- uvicorn's concurrency ceiling ---------------------------------------------------------------


def test_uvicorn_options():
    assert rg.uvicorn_options(SETTINGS) == {"limit_concurrency": 256}
    assert rg.uvicorn_options(rg.GuardSettings(limit_concurrency=0)) == {}


def test_limit_concurrency_answers_503_beyond_the_ceiling():
    uvicorn = pytest.importorskip("uvicorn")
    release = threading.Event()

    async def app(scope, receive, send):
        while not release.is_set():
            await asyncio.sleep(0.01)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    options = rg.uvicorn_options(rg.GuardSettings(limit_concurrency=2))  # open connections count too
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error",
                                                lifespan="off", **options))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        first: dict = {}
        holder = threading.Thread(target=lambda: first.update(
            response=httpx.get(f"http://127.0.0.1:{port}/", timeout=10)))
        holder.start()
        time.sleep(0.3)
        refused = httpx.get(f"http://127.0.0.1:{port}/", timeout=10)
        release.set()
        holder.join(10)
    finally:
        release.set()
        server.should_exit = True
        thread.join(10)
    assert refused.status_code == 503
    assert first["response"].status_code == 200


def test_api_entry_point_runs_uvicorn_with_the_guard_options():
    import ast

    tree = ast.parse((ROOT / "api" / "api.py").read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and getattr(node.func, "attr", None) == "run"
             and getattr(node.func, "value", None) is not None
             and getattr(node.func.value, "id", None) == "uvicorn"]
    assert len(calls) == 1
    assert any(keyword.arg is None and getattr(keyword.value.func, "id", None) == "_uvicorn_guard_options"
               for keyword in calls[0].keywords)


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.release.yml"])
def test_compose_caps_api_memory_and_passes_the_guard_knobs(compose):
    yaml = pytest.importorskip("yaml")
    api = yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))["services"]["api"]
    assert api["mem_limit"] == "${SHAKERSCAN_API_MEMORY_LIMIT:-4g}"
    names = {entry.split("=", 1)[0] for entry in api["environment"]}
    assert {
        "DB_STATEMENT_TIMEOUT_MS", "SHAKERSCAN_API_READ_STATEMENT_TIMEOUT_MS",
        "SHAKERSCAN_API_HEAVY_STATEMENT_TIMEOUT_MS", "SHAKERSCAN_API_EXPORT_STATEMENT_TIMEOUT_MS",
        "SHAKERSCAN_API_HEAVY_CONCURRENCY", "SHAKERSCAN_API_HEAVY_ADMISSION_WAIT_SECONDS",
        "SHAKERSCAN_API_HEAVY_RETRY_AFTER_SECONDS", "SHAKERSCAN_API_RESPONSE_MAX_BYTES",
        "SHAKERSCAN_API_EXPORT_RESPONSE_MAX_BYTES", "SHAKERSCAN_API_LIMIT_CONCURRENCY",
    } <= names
    json.dumps(api)  # plain data

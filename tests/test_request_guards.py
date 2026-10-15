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
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse, StreamingResponse  # noqa: E402

import request_guards as rg  # noqa: E402

SETTINGS = rg.GuardSettings(
    default_timeout_ms=30_000, interactive_timeout_ms=5_000, heavy_timeout_ms=31_000,
    export_timeout_ms=120_000, heavy_concurrency=2, admission_wait_seconds=0.05,
    retry_after_seconds=7, response_max_bytes=1_000, export_response_max_bytes=100_000,
    max_in_flight=256,
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
    # include_facets is read exactly as the endpoint's pydantic bool reads it.
    ("GET", "/targets/inventory", "include_facets=Y", "heavy", "inventory"),
    ("GET", "/targets/inventory", "include_facets=t", "heavy", "inventory"),
    ("GET", "/targets/inventory", "include_facets=ON", "heavy", "inventory"),
    ("GET", "/targets/inventory", "include_facets=1", "heavy", "inventory"),
    ("GET", "/targets/inventory", "include_facets=off", "interactive", None),
    ("GET", "/targets/inventory", "include_facets=maybe", "interactive", None),
    # Interim heavy rows until their endpoints are bounded.
    # Bounded since 2.11 (index-ordered page, separate count): an interactive read again.
    ("HEAD", "/findings", "", "interactive", None),
    ("GET", "/findings", "limit=50&offset=400000", "interactive", None),
    ("GET", "/findings", "proof_state=suspected&limit=50", "heavy", "findings"),
    ("GET", "/findings", "proof_state=%2C", "interactive", None),
    ("GET", "/findings", "proof_state=suspected&cursor=abc", "interactive", None),
    ("GET", "/findings", "proof_state=verified&count=exact", "interactive", None),
    ("GET", "/targets/abc/graph", "", "heavy", "target_graph"),
    ("GET", "/targets/abc/asm/gaps", "", "heavy", "asm"),
    ("GET", "/targets/abc/asm/endpoints", "limit=1000", "heavy", "asm"),
    # Bounded since 2.11: list/v1 graph pages, SQL-counted ASM coverage and campaign impact.
    ("GET", "/targets/abc/graph", "count=none&limit=200", "interactive", None),
    ("GET", "/targets/abc/graph", "cursor=x", "interactive", None),
    ("GET", "/targets/abc/asm/coverage", "", "interactive", None),
    ("GET", "/arsenal/campaigns", "", "interactive", None),
    ("GET", "/arsenal/refuter-reviews/summary", "", "heavy", "arsenal"),
    # Bounded in 2.11 (bounded reads; ~0.5 s at 100k job hashes / 0.3 s at 10k result files).
    ("GET", "/queue/stats", "", "interactive", None),
    ("GET", "/results", "", "interactive", None),
    ("GET", "/findings/abc", "", "interactive", None),
    ("GET", "/scans", "limit=50", "interactive", None),
    ("GET", "/results/folder/latest", "", "interactive", None),
    ("POST", "/dashboard", "", "default", None),
    ("POST", "/scans", "", "default", None),
    ("DELETE", "/exposure/assets", "", "default", None),
])
def test_classification(method, path, query, kind, group):
    assert rg.classify_request(method, path, query.encode()) == rg.RequestClass(kind, group)


def test_include_facets_parsing_matches_the_endpoint_bool():
    from pydantic import TypeAdapter, ValidationError

    for raw in ["1", "0", "true", "False", "yes", "NO", "y", "n", "t", "f", "on", "Off", "2", "", "x"]:
        try:
            expected = TypeAdapter(bool).validate_python(raw)
        except ValidationError:
            expected = False
        heavy = rg.classify_request("GET", "/targets/inventory", f"include_facets={raw}").kind == "heavy"
        assert heavy is expected, raw


def test_the_classification_is_one_table_a_row_can_leave():
    rows = [rule for rule in rg.ROUTE_CLASSES if rule.pattern.pattern == "^/findings$"]
    assert len(rows) == 1
    remaining = tuple(rule for rule in rg.ROUTE_CLASSES if rule is not rows[0])
    original = rg.ROUTE_CLASSES
    try:
        rg.ROUTE_CLASSES = remaining
        assert rg.classify_request("GET", "/findings", b"proof_state=suspected") == rg.RequestClass(
            "interactive", None)
    finally:
        rg.ROUTE_CLASSES = original


def test_settings_from_environment(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_API_READ_STATEMENT_TIMEOUT_MS", "2500")
    monkeypatch.setenv("SHAKERSCAN_API_HEAVY_CONCURRENCY", "3")
    monkeypatch.setenv("SHAKERSCAN_API_RESPONSE_MAX_BYTES", "0")
    monkeypatch.setenv("SHAKERSCAN_API_MAX_IN_FLIGHT_REQUESTS", "junk")
    monkeypatch.setenv("DB_STATEMENT_TIMEOUT_MS", "-5")
    settings = rg.GuardSettings.from_env()
    assert settings.interactive_timeout_ms == 2500
    assert settings.heavy_concurrency == 3
    assert settings.response_max_bytes == 0
    assert settings.max_in_flight == 256
    assert settings.default_timeout_ms == 0
    assert rg.GuardSettings() == rg.GuardSettings(
        default_timeout_ms=30_000, interactive_timeout_ms=5_000, heavy_timeout_ms=30_000,
        export_timeout_ms=120_000, heavy_concurrency=2, admission_wait_seconds=1.0,
        retry_after_seconds=5, response_max_bytes=50 * 1024 * 1024,
        export_response_max_bytes=512 * 1024 * 1024, max_in_flight=256,
        heavy_send_timeout_seconds=30.0,
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
    assert options["server_settings"] == {"statement_timeout": "30000", "jit": "off"}
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


# --- In-flight ceiling, slow clients, cancellations in broad excepts -------------------------


def _guarded(app, **overrides):
    settings = rg.GuardSettings(**{**SETTINGS.__dict__, **overrides})
    return rg.RequestGuardMiddleware(app, settings=settings)


def _scope(path, method="GET"):
    return {"type": "http", "method": method, "path": path, "query_string": b"", "headers": []}


def test_in_flight_ceiling_answers_503_with_retry_after_and_health_still_answers():
    release = None
    entered = []

    async def app(scope, receive, send):
        entered.append(scope["path"])
        if scope["path"] != "/health":
            await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def run():
        nonlocal release
        release = asyncio.Event()
        middleware = _guarded(app, max_in_flight=2)
        sent: list[list] = [[] for _ in range(4)]

        def recorder(index):
            async def send(message):
                sent[index].append(message)
            return send

        held = [asyncio.create_task(middleware(_scope("/scans"), None, recorder(i))) for i in range(2)]
        while len(entered) < 2:
            await asyncio.sleep(0.01)
        await middleware(_scope("/targets"), None, recorder(2))
        await middleware(_scope("/health"), None, recorder(3))
        release.set()
        await asyncio.gather(*held)
        after = middleware.in_flight.active
        return sent, after

    sent, after = asyncio.run(run())
    refused = sent[2][0]
    assert refused["status"] == 503
    assert (b"retry-after", b"7") in refused["headers"]
    assert json.loads(sent[2][1]["body"])["detail"]["error"] == "server_overloaded"
    assert sent[3][0]["status"] == 200  # liveness is never capped
    assert [m[0]["status"] for m in sent[:2]] == [200, 200]
    assert after == 0


def test_a_response_that_has_started_no_longer_counts_in_flight():
    """An event stream (or a slow body) must not hold a request slot for its whole life."""
    streaming = asyncio.Event()
    finish = asyncio.Event()

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")]})
        streaming.set()
        await finish.wait()
        await send({"type": "http.response.body", "body": b"data: x\n\n"})

    async def run():
        middleware = _guarded(app, max_in_flight=1)

        async def send(message):
            pass

        stream = asyncio.create_task(middleware(_scope("/scans/abc/logs/stream"), None, send))
        await streaming.wait()
        during = middleware.in_flight.active
        statuses = []

        async def record(message):
            if message["type"] == "http.response.start":
                statuses.append(message["status"])

        async def quick(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        middleware.app = quick
        await middleware(_scope("/scans"), None, record)
        finish.set()
        middleware.app = app
        await stream
        return during, statuses

    during, statuses = asyncio.run(run())
    assert during == 0
    assert statuses == [200]


def test_idle_connections_never_refuse_requests():
    """The outage the uvicorn ceiling allowed: bare sockets that never send a byte."""
    uvicorn = pytest.importorskip("uvicorn")
    app = FastAPI()

    @app.get("/scans")
    async def scans():
        return {"ok": True}

    rg.configure_request_guards(app, rg.GuardSettings(**{**SETTINGS.__dict__, "max_in_flight": 2}))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    idle: list[socket.socket] = []
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        for _ in range(20):
            idle.append(socket.create_connection(("127.0.0.1", port)))
        time.sleep(0.2)
        response = httpx.get(f"http://127.0.0.1:{port}/scans", timeout=10)
    finally:
        for sock in idle:
            sock.close()
        server.should_exit = True
        thread.join(10)
    assert response.status_code == 200


def test_the_admission_slot_is_returned_before_a_slow_client_reads_the_body():
    client_reading = asyncio.Event()
    client_done = asyncio.Event()

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    async def run():
        gate = rg.AdmissionGate(1, 0.01)
        middleware = rg.RequestGuardMiddleware(app, settings=SETTINGS, gate=gate)

        async def slow_send(message):
            if message["type"] == "http.response.body":
                client_reading.set()
                await client_done.wait()

        slow = asyncio.create_task(middleware(_scope("/dashboard"), None, slow_send))
        await client_reading.wait()
        free_while_sending = gate.active("dashboard")
        second: list[int] = []

        async def record(message):
            if message["type"] == "http.response.start":
                second.append(message["status"])

        await middleware(_scope("/dashboard"), None, record)
        client_done.set()
        await slow
        return free_while_sending, second, gate.active("dashboard")

    free_while_sending, second, after = asyncio.run(run())
    assert free_while_sending == 0
    assert second == [200]
    assert after == 0


def test_detached_statements_drop_the_request_class():
    options = rg.statement_timeout_pool_options(30_000)
    executed: list[str] = []

    class Conn:
        async def execute(self, sql):
            executed.append(sql)

    async def run():
        with rg.statement_timeout(5_000):
            with rg.detached_statements():
                task = asyncio.create_task(options["setup"](Conn()))
            await task
            await options["setup"](Conn())

    asyncio.run(run())
    assert executed == ["SET statement_timeout = 5000"]  # only the request's own acquire


def test_reraise_statement_timeout_only_reraises_cancellations():
    asyncpg = pytest.importorskip("asyncpg")
    rg.reraise_statement_timeout(ValueError("x"))
    with pytest.raises(asyncpg.exceptions.QueryCanceledError):
        rg.reraise_statement_timeout(asyncpg.exceptions.QueryCanceledError("timeout"))


def test_dashboard_status_cards_let_a_cancelled_query_answer_504():
    asyncpg = pytest.importorskip("asyncpg")
    from operations import router as operations_router

    class Conn:
        async def fetchrow(self, *args, **kwargs):
            raise asyncpg.exceptions.QueryCanceledError("canceling statement due to statement timeout")

        fetch = fetchval = fetchrow

    with pytest.raises(asyncpg.exceptions.QueryCanceledError):
        asyncio.run(operations_router._build_dashboard_product_status(Conn(), worker_snapshot={}))
    with pytest.raises(asyncpg.exceptions.QueryCanceledError):
        asyncio.run(operations_router._build_dashboard_action_center(Conn(), worker_snapshot={}))

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
        "SHAKERSCAN_API_EXPORT_RESPONSE_MAX_BYTES", "SHAKERSCAN_API_MAX_IN_FLIGHT_REQUESTS",
        "SHAKERSCAN_API_HEAVY_SEND_TIMEOUT_SECONDS",
    } <= names
    assert "SHAKERSCAN_API_LIMIT_CONCURRENCY" not in names
    json.dumps(api)  # plain data



# --- Slow uploaders and parked heavy bodies --------------------------------------------------------


def test_a_request_waiting_for_its_body_does_not_count_in_flight():
    body_arrives = asyncio.Event()

    async def app(scope, receive, send):
        await receive()  # the request body
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def run():
        middleware = _guarded(app, max_in_flight=1)

        async def slow_receive():
            await body_arrives.wait()
            return {"type": "http.request", "body": b"x", "more_body": False}

        async def fast_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        statuses: list[int] = []

        async def record(message):
            if message["type"] == "http.response.start":
                statuses.append(message["status"])

        async def ignore(message):
            pass

        uploads = [asyncio.create_task(middleware(_scope("/scans", "POST"), slow_receive, ignore))
                   for _ in range(5)]
        await asyncio.sleep(0.05)
        waiting = middleware.in_flight.active
        await middleware(_scope("/scans"), fast_receive, record)
        body_arrives.set()
        await asyncio.gather(*uploads)
        return waiting, statuses, middleware.in_flight.active

    waiting, statuses, after = asyncio.run(run())
    assert waiting == 0
    assert statuses == [200]
    assert after == 0


def test_slow_uploaders_cannot_fill_the_ceiling_on_a_real_server():
    """Headers + Content-Length 1000000 + 2 bytes, held open, against a body-reading POST."""
    uvicorn = pytest.importorskip("uvicorn")
    app = FastAPI()

    @app.post("/upload")
    async def upload(request: Request):
        return {"bytes": len(await request.body())}

    @app.get("/scans")
    async def scans():
        return {"ok": True}

    rg.configure_request_guards(app, rg.GuardSettings(**{**SETTINGS.__dict__, "max_in_flight": 4}))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    uploaders: list[socket.socket] = []
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        for _ in range(12):
            sock = socket.create_connection(("127.0.0.1", port))
            sock.sendall(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
                         b"Content-Length: 1000000\r\n\r\nab")
            uploaders.append(sock)
        time.sleep(0.3)
        response = httpx.get(f"http://127.0.0.1:{port}/scans", timeout=10)
        # The uploaders are really still sending: none of them has been answered.
        for sock in uploaders:
            sock.setblocking(False)
            with pytest.raises(BlockingIOError):
                sock.recv(1)
    finally:
        for sock in uploaders:
            sock.close()
        server.should_exit = True
        thread.join(10)
    assert response.status_code == 200


def test_a_heavy_body_a_client_does_not_read_is_aborted_and_frees_its_slot():
    never_read = asyncio.Event()

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    async def run():
        gate = rg.AdmissionGate(1, 0.01)
        settings = rg.GuardSettings(**{**SETTINGS.__dict__, "heavy_send_timeout_seconds": 0.1})
        middleware = rg.RequestGuardMiddleware(app, settings=settings, gate=gate)

        async def parked(message):
            if message["type"] == "http.response.body":
                await never_read.wait()

        started = asyncio.get_running_loop().time()
        with pytest.raises(rg.SlowClientAborted):
            await asyncio.wait_for(middleware(_scope("/dashboard"), None, parked), 5)
        elapsed = asyncio.get_running_loop().time() - started
        # An ordinary read has no send deadline: the same parked client is not aborted.
        plain = asyncio.create_task(middleware(_scope("/scans"), None, parked))
        await asyncio.sleep(0.3)
        plain_pending = not plain.done()
        plain.cancel()
        return elapsed, gate.active("dashboard"), plain_pending

    elapsed, active, plain_pending = asyncio.run(run())
    assert elapsed < 2
    assert active == 0
    assert plain_pending

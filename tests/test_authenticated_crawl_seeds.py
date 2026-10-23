"""A crawl that carries a session starts from every in-scope seed, not only the target (E1-N3).

The lab's Halvern Hub is reachable only from its own seeds: nothing on ``/`` links to ``/hub/``,
and ``/hub/`` answers only with the session. The signed-in crawl and browser crawl carried the
session but started at ``/`` alone, so nothing behind the sign-in was crawled. They now also
start at the scan's GET seed endpoints on the crawl's origin (depth 0 in the endpoint manifest:
seeds, known endpoints, collection requests) and at the page the sign-in landed on, within the
crawl's own reservation: the time box is shared among the inputs, and inputs a box cannot give a
useful share are left out. Action paths (sign-out, delete, one-time tokens) are never a seed.

The end-to-end test runs the real dispatcher and the real enforced crawler plan against a
fixture app on loopback; the crawler is a labelled fixture (``FixtureCrawler``) that follows the
plan's argv the way katana does (its ``-u`` inputs in order, ``-H`` headers, ``-crawl-out-scope``,
depth 2, same origin). No external target is contacted.
"""
from __future__ import annotations

import asyncio
import http.client
import http.server
import re
import threading
import urllib.parse
import uuid

import pytest

import agent_tools
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.execution_backend import ActionLease
from scan.work_manifests import build_endpoint_manifest

PROXY = "socks5://127.0.0.1:41000"
SESSION = {"Cookie": "hub_session=fixture"}


def _inputs(argv):
    return [argv[index + 1] for index, value in enumerate(argv) if value == "-u"]


def _value(argv, flag):
    return argv[argv.index(flag) + 1]


@pytest.mark.parametrize("tool", ["katana", "katana_headless"])
def test_seed_paths_become_crawl_inputs_on_the_crawl_origin_within_its_box(tool):
    budget = {"http_requests": 3_000, "tool_wall_seconds": 600}
    alone = agent_tools.build_enforced_scanner_plan(
        tool, "http://app.test:8000/", {}, reserved_budget=budget,
        pinned_proxy_url=PROXY, trusted_headers=SESSION,
    )
    seeded = agent_tools.build_enforced_scanner_plan(
        tool, "http://app.test:8000/", {"crawl_seed_paths": ["/hub/", "/hub/login", "/hub/"]},
        reserved_budget=budget, pinned_proxy_url=PROXY, trusted_headers=SESSION,
    )
    assert _inputs(list(alone.argv)) == ["http://app.test:8000/"]
    assert _inputs(list(seeded.argv)) == [
        "http://app.test:8000/", "http://app.test:8000/hub/", "http://app.test:8000/hub/login",
    ]
    whole = int(_value(list(alone.argv), "-crawl-duration").rstrip("s"))
    share = int(_value(list(seeded.argv), "-crawl-duration").rstrip("s"))
    assert share == whole // 3
    # The same reservation and the same ceiling: more inputs share the box, never a larger one.
    assert seeded.hard_budget_dict == alone.hard_budget_dict
    assert seeded.timeout_ms == alone.timeout_ms


@pytest.mark.parametrize("tool,wall,kept", [("katana", 25, 2), ("katana_headless", 42, 2)])
def test_a_box_too_small_for_every_seed_keeps_the_target_and_the_first_seeds(tool, wall, kept):
    plan = agent_tools.build_enforced_scanner_plan(
        tool, "https://app.test/", {"crawl_seed_paths": ["/a", "/b", "/c", "/d"]},
        reserved_budget={"http_requests": 3_000, "tool_wall_seconds": wall},
        pinned_proxy_url=PROXY, trusted_headers=SESSION,
    )
    assert _inputs(list(plan.argv)) == ["https://app.test/", "https://app.test/a", "https://app.test/b"][:kept]


@pytest.mark.parametrize("seed", [
    "http://evil.test/", "//evil.test/x", "hub", "/a,b", "/a b", "/a?x=1", "/a#b", "/a\\b", "/" + "a" * 2_100,
])
def test_a_seed_that_is_not_a_plain_path_on_the_crawl_origin_is_refused(seed):
    with pytest.raises(agent_tools.AgentToolError):
        agent_tools.build_scanner_argv(
            "katana", "https://app.test/", {"crawl_seed_paths": [seed]},
            pinned_proxy_url=PROXY, trusted_headers=SESSION,
        )


def test_too_many_seeds_are_refused():
    with pytest.raises(agent_tools.AgentToolError):
        agent_tools.build_scanner_argv(
            "katana", "https://app.test/",
            {"crawl_seed_paths": [f"/p{index}" for index in range(agent_tools.MAX_CRAWL_SEED_PATHS + 1)]},
            pinned_proxy_url=PROXY,
        )


# --- the dispatcher, a fixture app and a fixture crawler ----------------------------------------

class _FixtureApp(http.server.BaseHTTPRequestHandler):
    """``/`` never links to the Hub; the Hub answers only with the session cookie."""

    log: list[tuple[str, bool]] = []
    PAGES = {
        "/": '<a href="/about">About</a>',
        "/about": "<p>About</p>",
        "/hub/login": '<form method="post" action="/hub/login"><input name="username"></form>',
    }
    PRIVATE = {
        "/hub/": '<a href="/hub/orders">Orders</a> <a href="/hub/logout">Sign out</a>',
        "/hub/orders": '<a href="/hub/orders/7">Order 7</a>',
        "/hub/orders/7": "<p>order 7</p>",
        "/hub/logout": "<p>signed out</p>",
    }

    def do_GET(self):  # noqa: N802
        signed_in = "hub_session=fixture" in str(self.headers.get("Cookie") or "")
        self.log.append((self.path, signed_in))
        body = self.PAGES.get(self.path)
        if body is None and signed_in:
            body = self.PRIVATE.get(self.path)
        status = 200 if body is not None else (302 if self.path.startswith("/hub/") else 404)
        payload = (body or "").encode()
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/hub/login")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return None


class FixtureCrawler:
    """Labelled fixture for katana: crawls the plan's argv inputs in order, depth 2, same origin,
    with its ``-H`` headers, never following a URL its ``-crawl-out-scope`` expression matches.
    Every host name is reached at the fixture app's loopback port, as the pinned proxy would."""

    def __init__(self, port: int):
        self.port = port

    def run(self, argv: list[str]) -> None:
        headers = dict(
            value.split(": ", 1) for flag, value in zip(argv, argv[1:]) if flag == "-H"
        )
        exclusion = re.compile(_value(argv, "-crawl-out-scope")) if "-crawl-out-scope" in argv else None
        for start in _inputs(argv):
            origin = urllib.parse.urlsplit(start)
            frontier, seen = [(start, 0)], {start}
            while frontier:
                url, depth = frontier.pop(0)
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                connection.request("GET", urllib.parse.urlsplit(url).path or "/", headers=headers)
                response = connection.getresponse()
                body = response.read().decode()
                connection.close()
                if depth >= 2 or response.status != 200:
                    continue
                for href in re.findall(r'href="([^"]+)"', body):
                    link = urllib.parse.urljoin(url, href)
                    if urllib.parse.urlsplit(link).netloc != origin.netloc or link in seen:
                        continue
                    if exclusion is not None and exclusion.search(link):
                        continue
                    seen.add(link)
                    frontier.append((link, depth + 1))


@pytest.fixture
def fixture_app():
    _FixtureApp.log = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def _crawl(port, *, capability, signed_in, seeds, landing=None):
    host = "app.fixture.test"
    target = TargetBinding(
        target_id="target-1", target_kind="web", canonical_host=host,
        allowed_origins=(f"http://{host}:{port}",), allowed_addresses=("192.0.2.10",),
    )
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=target.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": method, "scheme": "http", "host": host, "port": port,
                "normalized_path": path, "concrete_path": path, "query_keys": [], "source": source,
            } for method, path, source in seeds],
        },
        source_action_ids=("inputs.seed",),
        auth_lane="primary",
    )
    spec = CAPABILITY_REGISTRY.require(capability)
    action = ScanAction(
        action_id="discover.web_crawl" if capability == "web.crawl" else "discover.browser_crawl",
        stage="discover_surface", ordinal=0, capability_name=spec.name,
        capability_args={"endpoint_manifest_ref": endpoints.reference().canonical_dict(), "read_only": True},
        target_binding_digest=target.digest, input_binding_digest="1" * 64,
        requested_budget={"http_requests": 3_000, "tool_wall_seconds": 600, "browser_actions": 400},
        placement={
            "schema_version": "scan-action-placement/v1", "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter, "adapter_version": spec.adapter_version,
        },
        dependencies=(), required=False, supporting=True, output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=target.digest, actions=(action,))
    observations = {"inputs.auth_primary": ({
        "kind": "credential_session", "lane": "primary", "status": "established",
        "endpoint_path": "/hub/login", **({"landing_path": landing} if landing else {}),
    },)} if signed_in else {}

    class Backend:
        async def load_work_manifest(self, _action_id, _reference):
            return endpoints

        async def load_observations(self, action_id):
            return observations.get(action_id, ())

    captured = {}

    async def process_runner(payload, *, heartbeat):
        await heartbeat()
        captured.update(payload)
        process_plan = agent_tools.build_enforced_scanner_plan(
            payload["tool_name"], payload["execution_target"], payload["scanner_options"],
            reserved_budget=payload["_reserved_budget"], pinned_proxy_url=PROXY,
            trusted_headers=payload["trusted_headers"],
        )
        captured["argv"] = list(process_plan.argv)
        FixtureCrawler(port).run(list(process_plan.argv))
        return {
            "status": "success", "elapsed_seconds": 1,
            "typed_output": {"records": [], "errors": []},
            "process_enforcement": process_plan.enforcement_receipt(),
        }

    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url=f"http://{host}:{port}/", options=dict(SESSION_OPTIONS) if signed_in else {},
        target=target, policy=ScanPolicy(active_testing=False),
        scan_id=scan_id, job_id="job-1", worker_id="broker:worker-1",
        plan=plan, backend=Backend(), process_runner=process_runner, cancelled=lambda: False,
    )
    lease = ActionLease(
        lease_id=str(uuid.uuid4()), lease_token="x" * 32, scan_id=scan_id,
        plan_digest=plan.plan_digest, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=target.digest, action=action, backend="broker",
        worker_id="broker:worker-1", lease_seconds=60, attempt=1,
    )
    try:
        asyncio.run(dispatcher(action, lease, lambda: asyncio.sleep(0)))
    except Exception:  # the fixture's output is not a real crawl's; the requests are the result
        pass
    return captured


SESSION_OPTIONS = {"auth_cookies": "hub_session=fixture"}
HUB_SEEDS = [
    ("GET", "/hub/login", "known_endpoints"),
    ("POST", "/hub/login", "known_endpoints"),
    ("GET", "/hub/logout", "known_endpoints"),
]


@pytest.mark.parametrize("capability", ["web.crawl", "web.browser_crawl"])
def test_the_signed_in_crawl_reaches_the_hub_from_its_seeds_with_the_session(fixture_app, capability):
    captured = _crawl(fixture_app, capability=capability, signed_in=True,
                      seeds=[*HUB_SEEDS, ("GET", "/hub/", "known_endpoints")])
    assert captured["scanner_options"]["crawl_seed_paths"] == ["/hub/", "/hub/login"]
    requested = {path for path, signed_in in _FixtureApp.log if signed_in}
    assert {"/hub/", "/hub/orders", "/hub/orders/7"} <= requested
    # Never a sign-out with the session, neither as a seed nor as a followed link.
    assert "/hub/logout" not in {path for path, _signed_in in _FixtureApp.log}


def test_the_page_the_sign_in_landed_on_is_a_seed(fixture_app):
    captured = _crawl(fixture_app, capability="web.crawl", signed_in=True, seeds=HUB_SEEDS,
                      landing="/hub/")
    assert captured["scanner_options"]["crawl_seed_paths"] == ["/hub/", "/hub/login"]
    assert "/hub/orders/7" in {path for path, signed_in in _FixtureApp.log if signed_in}


def test_without_seeds_the_signed_in_crawl_never_reaches_the_hub(fixture_app):
    """The 2.11.1 behaviour this fixes: the session alone, from ``/``, finds nothing behind it."""
    captured = _crawl(fixture_app, capability="web.crawl", signed_in=True, seeds=[])
    assert "crawl_seed_paths" not in captured["scanner_options"]
    assert not any(path.startswith("/hub/") for path, _signed_in in _FixtureApp.log)


def test_an_anonymous_crawl_keeps_its_single_input(fixture_app):
    captured = _crawl(fixture_app, capability="web.crawl", signed_in=False,
                      seeds=[*HUB_SEEDS, ("GET", "/hub/", "known_endpoints")])
    assert "crawl_seed_paths" not in captured["scanner_options"]
    assert _inputs(captured["argv"]) == [captured["execution_target"]]


# --- the page the sign-in landed on -------------------------------------------------------------

def _form_login(location, *, action="/hub/login"):
    from capabilities.auth import TargetBoundSessionCredential, establish_target_bound_http_session
    from tests.test_auth_session_capability import TARGET as AUTH_TARGET, _private_response

    async def request_executor(origin, args, **kwargs):
        if args["method"] == "GET":
            response = _private_response(200, body=(
                f'<form action="{action.replace("&", "&amp;")}" method="post">'
                '<input name="username"><input type="password" name="password"></form>'))
        else:
            response = _private_response(
                303, headers={"location": location} if location else {}, cookies={"hub": "session-canary"},
                final_url="https://app.example.test/hub/login")
        kwargs["private_response_sink"](response)
        return {"ok": True, "request": {"method": args["method"], "path": args["path"]}}

    credential = TargetBoundSessionCredential(
        lane="primary", auth_kind="form_login", endpoint_url="/hub/login",
        binding_digest="a" * 64, username="operator", secret="password-canary",
    )
    session = asyncio.run(establish_target_bound_http_session(
        credential, target=AUTH_TARGET, request_executor=request_executor))
    return session.execution_result()["observation"]


@pytest.mark.parametrize("location,landing", [
    ("/hub/", "/hub/"),
    ("https://app.example.test/hub/home?welcome=1", "/hub/home"),
    ("dashboard", "/hub/dashboard"),
])
def test_a_sign_in_redirect_records_the_landing_path(location, landing):
    observation = _form_login(location)
    assert observation["status"] == "established"
    assert observation["landing_path"] == landing


@pytest.mark.parametrize("location", [
    None, "https://elsewhere.test/hub/", "/hub/logout", "/hub/confirm/9f8e7d6c5b4a39281706f5e4d3c2b1a0",
])
def test_no_landing_path_for_another_origin_an_action_or_a_token(location):
    observation = _form_login(location)
    assert observation["status"] == "established"
    assert "landing_path" not in observation

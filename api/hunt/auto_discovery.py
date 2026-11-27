"""Discovery a web Hunt runs on its own at start, so coverage does not depend on planner discipline.

Measured Hunts mapped almost nothing: agents rarely called crawling, content discovery or the
template pack, and most of the target surface was never requested. Mapping is not a judgement
call, so the engine does it itself when a web or API Hunt starts:

* **Crawl** the target anonymously and, when the Hunt selected signed-in principals and holds the
  approval that lets them be used, once as each of them (``web.crawl``).
* **Content discovery** with the bundled ``corporate``, ``api`` and ``admin`` lists
  (``web.content_discover``; ``corporate`` reads the common list first).
* **Description and product probes**: one read-only GET per conventional API description
  location (OpenAPI/Swagger), hint file (robots.txt, llms.txt, security.txt), GraphQL endpoint and
  well-known identity path of common self-hosted products (CI servers, notebook and ML platforms,
  application servers, database admin consoles, CMSs, framework debug tools, container and cluster
  APIs, AI gateways), measured against a negative control (a path that cannot exist) the way
  content discovery is. A product that answers gets its known sensitive routes probed the same way.
  Every hit enters the target's endpoint inventory; a small API description is parsed into routes.
* **Exposure probes**: one GET per secret-bearing file a deployment commonly leaves in a web root
  (the Scan's exposure seeds, its thorough seeds, and credential, cloud, cluster, build and AI
  assistant files of the same kind), against the same negative control; a hit enters the
  inventory and the sweep reads and proves it.
* **Templates**: the Hunt's reviewed passive template pack once, when the Hunt may run it.

Every step is an ordinary capability call of the Hunt (``execute_hunt_capability``), so scope,
destination checks, pacing, budget reservation, approval and the action record are exactly what
the planner's own calls get, and each step has a fixed idempotency key, so a step is never run
twice. A step the Hunt may not run (not in its manifest, needing an approval the Hunt does not
hold, refused by the server) is skipped and named in the coverage report; nothing here asks a
person for anything. Long steps run one at a time, leaving the planner a long slot.

``SHAKERSCAN_HUNT_AUTO_DISCOVERY=false`` turns it off for the instance. Progress is process state:
a restarted API reports the steps that never ran as not run, and the planner can run them.

It runs only in a Hunt that holds active testing authority (``testing_authority``: active testing
with an approval). A passive Hunt keeps its zero authority: the engine adds no traffic to it, and
its planner maps what it chooses to.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
import json
import os
import re
import sys
from typing import Any
import hashlib
import uuid

from .server_sweep import Refused, Sweep, WirePace

# Web and API Hunts map their target; other kinds have no HTTP surface to map.
COVERAGE_TARGET_KINDS = frozenset({"web", "api"})

SETTING = "SHAKERSCAN_HUNT_AUTO_DISCOVERY"
KEY_PREFIX = "auto-discovery"
CONTENT_WORDLISTS = ("corporate", "api", "admin")
SIGNED_IN_WORDLISTS = ("corporate", "api")
MAX_SIGNED_IN_CRAWLS = 2
# Every probe path is sent at most once (probe_paths(): about 300); this is the work budget.
MAX_PROBES = 400
PROBE_CONCURRENCY = 8
# A probe answer within this share of the control's length (same status) is the control's page.
CONTROL_LENGTH_TOLERANCE = 0.05
# Discovery and the sweep never outlive the Hunt's own wall; a Hunt without one gets this.
MAX_DISCOVERY_SECONDS = 24 * 3600

SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api-docs.json",
    "/swagger/v1/swagger.json", "/openapi.yaml", "/swagger.yaml", "/api/openapi.json",
    "/api/swagger.json", "/api/v1/openapi.json", "/docs", "/redoc",
)
HINT_PATHS: tuple[str, ...] = (
    "/robots.txt", "/llms.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
)
GRAPHQL_PATHS: tuple[str, ...] = ("/graphql", "/api/graphql", "/graphql/v1", "/graphql/v2", "/graphiql")
try:
    from capabilities.exposure_probe import SENSITIVE_SEED_PATHS, THOROUGH_SEED_PATHS
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.exposure_probe import SENSITIVE_SEED_PATHS, THOROUGH_SEED_PATHS
# Secret-bearing files of the same kind as the Scan's exposure seeds: cloud, cluster, container
# and database credentials, framework secrets, infrastructure state, CI and build manifests,
# private keys, shell history and logs. Each is a commonly published exposure check (public
# content-discovery wordlists and exposure template collections), not any one application's file.
EXTRA_EXPOSURE_PATHS: tuple[str, ...] = (
    "/.aws/config", "/.docker/config.json", "/.kube/config", "/.pgpass", "/.my.cnf",
    "/config/secrets.yml", "/config/database.yml", "/config/master.key", "/terraform.tfvars",
    "/terraform.tfstate", "/.ssh/id_rsa", "/id_dsa", "/id_ed25519", "/package.json", "/composer.json",
    "/composer.lock", "/docker-compose.yml", "/Dockerfile", "/.gitlab-ci.yml", "/.travis.yml",
    "/.bash_history", "/error_log", "/debug.log", "/logs/", "/backup/", "/backups/",
    "/.vscode/settings.json", "/.env.example", "/storage/logs/laravel.log", "/wp-config.php~",
)
EXPOSURE_PATHS: tuple[str, ...] = tuple(dict.fromkeys(
    (*SENSITIVE_SEED_PATHS, *THOROUGH_SEED_PATHS, *EXTRA_EXPOSURE_PATHS)))


from .products import PRODUCTS, Product  # noqa: F401 - re-exported: callers import them from here


_PRODUCT_BY_KEY = {product.key: product for product in PRODUCTS}
# Products recognised from the root page alone (no identity probe of their own).
_ROOT_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nextjs", re.compile(r"/_next/|__NEXT_DATA__|next\.js", re.I)),
    ("wordpress", re.compile(r"/wp-content/|/wp-includes/", re.I)),
    ("drupal", re.compile(r"drupal", re.I)),
    ("joomla", re.compile(r"joomla", re.I)),
    ("laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
)


def enabled() -> bool:
    return str(os.environ.get(SETTING, "true")).strip().lower() not in {"0", "false", "no", "off"}


def key_digest(key: str) -> str:
    """sha256 of an idempotency key, as the action record stores it (``idempotency_key_sha256``)."""
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()


def step_key(name: str) -> str:
    return f"{KEY_PREFIX}:{name}"


def _probe_key(path: str) -> str:
    # Deterministic per path: a repeated discovery (another API process) replays, never resends.
    return step_key("probe:" + uuid.uuid5(uuid.NAMESPACE_URL, path).hex[:16])


def control_path(hunt_id: str) -> str:
    """A path that cannot exist, fixed per Hunt so a replayed control sends the same request."""
    return "/.shakerscan-absent-" + uuid.uuid5(uuid.NAMESPACE_URL, f"control:{hunt_id}").hex[:12]


def probe_paths() -> tuple[str, ...]:
    """Every path the probe phase may send (it sends at most ``MAX_PROBES`` of them)."""
    paths: list[str] = ["/"]
    for path in (*SPEC_PATHS, *HINT_PATHS, *GRAPHQL_PATHS,
                 *(item for product in PRODUCTS for item in (*product.identity, *product.routes)),
                 *EXPOSURE_PATHS):
        if path not in paths:
            paths.append(path)
    return tuple(paths)


_STEP_NAMES = ("crawl", *(f"content:{name}" for name in CONTENT_WORDLISTS), "crawl:primary",
               "crawl:secondary", "templates", "probe:control", "browser_crawl",
               *(f"content:{name}:{slot}" for name in SIGNED_IN_WORDLISTS for slot in ("primary", "secondary")))
_PROBE_DIGESTS = frozenset(key_digest(_probe_key(path)) for path in probe_paths()) | {
    key_digest(step_key(name)) for name in _STEP_NAMES}


def probe_key_digests() -> frozenset[str]:
    """sha256 of the engine's own discovery keys: their answers are discovery, not testing."""
    return _PROBE_DIGESTS


# --- process state ------------------------------------------------------------------------------

_STATE: dict[str, dict[str, Any]] = {}
_TASKS: set[asyncio.Task] = set()
# The running discovery task per Hunt, so a finish can stop it (``stop``).
_TASK_BY_HUNT: dict[str, asyncio.Task] = {}


def testing_authority(run: Mapping[str, Any] | None) -> bool:
    """Whether a Hunt's policy lets the engine test on its own: active testing with an approval.

    A passive Hunt (zero authority) gets no engine discovery or sweep, never waits for one at
    finish, and is never refused a finish for open coverage it has no checks to close."""
    policy = _json((run or {}).get("policy_json", (run or {}).get("policy")), {})
    return bool(policy.get("active_testing")) and bool(policy.get("approval_receipt_id"))


def discovery_state(hunt_id: str) -> dict[str, Any]:
    """This process's record of a Hunt's discovery: step outcomes, products, notes, running."""
    state = _STATE.get(str(hunt_id))
    return json.loads(json.dumps(state)) if state else {}


def _note(state: dict[str, Any], text: str) -> None:
    notes = state.setdefault("notes", [])
    if len(notes) < 20 and text not in notes:
        notes.append(text[:300])


# --- planning -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    name: str
    capability: str
    input: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return step_key(self.name)


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return default
    return value if isinstance(value, type(default)) else default


def signed_in_slots(run: Mapping[str, Any]) -> list[str]:
    """The principal slots the Hunt selected (``primary``, ``secondary``), when it may use them."""
    policy = _json(run.get("policy_json"), {})
    if not policy.get("credential_access") or not policy.get("approval_receipt_id"):
        return []
    context = _json(run.get("context_pack"), {})
    slots: list[str] = []
    for item in context.get("credential_refs") or ():
        if not isinstance(item, Mapping) or item.get("source") != "credential_profiles":
            continue
        slot = str(item.get("principal_slot") or "")
        if slot in {"primary", "secondary"} and slot not in slots:
            slots.append(slot)
    return slots[:MAX_SIGNED_IN_CRAWLS]


def plan_steps(run: Mapping[str, Any]) -> tuple[list[Step], list[str]]:
    """The long steps for one Hunt and the reasons steps were left out."""
    if str(run.get("target_kind") or "") not in COVERAGE_TARGET_KINDS:
        return [], []
    policy = _json(run.get("policy_json"), {})
    allowed = {str(name) for name in policy.get("allowed_capabilities") or ()}
    steps: list[Step] = []
    skipped: list[str] = []
    if "web.crawl" in allowed:
        steps.append(Step("crawl", "web.crawl"))
    else:
        skipped.append("crawl: web.crawl is not in this Hunt's capabilities")
    if "web.content_discover" in allowed:
        steps.extend(Step(f"content:{name}", "web.content_discover", {"wordlist": name})
                     for name in CONTENT_WORDLISTS)
    else:
        skipped.append("content discovery: web.content_discover is not in this Hunt's capabilities")
    if "web.crawl" in allowed:
        steps.extend(Step(f"crawl:{slot}", "web.crawl", {"as_principal": slot})
                     for slot in signed_in_slots(run))
    if "web.content_discover" in allowed:
        # What only a signed-in role sees: content discovery as each selected principal.
        steps.extend(Step(f"content:{name}:{slot}", "web.content_discover",
                          {"wordlist": name, "as_principal": slot})
                     for slot in signed_in_slots(run) for name in SIGNED_IN_WORDLISTS)
    if "web.browser_crawl" in allowed:
        # The routes the application's own scripts call at runtime.
        steps.append(Step("browser_crawl", "web.browser_crawl"))
    if "templates.scan" in allowed and policy.get("active_testing") and policy.get("approval_receipt_id"):
        steps.append(Step("templates", "templates.scan"))
    elif "templates.scan" in allowed:
        skipped.append("templates: templates.scan needs active testing and the Hunt's approval")
    return steps, skipped


# --- probe evaluation ---------------------------------------------------------------------------

def _observation(result: Any) -> Mapping[str, Any] | None:
    if not isinstance(result, Mapping):
        return None
    action = result.get("action_result") if isinstance(result.get("action_result"), Mapping) else {}
    for item in action.get("observations") or ():
        if isinstance(item, Mapping) and isinstance(item.get("response"), Mapping):
            return item["response"]
    return None


def answer_of(result: Any) -> dict[str, Any] | None:
    """(status, length, text, content type) of one probe's answer, or None when nothing came back."""
    response = _observation(result)
    if response is None or not isinstance(response.get("status"), int):
        return None
    html = response.get("html") if isinstance(response.get("html"), Mapping) else {}
    text = " ".join(str(part) for part in (
        response.get("body_sample") or "", html.get("title") or "",
        " ".join(str(key) for key in response.get("json_keys") or ()),
        " ".join(f"{k}: {v}" for k, v in (response.get("security_headers") or {}).items()),
    ))
    length = response.get("bytes_observed")
    return {
        "status": int(response["status"]),
        "length": int(length) if isinstance(length, int) else len(str(response.get("body_sample") or "")),
        "text": text[:4000],
        "content_type": str(response.get("content_type") or ""),
        "location": str(response.get("location") or ""),
        "complete": response.get("body_digest_scope") == "complete" and not response.get("truncated"),
        "body": str(response.get("body_sample") or ""),
    }


def present(answer: Mapping[str, Any] | None, control: Mapping[str, Any] | None) -> bool:
    """Whether a probe found something: not absent, not the server's answer for absent paths."""
    if not answer:
        return False
    status = int(answer["status"])
    # A rate-limit answer (429) says nothing about the path.
    if status in {404, 410, 429} or status >= 500 or status == 400 and not answer.get("text"):
        return False
    if 300 <= status < 400:
        # A redirect to a sign-in or the same place every absent path goes is not a route.
        return bool(control) and int(control["status"]) != status
    if control and int(control["status"]) == status:
        control_length = int(control.get("length") or 0)
        length = int(answer.get("length") or 0)
        if abs(length - control_length) <= max(16, CONTROL_LENGTH_TOLERANCE * max(length, control_length)):
            return False
    return True


def matches_marker(product: Product, answer: Mapping[str, Any]) -> bool:
    if product.marker is None:
        return True
    return bool(re.search(product.marker, str(answer.get("text") or ""), re.I))


def graphql_answer(answer: Mapping[str, Any] | None) -> bool:
    if not answer:
        return False
    text = str(answer.get("text") or "")
    return bool(re.search(r"graphql|\berrors\b|must provide (a )?query|query string|graphiql", text, re.I))


def root_products(answer: Mapping[str, Any] | None) -> list[str]:
    text = str((answer or {}).get("text") or "")
    return [key for key, pattern in _ROOT_MARKERS if pattern.search(text)]


# --- running ------------------------------------------------------------------------------------

Executor = Callable[[str, str, Mapping[str, Any], str], Awaitable[Any]]
Recorder = Callable[[str, list[str], str], Awaitable[int]]


class _Refused(Exception):
    pass


# Wired by the composition root (``configure_auto_discovery``): this module imports no router.
_DEFAULTS: dict[str, Callable[..., Awaitable[Any]]] = {}


def configure_auto_discovery(*, execute: Executor, record: Recorder,
                             load_run: Callable[[str], Awaitable[Mapping[str, Any] | None]],
                             load_report: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None = None,
                             create_candidate: Callable[[str, Mapping[str, Any]], Awaitable[Any]] | None = None,
                             finish: Callable[..., Awaitable[Any]] | None = None,
                             request_permission: Callable[..., Awaitable[str]] | None = None) -> None:
    """Wire the Hunt capability call, the inventory write, the run read, and for the sweep the
    coverage read, candidate recording, the deferred finish and its own permission requests
    (composition root)."""
    _DEFAULTS.update(execute=execute, record=record, load_run=load_run)
    for name, value in (("load_report", load_report), ("create_candidate", create_candidate), ("finish", finish),
                        ("request_permission", request_permission)):
        if value is not None:
            _DEFAULTS[name] = value


def sweep_running(hunt_id: str) -> bool:
    """Whether this process is still running the Hunt's discovery or sweep."""
    return bool((_STATE.get(str(hunt_id)) or {}).get("running"))


def sweep_following(hunt_id: str) -> bool:
    """Whether the Hunt's sweep has tested what was mapped and now only follows the planner."""
    state = _STATE.get(str(hunt_id)) or {}
    return bool(state.get("running")) and state.get("sweep") == "following"


def stop(hunt_id: str) -> bool:
    """Stop a Hunt's discovery and sweep: no further call is made, and the call in flight is
    cancelled (a worker job is told through its cancel key and settles itself). True when there
    was something running to stop."""
    state = _STATE.get(str(hunt_id)) or {}
    task = _TASK_BY_HUNT.get(str(hunt_id))
    if not state.get("running") or task is None or task.done():
        return False
    state["stopping"] = True
    state.pop("deferred_finish", None)
    _note(state, "discovery stopped: the planner finished and the Hunt holds no testing authority")
    task.cancel()
    return True


async def wait_stopped(hunt_id: str, *, timeout: float) -> bool:
    """Wait (bounded) for a stopped Hunt's discovery task to end; True when it has."""
    task = _TASK_BY_HUNT.get(str(hunt_id))
    if task is None or task.done():
        return True
    done, _pending = await asyncio.wait({task}, timeout=max(0.0, timeout))
    return bool(done)


def defer_finish(hunt_id: str, *, summary: str, next_actions: list[str], reason: str | None) -> dict[str, Any]:
    """Record the planner's finish; the Hunt finishes with it when the server sweep ends."""
    state = _STATE.setdefault(str(hunt_id), {})
    state["deferred_finish"] = {"summary": summary, "next_actions": list(next_actions),
                                "reason": (reason or "").strip() or None}
    return dict(state["deferred_finish"])


async def _not_configured(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError("auto discovery is not configured")


def _refusal_text(exc: BaseException) -> str:
    detail = getattr(exc, "detail", None)
    if isinstance(detail, Mapping):
        detail = detail.get("message") or detail.get("detail") or json.dumps(detail)[:200]
    return str(detail or type(exc).__name__)[:200]


def _live(run: Mapping[str, Any] | None) -> bool:
    return bool(run) and str(run.get("status")) in {"active", "awaiting_planner"} and not run.get("completed_at")


class DiscoveryRunner:
    """Runs one Hunt's start-of-Hunt discovery through its own capability calls."""

    def __init__(self, hunt_id: str, *, execute: Executor | None = None, record: Recorder | None = None,
                 load_run: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None = None,
                 load_report: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None = None,
                 create_candidate: Callable[[str, Mapping[str, Any]], Awaitable[Any]] | None = None,
                 finish: Callable[..., Awaitable[Any]] | None = None) -> None:
        self.hunt_id = str(hunt_id)
        self._execute = execute or _DEFAULTS.get("execute") or _not_configured
        self._record = record or _DEFAULTS.get("record") or _not_configured
        self._load_run = load_run or _DEFAULTS.get("load_run") or _not_configured
        self._load_report = load_report if load_report is not None else _DEFAULTS.get("load_report")
        self._create_candidate = (create_candidate if create_candidate is not None
                                  else _DEFAULTS.get("create_candidate"))
        self._finish = finish if finish is not None else _DEFAULTS.get("finish")
        self.state = _STATE.setdefault(self.hunt_id, {})
        # One pace for discovery and the sweep: together they never start target requests faster
        # than the fastest wire rate a Hunt executor is held to (budget_pace).
        from .budget_pace import wire_requests_per_second
        self.pace = WirePace(wire_requests_per_second())

    async def _call(self, capability: str, values: Mapping[str, Any], key: str) -> Any:
        try:
            return await self._execute(self.hunt_id, capability, values, key)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a refused step is skipped, never fatal
            raise _Refused(_refusal_text(exc)) from exc

    async def run(self) -> dict[str, Any]:
        run = await self._load_run(self.hunt_id)
        if not _live(run) or str(run.get("target_kind")) not in COVERAGE_TARGET_KINDS:
            return self.state
        if not testing_authority(run):
            _note(self.state, "engine discovery runs only in a Hunt with active testing authority")
            return self.state
        steps, skipped = plan_steps(run)
        for reason in skipped:
            _note(self.state, reason)
        self.state["running"] = True
        for step in steps:
            self.state[step.name] = "queued"
        policy = _json(run.get("policy_json"), {})
        probes = "http.request" in set(policy.get("allowed_capabilities") or ())
        if probes:
            self.state["probes"] = "queued"
        try:
            await asyncio.gather(self._long_steps(steps), self._probe_phase(run) if probes else _nothing())
            await self._sweep()
        finally:
            self.state["running"] = False
            for step in [*steps, Step("probes", "http.request")]:
                if self.state.get(step.name) in {"queued", "running"}:
                    self.state[step.name] = "not_run"
            await self._finish_deferred()
        return self.state

    async def _sweep(self) -> None:
        """The engine's own checks over what discovery mapped (``server_sweep``)."""
        if self._load_report is None or self._create_candidate is None:
            return
        run = await self._load_run(self.hunt_id)
        if not _live(run):
            return
        report = await self._load_report(self.hunt_id)
        if not report:
            return

        async def call(capability: str, values: Mapping[str, Any], key: str) -> Any:
            try:
                return await self._call(capability, values, key)
            except _Refused as exc:
                raise Refused(str(exc)) from exc

        async def live() -> bool:
            return _live(await self._load_run(self.hunt_id))

        create = self._create_candidate
        ask = _DEFAULTS.get("request_permission")

        async def request_permission(flag: str, routes: list[str]) -> str:
            return await ask(self.hunt_id, flag, routes) if ask is not None else "unavailable"

        sweep = Sweep(call=call, create_candidate=lambda values: create(self.hunt_id, values),
                      state=self.state, live=live, pace=self.pace, request_permission=request_permission)
        target_id = str(run.get("target_id") or "")

        async def reload() -> Mapping[str, Any] | None:
            return await self._load_report(self.hunt_id)

        async def record(worklist: list[str]) -> Any:
            return await self._record(target_id, worklist, "hunt_sweep") if target_id else 0

        try:
            # The sweep follows the Hunt until the planner finishes (its finish is deferred while
            # the sweep runs): what the planner maps later gets the same checks.
            await sweep.run(run, report, load_report=reload, record=record,
                            planner_finished=lambda: bool(self.state.get("deferred_finish")))
        except asyncio.CancelledError:
            if self.state.get("sweep") != "stopped":
                raise
            _note(self.state, "sweep stopped: the Hunt ended")

    async def _finish_deferred(self) -> None:
        """Finish the Hunt with the planner's debrief once the engine's own work has ended."""
        deferred = self.state.get("deferred_finish")
        if not deferred or self._finish is None:
            return
        for _attempt in range(60):  # actions still settling hold a finish; wait for them, bounded
            run = await self._load_run(self.hunt_id)
            if not run or run.get("completed_at") or str(run.get("status")) not in {
                    "active", "awaiting_planner", "budget_exhausted"}:
                return
            try:
                await self._finish(self.hunt_id, summary=deferred["summary"],
                                   next_actions=deferred["next_actions"], force=True,
                                   force_reason=deferred.get("reason") or
                                   "the planner finished; the server sweep has ended")
                self.state["deferred_finish"] = {**deferred, "finished": True}
                return
            except Exception as exc:  # noqa: BLE001 - retried while actions settle
                if getattr(exc, "status_code", None) != 409:
                    _note(self.state, f"deferred finish failed: {type(exc).__name__}")
                    return
            await asyncio.sleep(10)

    async def _long_steps(self, steps: Sequence[Step]) -> None:
        for step in steps:
            if not _live(await self._load_run(self.hunt_id)):
                _note(self.state, "discovery stopped: the Hunt ended")
                return
            self.state[step.name] = "running"
            try:
                result = await self._call(step.capability, step.input, step.key)
            except _Refused as exc:
                self.state[step.name] = "skipped"
                _note(self.state, f"{step.name}: {exc}")
                continue
            status = str(((result or {}).get("action_result") or {}).get("status") or "done") \
                if isinstance(result, Mapping) else "done"
            self.state[step.name] = "done" if status in {"success", "partial", "done"} else status
        # Content discovery and the crawl settle into the target's endpoint inventory themselves.

    async def _probe(self, path: str) -> dict[str, Any] | None:
        await self.pace.take(1)
        result = await self._call("http.request", {"method": "GET", "path": path, "follow_redirects": False},
                                  _probe_key(path))
        return answer_of(result)

    async def _probe_phase(self, run: Mapping[str, Any]) -> None:
        self.state["probes"] = "running"
        target_id = str(run.get("target_id") or "")
        try:
            control = answer_of(await self._call(
                "http.request",
                {"method": "GET", "path": control_path(self.hunt_id), "follow_redirects": False},
                step_key("probe:control")))
            root = await self._probe("/")
        except _Refused as exc:
            self.state["probes"] = "skipped"
            _note(self.state, f"probes: {exc}")
            return
        found: list[str] = []
        products: list[str] = list(dict.fromkeys(root_products(root)))
        specs: list[tuple[str, dict[str, Any]]] = []
        sent = 2

        answers: dict[str, dict[str, Any] | None] = {"/": root}

        async def probe(path: str) -> dict[str, Any] | None:
            # A path two products share is sent once.
            nonlocal sent
            if path in answers:
                return answers[path]
            if sent >= MAX_PROBES or not _live(await self._load_run(self.hunt_id)):
                return None
            sent += 1
            try:
                answers[path] = await self._probe(path)
            except _Refused as exc:
                _note(self.state, f"probe {path}: {exc}")
                answers[path] = None
            return answers[path]

        gate = asyncio.Semaphore(PROBE_CONCURRENCY)

        async def prefetch(paths: Sequence[str]) -> None:
            # Each engine call waits about two seconds end to end, so probes go several at once;
            # the loops below then read the answers in order.
            async def one(path: str) -> None:
                async with gate:
                    await probe(path)
            await asyncio.gather(*(one(path) for path in dict.fromkeys(paths) if path not in answers))

        await prefetch([*SPEC_PATHS, *HINT_PATHS, *GRAPHQL_PATHS,
                        *(path for product in PRODUCTS for path in product.identity)])
        for path in (*SPEC_PATHS, *HINT_PATHS):
            answer = await probe(path)
            if present(answer, control):
                found.append(f"GET {path}")
                if path in SPEC_PATHS:
                    specs.append((path, answer))
        for path in GRAPHQL_PATHS:
            answer = await probe(path)
            if present(answer, control) or (answer and answer["status"] in {400, 405} and graphql_answer(answer)):
                found.append(f"GET {path}")
                found.append(f"POST {path}")
        product_paths: dict[str, list[str]] = {}
        for product in PRODUCTS:
            hit = False
            for path in product.identity:
                answer = await probe(path)
                if present(answer, control) and matches_marker(product, answer or {}):
                    found.append(f"GET {path}")
                    product_paths.setdefault(product.key, []).append(path)
                    hit = True
            if hit and product.key not in products:
                products.append(product.key)
        await prefetch([path for key in products for path in _PRODUCT_BY_KEY[key].routes])
        for key in products:
            for path in _PRODUCT_BY_KEY[key].routes:
                answer = await probe(path)
                if present(answer, control):
                    found.append(f"GET {path}")

        async def exposure(path: str) -> None:
            async with gate:
                answer = await probe(path)
            if present(answer, control):
                found.append(f"GET {path}")

        await asyncio.gather(*(exposure(path) for path in EXPOSURE_PATHS))
        routes = _spec_routes(specs, origin=_origin(run))
        if specs and not routes:
            for path, _answer in specs:
                _note(self.state, f"API description at {path}: read it (artifact.inspect) and test the routes it declares")
        self.state["products"] = products
        # Where each product answered: the sweep runs its templates there as well as at the root.
        self.state["product_paths"] = product_paths
        worklist = list(dict.fromkeys([*found, *routes]))
        if worklist and target_id:
            try:
                await self._record(target_id, worklist, "hunt_probe")
            except Exception as exc:  # noqa: BLE001 - inventory is a worklist; a write failure is reported
                _note(self.state, f"probe hits not recorded: {type(exc).__name__}")
        self.state["probe_hits"] = len(worklist)
        self.state["probes"] = "done"


async def _nothing() -> None:
    return None


def _origin(run: Mapping[str, Any]) -> str:
    context = _json(run.get("context_pack"), {})
    target = context.get("target") if isinstance(context.get("target"), Mapping) else {}
    return str(target.get("url") or run.get("target_url") or "").rstrip("/")


def _spec_routes(specs: Sequence[tuple[str, Mapping[str, Any]]], *, origin: str) -> list[str]:
    """``METHOD /path?params`` worklist entries from API descriptions whose body came back whole."""
    if not specs or not origin:
        return []
    try:
        from capabilities.spec_ingest import ingest_spec_bodies
    except ModuleNotFoundError:  # package import in host-side tests
        from ..capabilities.spec_ingest import ingest_spec_bodies
    documents = [(f"{origin}{path}", str(answer.get("body") or "").encode("utf-8"), answer.get("content_type"))
                 for path, answer in specs if answer.get("complete") and answer.get("body")
                 and int(answer.get("length") or 0) <= len(str(answer.get("body") or "").encode("utf-8"))]
    if not documents:
        return []
    try:
        records = ingest_spec_bodies(documents, origin=origin)
    except Exception:  # noqa: BLE001 - untrusted document
        return []
    out: list[str] = []
    for record in records[:500]:
        url = str(record.get("url") or "")
        path = url[len(origin):] if url.startswith(origin) else ""
        if not path.startswith("/") or " " in path:
            continue
        method = str(record.get("method") or "GET").upper()
        fields = [str(name) for name in record.get("body_field_names") or () if str(name)][:20]
        if fields and method in {"POST", "PUT", "PATCH"}:
            # The inventory's worklist form keeps the body's field names as its parameters.
            kind = "form" if "form" in str(record.get("content_type") or "") else "json"
            body = ("&".join(f"{name}=" for name in fields) if kind == "form"
                    else json.dumps({name: "" for name in fields}, separators=(",", ":")))
            out.append(f"{method} {path} {kind}:{body}")
        else:
            out.append(f"{method} {path}")
    return out


def _wall_left(run: Mapping[str, Any] | None) -> float:
    """Seconds until the Hunt's own wall runs out (``MAX_DISCOVERY_SECONDS`` without one)."""
    budget = _json((run or {}).get("budget_json"), {})
    limit = budget.get("max_duration_seconds")
    created = (run or {}).get("created_at")
    if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0 and hasattr(created, "timestamp"):
        import time
        return max(60.0, min(float(MAX_DISCOVERY_SECONDS), limit - (time.time() - created.timestamp())))
    return float(MAX_DISCOVERY_SECONDS)


def start(hunt_id: str, *, runner: DiscoveryRunner | None = None) -> asyncio.Task | None:
    """Schedule a started Hunt's discovery in the background. Never raises; returns the task."""
    if not enabled() or (runner is None and "execute" not in _DEFAULTS):
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    if str(hunt_id) in _STATE and _STATE[str(hunt_id)].get("running"):
        return None
    worker = runner or DiscoveryRunner(str(hunt_id))

    async def _run() -> None:
        try:
            run = await worker._load_run(worker.hunt_id)
            await asyncio.wait_for(worker.run(), _wall_left(run))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - discovery never breaks a Hunt
            worker.state["running"] = False
            _note(worker.state, f"discovery stopped: {type(exc).__name__}")
            print(f"[hunt] auto discovery stopped: {type(exc).__name__}", file=sys.stderr, flush=True)

    task = loop.create_task(_run())
    _TASKS.add(task)
    _TASK_BY_HUNT[str(hunt_id)] = task

    def _done(finished: asyncio.Task) -> None:
        _TASKS.discard(finished)
        if _TASK_BY_HUNT.get(str(hunt_id)) is finished:
            _TASK_BY_HUNT.pop(str(hunt_id), None)
        worker.state["running"] = False

    task.add_done_callback(_done)
    return task


__all__ = [
    "CONTENT_WORDLISTS", "DiscoveryRunner", "configure_auto_discovery", "PRODUCTS", "SETTING", "Step", "answer_of",
    "discovery_state", "enabled", "plan_steps", "present", "probe_key_digests", "probe_paths",
    "signed_in_slots", "start", "stop", "sweep_following", "sweep_running", "defer_finish", "testing_authority", "wait_stopped",
]

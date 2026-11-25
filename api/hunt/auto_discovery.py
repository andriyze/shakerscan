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
* **Templates**: the Hunt's reviewed passive template pack once, when the Hunt may run it.

Every step is an ordinary capability call of the Hunt (``execute_hunt_capability``), so scope,
destination checks, pacing, budget reservation, approval and the action record are exactly what
the planner's own calls get, and each step has a fixed idempotency key, so a step is never run
twice. A step the Hunt may not run (not in its manifest, needing an approval the Hunt does not
hold, refused by the server) is skipped and named in the coverage report; nothing here asks a
person for anything. Long steps run one at a time, leaving the planner a long slot.

``SHAKERSCAN_HUNT_AUTO_DISCOVERY=false`` turns it off for the instance. Progress is process state:
a restarted API reports the steps that never ran as not run, and the planner can run them.
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
import uuid

from .coverage_map import COVERAGE_TARGET_KINDS, key_digest

SETTING = "SHAKERSCAN_HUNT_AUTO_DISCOVERY"
KEY_PREFIX = "auto-discovery"
CONTENT_WORDLISTS = ("corporate", "api", "admin")
MAX_SIGNED_IN_CRAWLS = 2
MAX_PROBES = 160
# A probe answer within this share of the control's length (same status) is the control's page.
CONTROL_LENGTH_TOLERANCE = 0.05
# The whole discovery never outlives this (the slowest steps are bounded by their own walls).
MAX_DISCOVERY_SECONDS = 45 * 60

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


@dataclass(frozen=True)
class Product:
    """A product's identity probes, and the known sensitive routes probed once it answers."""

    key: str
    identity: tuple[str, ...]
    routes: tuple[str, ...] = ()
    # Text one identity answer must carry (in its body sample, title or JSON keys) to count;
    # without it, any answer distinct from the control counts.
    marker: str | None = None


PRODUCTS: tuple[Product, ...] = (
    Product("jenkins", ("/jenkins/api/json", "/jenkins/login", "/api/json"),
            ("/jenkins/script", "/jenkins/whoAmI/api/json", "/jenkins/asynchPeople/api/json",
             "/jenkins/people/api/json", "/jenkins/queue/api/json", "/jenkins/computer/api/json",
             "/script", "/whoAmI/api/json", "/asynchPeople/api/json"),
            marker=r"jenkins|hudson|_class"),
    Product("jupyter", ("/api/kernelspecs", "/api/status"),
            ("/api/kernels", "/api/sessions", "/api/terminals", "/api/contents", "/tree", "/lab"),
            marker=r"kernelspecs|kernels|started|last_activity|jupyter"),
    Product("ray", ("/api/cluster_status", "/api/version"),
            ("/api/jobs/", "/api/v0/nodes", "/api/v0/actors", "/api/v0/tasks", "/api/v0/logs",
             "/nodes?view=summary"),
            marker=r"ray|autoscaler|cluster_status"),
    Product("mlflow", ("/api/2.0/mlflow/experiments/search?max_results=1",
                       "/ajax-api/2.0/mlflow/experiments/search?max_results=1"),
            ("/api/2.0/mlflow/registered-models/search", "/ajax-api/2.0/mlflow/registered-models/search",
             "/api/2.0/mlflow/experiments/get-by-name?experiment_name=Default", "/get-artifact",
             "/model-versions/get-artifact"),
            marker=r"experiment"),
    Product("langflow", ("/api/v1/version", "/api/v1/auto_login"),
            ("/api/v1/flows/", "/api/v1/all", "/api/v1/users/whoami", "/api/v1/login",
             "/api/v1/validate/code", "/api/v1/custom_component"),
            marker=r"langflow|access_token|version"),
    Product("flowise", ("/api/v1/ping",), ("/api/v1/chatflows", "/api/v1/credentials", "/api/v1/apikey"),
            marker=r"pong"),
    Product("comfyui", ("/system_stats", "/api/system_stats"),
            ("/object_info", "/queue", "/history", "/api/queue", "/api/history", "/view",
             "/customnode/getlist", "/manager/queue/status"),
            marker=r"system|devices|comfyui|python_version"),
    Product("ollama", ("/api/version", "/api/tags"), ("/api/ps", "/api/show", "/ollama/api/tags"),
            marker=r"version|models"),
    Product("openai_api", ("/v1/models",), ("/v1/usage", "/v1/files", "/v1/chat/completions"),
            marker=r"\bdata\b|object|model"),
    Product("mcp", ("/mcp", "/.well-known/mcp.json"), ("/mcp/tools", "/mcp/resources"),
            marker=r"jsonrpc|tools|mcp|protocol"),
    Product("a2a", ("/.well-known/agent-card.json", "/.well-known/agent.json"), ("/a2a/tasks",),
            marker=r"skills|capabilities|agent"),
    Product("tomcat", ("/manager/html", "/manager/text/list", "/host-manager/html"),
            ("/manager/status", "/manager/text/serverinfo"), marker=None),
    Product("phpmyadmin", ("/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/dbadmin/", "/myadmin/"), (),
            marker=r"phpmyadmin|pma_"),
    Product("wordpress", ("/wp-login.php", "/wp-json/"),
            ("/wp-json/wp/v2/users", "/xmlrpc.php", "/readme.html", "/wp-content/debug.log",
             "/wp-config.php.bak", "/wp-config.php~", "/?author=1"),
            marker=r"wordpress|wp-|namespaces"),
    Product("drupal", ("/core/CHANGELOG.txt", "/CHANGELOG.txt", "/user/login"),
            ("/user/register", "/core/install.php", "/node/1"), marker=r"drupal"),
    Product("joomla", ("/administrator/manifests/files/joomla.xml", "/administrator/"),
            ("/api/index.php/v1/config/application?public=true", "/api/index.php/v1/users?public=true",
             "/configuration.php.bak"), marker=r"joomla"),
    Product("laravel", ("/_ignition/health-check", "/telescope", "/horizon", "/_debugbar/open"),
            ("/storage/logs/laravel.log", "/telescope/telescope-api/requests", "/telescope/requests",
             "/horizon/api/stats", "/_ignition/execute-solution"), marker=None),
    Product("spring", ("/actuator", "/actuator/health"),
            ("/actuator/env", "/actuator/mappings", "/actuator/configprops", "/actuator/logfile",
             "/actuator/beans", "/jolokia/list", "/jolokia/read"), marker=r"_links|status|UP"),
    Product("jolokia", ("/jolokia/", "/jolokia/version"), ("/jolokia/list", "/jolokia/read"),
            marker=r"jolokia|agent|protocol"),
    Product("docker_api", ("/_ping", "/version", "/v1.41/version"),
            ("/info", "/containers/json", "/images/json", "/v1.41/containers/json"),
            marker=r"ApiVersion|OK|Docker"),
    Product("container_registry", ("/v2/",), ("/v2/_catalog",), marker=None),
    Product("kubelet", ("/healthz", "/pods"), ("/runningpods/", "/configz", "/stats/summary", "/spec/"),
            marker=r"PodList|items|ok"),
    Product("kubernetes", ("/api", "/apis", "/k8s/clusters/local/api/v1/namespaces"),
            ("/api/v1/namespaces", "/api/v1/secrets", "/api/v1/pods"), marker=r"APIVersions|versions|kind"),
    Product("etcd", ("/v2/keys/", "/v3/version"), ("/v2/keys/?recursive=true", "/v2/members"),
            marker=r"etcd|node|action"),
    Product("consul", ("/v1/agent/self",), ("/v1/kv/?recurse", "/v1/catalog/services"), marker=r"Config|Member"),
    Product("elasticsearch", ("/_cluster/health",), ("/_cat/indices", "/_nodes"), marker=r"cluster_name"),
    Product("grafana", ("/api/health",), ("/api/datasources", "/api/users", "/api/snapshots"),
            marker=r"database|version"),
    Product("gitlab", ("/api/v4/version", "/users/sign_in"), ("/api/v4/projects", "/explore/projects", "/api/v4/users"),
            marker=r"gitlab|version"),
    Product("prometheus", ("/api/v1/status/buildinfo",), ("/api/v1/status/config", "/api/v1/targets", "/metrics"),
            marker=r"version|success"),
    Product("solr", ("/solr/admin/info/system?wt=json",), ("/solr/admin/cores?wt=json",), marker=r"solr|lucene"),
    Product("n8n", ("/rest/settings",), ("/rest/workflows", "/rest/credentials"), marker=r"data|n8n"),
    Product("exchange", ("/autodiscover/autodiscover.xml", "/EWS/Exchange.asmx", "/owa/"),
            ("/mapi/", "/rpc/", "/_vti_bin/"), marker=None),
    Product("php", ("/phpinfo.php", "/info.php"), ("/php.php", "/test.php", "/debug.php"),
            marker=r"phpinfo|PHP Version|php"),
    Product("apache_status", ("/server-status", "/server-info"), (), marker=r"Apache|Server"),
    Product("scim", ("/scim/v2/ServiceProviderConfig", "/scim/v2/Users"), ("/scim/v2/Groups",),
            marker=r"schemas|Resources|scim"),
    Product("odata", ("/odata/$metadata", "/api/$metadata"), ("/odata/Users",), marker=r"edmx|EntityType"),
    Product("nextjs", (), ("/api/auth/session", "/dashboard", "/admin"), marker=None),
)
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
                 *(item for product in PRODUCTS for item in (*product.identity, *product.routes))):
        if path not in paths:
            paths.append(path)
    return tuple(paths)


_PROBE_DIGESTS = frozenset(key_digest(_probe_key(path)) for path in probe_paths()) | {
    key_digest(step_key("probe:control"))}


def probe_key_digests() -> frozenset[str]:
    """sha256 of the probe idempotency keys: their answers are discovery, not the Hunt's testing."""
    return _PROBE_DIGESTS


# --- process state ------------------------------------------------------------------------------

_STATE: dict[str, dict[str, Any]] = {}
_TASKS: set[asyncio.Task] = set()


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
    if status in {404, 410} or status >= 500 or status == 400 and not answer.get("text"):
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


async def _default_execute(hunt_id: str, capability: str, values: Mapping[str, Any], key: str) -> Any:
    from .interaction_router import HuntCapabilityRequest, execute_hunt_capability
    return await execute_hunt_capability(
        hunt_id, capability, HuntCapabilityRequest(idempotency_key=key, input=dict(values)),
    )


async def _default_record(target_id: str, worklist: list[str], source: str) -> int:
    from .interaction_router import _pool
    try:
        import asm_inventory
    except ModuleNotFoundError:  # package import in host-side tests
        from .. import asm_inventory
    async with _pool().acquire() as conn:
        return await asm_inventory.upsert_endpoints(conn, target_id, worklist, source=source)


async def _load_run(hunt_id: str) -> Mapping[str, Any] | None:
    from .interaction_router import _pool
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", uuid.UUID(str(hunt_id)))
    return dict(row) if row else None


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
                 load_run: Callable[[str], Awaitable[Mapping[str, Any] | None]] | None = None) -> None:
        self.hunt_id = str(hunt_id)
        self._execute = execute or _default_execute
        self._record = record or _default_record
        self._load_run = load_run or _load_run
        self.state = _STATE.setdefault(self.hunt_id, {})

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
        finally:
            self.state["running"] = False
            for step in [*steps, Step("probes", "http.request")]:
                if self.state.get(step.name) in {"queued", "running"}:
                    self.state[step.name] = "not_run"
        return self.state

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
        for product in PRODUCTS:
            hit = False
            for path in product.identity:
                answer = await probe(path)
                if present(answer, control) and matches_marker(product, answer or {}):
                    found.append(f"GET {path}")
                    hit = True
            if hit and product.key not in products:
                products.append(product.key)
        for key in products:
            for path in _PRODUCT_BY_KEY[key].routes:
                answer = await probe(path)
                if present(answer, control):
                    found.append(f"GET {path}")
        routes = _spec_routes(specs, origin=_origin(run))
        if specs and not routes:
            for path, _answer in specs:
                _note(self.state, f"API description at {path}: read it (artifact.inspect) and test the routes it declares")
        self.state["products"] = products
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
        if path.startswith("/"):
            out.append(f"{str(record.get('method') or 'GET').upper()} {path}")
    return out


def start(hunt_id: str, *, runner: DiscoveryRunner | None = None) -> asyncio.Task | None:
    """Schedule a started Hunt's discovery in the background. Never raises; returns the task."""
    if not enabled():
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
            await asyncio.wait_for(worker.run(), MAX_DISCOVERY_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - discovery never breaks a Hunt
            worker.state["running"] = False
            _note(worker.state, f"discovery stopped: {type(exc).__name__}")
            print(f"[hunt] auto discovery stopped: {type(exc).__name__}", file=sys.stderr, flush=True)

    task = loop.create_task(_run())
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return task


__all__ = [
    "CONTENT_WORDLISTS", "DiscoveryRunner", "PRODUCTS", "SETTING", "Step", "answer_of",
    "discovery_state", "enabled", "plan_steps", "present", "probe_key_digests", "probe_paths",
    "signed_in_slots", "start",
]

"""The engine's own testing sweep over a web Hunt's mapped surface, after discovery.

Measured agents mapped little, requested little and finished early, whatever the coverage report
told them. So once discovery has mapped the target, the engine runs the deterministic checks
itself, as ordinary capability calls of the Hunt (same scope, destination checks, pacing, budget
reservation, approval and action record as the planner's own calls; fixed idempotency keys, so a
check never runs twice):

1. **Read every mapped endpoint** (one GET each, anonymously). An answer that carries a value the
   shared masking withholds as credential-shaped, a private key or a directory index becomes a
   ``data_exposure`` candidate citing that request, and ``candidate.verify`` proves it or not.
2. **Default credentials** on each sign-in it found (an HTML sign-in form's own fields, or a JSON
   login's ``username``/``password``): the built-in pairs through ``http.request`` bindings, under
   the default-credential module's server-side bounds (per-login attempt cap, pacing, stop at the
   first lockout or rate-limit sign). An accepted pair becomes a ``default_credentials`` candidate
   and ``candidate.verify`` proves it. Needs the Hunt's state-changing permission.
3. **Function-level authorization** (``authz.verify`` mode ``function``) on administrative routes,
   when the Hunt has a primary and a secondary principal.
4. **Injection verifiers**: ``xss.verify`` then ``sqli.verify`` on every endpoint parameter (query
   parameters; body fields when state-changing HTTP is allowed). They record proven findings
   themselves. They are long calls (an SQL injection verification takes minutes at its pace), so
   they run from a queue beside the rounds: a round queues them and goes on reading and verifying
   what the next round maps; the sweep ends when the rounds are done and the queue is drained.
5. **Request checks** (``request.verify``): every input of every endpoint gets the injection classes
   a deterministic differential proves (SQL, command, template, path traversal; SSRF, open redirect
   and CRLF for an input named like a URL or a redirect target), a GraphQL endpoint its GraphQL
   check, an XML endpoint XXE, a sign-in its rate-limit, LDAP and NoSQL checks, and the root and
   a bounded set of API answers their CORS and header checks. Each is a short action (seconds,
   tens of requests) run from a second queue beside the long verifiers; inputs whose name points
   at a class go first.
6. **API routes**: under each API root the mapped routes sit under (``/api``, ``/api/v1``, ...),
   one GET per authored route name (``route_words``), measured against a negative control under
   the same root; a distinct answer (405 included) enters the inventory for the next round.
7. **Product templates**: for every product discovery recognised (``products``), its own templates
   from the pinned bundle (``templates.scan`` with ``product``; ``runtime/product_templates.py``),
   at the root and at the path the product answered under. The read-only checks run right after
   the reads; the state-changing ones (non-GET and exploit-class templates) after the default
   credentials, when the Hunt may send writes. Each template match becomes a candidate citing the
   templates.scan action; an exposure match is handed to ``candidate.verify``.

Only checks a deterministic verifier settles run here; everything else stays on the coverage
report for the planner. A check the Hunt may not run (not in its capabilities, refused by the
server) is skipped and named. Nothing here asks a person for anything.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
import hashlib
import json
import re
import time
from typing import Any
import urllib.parse
import uuid

try:
    from runtime.product_templates import PRODUCT_MOUNTS, PRODUCT_TEMPLATE_TAGS, product_window_count
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.product_templates import PRODUCT_MOUNTS, PRODUCT_TEMPLATE_TAGS, product_window_count
from .route_words import API_ROUTE_WORDS, MAX_API_PREFIXES
try:
    from capabilities.product_api import product_api_for
except ModuleNotFoundError:  # package import in host-side tests
    from ..capabilities.product_api import product_api_for

KEY_PREFIX = "auto-sweep"
# Engine checks at once: leaves the planner a long slot (agent_job_concurrency gives a Hunt two
# long slots per agent-tool worker).
LONG_CONCURRENCY = 2
# Each engine call waits about two seconds end to end (measured: 80 calls a minute at three at
# once), so short calls go several at once.
SHORT_CONCURRENCY = 8
MAX_READS = 800
MAX_INJECTION_TARGETS = 400
MAX_FIELDS_PER_BODY = 4
MAX_AUTHZ_ROUTES = 50
# request.verify calls one sweep may queue (measured: about 3-40 requests and 1-20 s each).
MAX_REQUEST_CHECKS = 1_200
REQUEST_CONCURRENCY = 4
# CORS is usually one policy per origin: the root and a few API answers show it.
MAX_HEADER_CHECK_ROUTES = 5
# Routes that refuse GET (405) the sweep sends one empty JSON POST to learn their inputs.
MAX_SHAPE_PROBES = 200
MAX_SCRIPTS = 40
# HTML pages whose inline scripts the sweep analyzes for routes (one request each).
MAX_HTML_PAGES = 60
# Rounds of read-record-test; each round only tests what earlier rounds did not.
MAX_ROUNDS = 8
# Once its own rounds find nothing new the sweep follows the Hunt: it re-reads the coverage report
# and runs a round on whatever the planner's requests mapped since (routes, and inputs of routes
# already tested), until the planner finishes. The wait between two looks grows while nothing is new.
MAX_FOLLOW_ROUNDS = 60
FOLLOW_POLL_SECONDS = 15.0
FOLLOW_POLL_MAX_SECONDS = 120.0
DEFAULT_CREDENTIAL_PACE_SECONDS = 2.2
# Product-template and injection-verifier calls are long actions. While the Hunt's long-action
# slots are all taken (the planner's scanners, the sweep's own verifiers), admission refuses them:
# measured Hunts had 23 and 30 template refusals (one Hunt's every state-changing check among
# them) and 17-18 verifier refusals. Such a call waits for a slot instead: admission says retry
# after 60 s, and a verifier holds a slot for up to about 20 minutes.
LONG_SLOT_RETRY_SECONDS = 30.0
LONG_SLOT_WAIT_SECONDS = 1_800.0
_LONG_SLOTS_TAKEN = re.compile(r"long actions in flight", re.I)
DEFAULT_PAIR_IDS = tuple(f"dc-{index:02d}" for index in range(1, 21))
_SECRET_TEXT = re.compile(
    r"\[withheld:\d+\]|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|"
    r"<title>\s*index of /|\bindex of /", re.I)
# A field or setting named like a secret, with a value: "password": "...", DB_PASSWORD=..., token: ...
_SECRET_FIELD = re.compile(
    r"""(?ix)["']?\b[\w.-]*(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|private[_-]?key|
    token|credential|connection[_-]?string|password_hash)\b["']?\s*[:=]\s*["']?[^\s"',}{\]\[]{3,}""")
# JSON account records served to an anonymous caller (two or more objects with an email or username).
_RECORDS = re.compile(r'(?s)"(?:email|username|user_name|login)"\s*:\s*"[^"]+".*?"(?:email|username|user_name|login)"\s*:\s*"[^"]+"')
_LOGIN_PATH = re.compile(r"(?:^|/)(?:log-?in|sign-?in|auth(?:enticate)?|session|token)(?:/|$|\.)", re.I)
_USER_FIELDS = ("username", "user", "email", "login", "user_name", "userName")
# Input names that point at one class (request.verify checks); matched case-insensitively.
_URL_INPUT = re.compile(r"(?:^|_)(?:url|uri|link|href|src|source|feed|fetch|proxy|endpoint|webhook|callback|"
                        r"image_?url|site|host|domain|target|resource|remote)$", re.I)
_REDIRECT_INPUT = re.compile(r"^(?:redirect\w*|return\w*|next|continue|goto|go|dest|destination|forward|"
                             r"back|to|r|u|url|redir|out|exit|target|location|callback\w*)$", re.I)
_FILE_INPUT = re.compile(r"(?:^|_)(?:file\w*|path|filepath|dir|directory|folder|doc|document|download|"
                         r"attachment|include|inc|page|template|tpl|view|log\w*|img|image|load|read|"
                         r"preview|name|report|lang|locale)$", re.I)
_COMMAND_INPUT = re.compile(r"(?:^|_)(?:cmd|command|exec\w*|run|shell|host\w*|ip|addr\w*|ping|domain|"
                            r"target|server|lookup|query|arg\w*|opt\w*)$", re.I)
_TEMPLATE_INPUT = re.compile(r"(?:^|_)(?:template|tpl|tmpl|name|message|msg|text|content|body|greeting|"
                             r"subject|title|preview|expr\w*|q|search|bio|comment|note|description)$", re.I)
_XML_PATH = re.compile(r"(?:^|/|\.)(?:xml|soap|wsdl|rss|import|parse|svg)(?:/|$|\.)", re.I)
_RESET_PATH = re.compile(r"(?:reset|forgot|recover)[-_]?(?:password|pass|pw)?|password[-_/]?reset", re.I)
# A route whose name says it destroys, moves money or changes access is never sent the shape probe's
# empty POST (a route that needs no input would act on it); the planner decides those.
_DESTRUCTIVE_ROUTE = re.compile(
    r"(?:delete|remove|destroy|drop|purge|wipe|truncate|shutdown|restart|reboot|reset|restore|revoke|"
    r"cancel|withdraw|refund|transfer|pay(?:ment)?s?|purchase|checkout|approve|disable|deactivate|"
    r"unsubscribe|terminate|kill|stop|logout|signout|import|deploy|install|exec|run|build)", re.I)
_GRAPHQL_PATH = re.compile(r"(?:^|/)graph(?:i)?ql(?:/|$)", re.I)
# Routes whose anonymous answer the Scan's exposure classifier is worth running on (request.verify
# check exposure): a file name with an extension, a directory, a dot-path, or a name operators
# expose diagnostics under.
_EXPOSURE_ROUTE = re.compile(
    r"(?:/$|/\.[^/]+|\.[A-Za-z0-9~]{1,8}$|(?:^|/)(?:metrics|debug|status|server-status|server-info|info|"
    r"env|environment|trace|logs?|console|actuator(?:/[a-z]+)?|heapdump|dump|backups?|config|"
    r"configuration|settings|ftp|well-known)$)", re.I)
# An API root a route sits under: /api, /api/v1, /rest, /v2 ... (the sweep tries API_ROUTE_WORDS there).
_API_PREFIX = re.compile(r"^(/(?:api|rest|v[0-9]{1,2})(?:/v[0-9]{1,2})?)(?=/|$)", re.I)
# A framework's validation answer that names the inputs a route requires (FastAPI/pydantic
# ``"loc": ["query", "id"]``, and the plain "missing parameter 'x'" wording of other stacks).
_LOC_FIELD = re.compile(r'"loc"\s*:\s*\[\s*"(query|body|form)"\s*,\s*"([A-Za-z_][A-Za-z0-9_.-]{0,63})"')
_MISSING_FIELD = re.compile(r"(?:missing|required)\s+(?:required\s+)?(?:query\s+|body\s+|form\s+)?"
                            r"(?:param(?:eter)?|field|argument|value)s?\s*[:=]?\s*['\"`]?([A-Za-z_][A-Za-z0-9_.-]{0,63})", re.I)
_SECRET_FIELDS = ("password", "pass", "passwd", "pwd")

Call = Callable[[str, Mapping[str, Any], str], Awaitable[Any]]
CreateCandidate = Callable[[Mapping[str, Any]], Awaitable[Any]]


class Refused(Exception):
    """A check the server refused; it is skipped and named."""


# Requests one engine call of each kind sends to the target, as the wire pace charges them: an
# http.request is one; a request.verify check its usual run (baseline, repeat, control and the
# check's probes; measured 3-20). Long verifiers and templates run at their own tool rates.
_WIRE_COST = {"http.request": 1, "candidate.verify": 3, "authz.verify": 6}
_CHECK_COST = {"exposure": 3, "unauthenticated_api": 3, "directory_listing": 3, "security_headers": 2,
               "cors": 6, "host_header_injection": 6, "sql_injection": 12, "nosql_injection": 10,
               "ldap_injection": 6, "rate_limit": 13, "graphql": 10, "command_injection": 14,
               "path_traversal": 8, "template_injection": 6, "ssrf": 6, "xxe": 6, "open_redirect": 6,
               "crlf_injection": 6}


class WirePace:
    """The engine's own calls of one Hunt (discovery probes and the sweep) start no faster than
    ``rate`` target requests a second, whatever their concurrency: a call waits until the
    requests it will send fit. ``rate`` is the fastest wire rate any Hunt executor is held to."""

    def __init__(self, rate: float) -> None:
        self.rate = max(1.0, float(rate))
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def take(self, requests: int) -> None:
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + max(1, int(requests)) / self.rate
        if start > now:
            await asyncio.sleep(start - now)


def wire_cost(capability: str, values: Mapping[str, Any]) -> int:
    if capability == "request.verify":
        return _CHECK_COST.get(str(values.get("check") or ""), 10)
    return _WIRE_COST.get(capability, 0)


def sweep_key(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{KEY_PREFIX}:{parts[0]}:{digest}"


def concrete(route: str) -> str:
    """A requestable path for an inventory route: template segments take the value 1."""
    return re.sub(r"\{[^/{}]*\}", "1", route)


def _response(result: Any) -> Mapping[str, Any]:
    action = result.get("action_result") if isinstance(result, Mapping) else None
    for item in (action or {}).get("observations") or ():
        if isinstance(item, Mapping) and isinstance(item.get("response"), Mapping):
            return item["response"]
    return {}


def _action_id(result: Any) -> str | None:
    if not isinstance(result, Mapping):
        return None
    return str(result.get("action_id") or (result.get("action_result") or {}).get("action_id") or "") or None


def exposure_signal(response: Mapping[str, Any]) -> str | None:
    """Why an answer exposes something a verifier can settle, or None."""
    status = response.get("status")
    if not isinstance(status, int) or status >= 300:
        return None
    text = str(response.get("body_sample") or "")
    html = response.get("html") if isinstance(response.get("html"), Mapping) else {}
    text += " " + str(html.get("title") or "") + " " + str(html.get("text_sample") or "")
    keys = " ".join(f'"{key}":' for key in response.get("json_keys") or ())
    # An HTML page carries withheld values as a matter of course (a form's anti-forgery token, a
    # session nonce in a script): on a page only a key, a provider key id or an index is a signal.
    page = any(html.get(name) for name in ("title", "forms", "links", "text_sample"))
    for match in _SECRET_TEXT.finditer(text):
        found = match.group(0).lower()
        if "index of" in found:
            return "a directory index"
        if "private key" in found:
            return "a private key"
        if not page or not found.startswith("[withheld"):
            return "credential-shaped values"
    if _SECRET_FIELD.search(text) or _SECRET_FIELD.search(keys):
        return "secret-named fields"
    if not html and _RECORDS.search(text):
        return "account records"
    return None


def login_form(response: Mapping[str, Any]) -> tuple[str, str, str] | None:
    """``(action path, user field, secret field)`` of a sign-in form in an HTML answer."""
    html = response.get("html") if isinstance(response.get("html"), Mapping) else {}
    for form in html.get("forms") or ():
        if not isinstance(form, Mapping) or str(form.get("method") or "").upper() != "POST":
            continue
        fields = [field for field in form.get("fields") or () if isinstance(field, Mapping)]
        secret = next((str(f.get("name")) for f in fields if str(f.get("type")) == "password" and f.get("name")), None)
        user = next((str(f.get("name")) for f in fields
                     if str(f.get("type") or "text") in {"text", "email"} and f.get("name")), None)
        if secret and user and str(form.get("action") or "").startswith("/"):
            return str(form["action"]).split("?", 1)[0], user, secret
    return None


def required_inputs(response: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(location, name)`` of the inputs a 400/422 answer says the route requires."""
    if response.get("status") not in {400, 422}:
        return []
    text = str(response.get("body_sample") or "")
    found = [(location, name) for location, name in _LOC_FIELD.findall(text)]
    if not found:
        found = [("query", name) for name in _MISSING_FIELD.findall(text)
                 if name.lower() not in {"param", "parameter", "field", "value", "the", "a", "an"}]
    unique: list[tuple[str, str]] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique[:12]


def input_checks(name: str, method: str) -> list[tuple[int, str]]:
    """``(rank, check)`` request.verify runs on one input: the classes its name points at
    (rank 0, open redirect's CRLF twin rank 1), then the injection classes every input gets (rank 2)."""
    read = method == "GET"
    named: list[str] = []
    if read and _REDIRECT_INPUT.match(name):
        named.append("open_redirect")
    if read and _URL_INPUT.search(name):
        named.append("ssrf")
    if read and _FILE_INPUT.search(name):
        named.append("path_traversal")
    if _COMMAND_INPUT.search(name):
        named.append("command_injection")
    if _TEMPLATE_INPUT.search(name):
        named.append("template_injection")
    checks = [(0, check) for check in named]
    if "open_redirect" in named:
        checks.append((1, "crlf_injection"))
    # The SQL injection proof takes a few requests; the long sqli.verify tool runs from its own queue.
    checks.append((1, "sql_injection"))
    generic = ("command_injection", "template_injection", *(("path_traversal",) if read else ()))
    checks += [(2, check) for check in generic if check not in named]
    return checks


def _default_credential_request(path: str, user: str, secret: str, pair: str, *, json_body: bool) -> dict[str, Any]:
    body = {user: "", secret: ""}
    return {
        "method": "POST", "path": path, "follow_redirects": False,
        ("json_body" if json_body else "form_body"): body,
        "request_bindings": [
            {"default_credential": pair, "credential_field": "username", "body_pointer": f"/{user}"},
            {"default_credential": pair, "credential_field": "secret", "body_pointer": f"/{secret}"},
        ],
    }


class Sweep:
    """One Hunt's sweep. ``call`` runs one capability call; ``create_candidate`` records one.

    The sweep runs in rounds until a round finds nothing new to test: each round reads the
    coverage report (``load_report``), runs every check no earlier round ran on each endpoint, and
    records what its reads revealed (same-origin links, routes in JavaScript) into the inventory
    (``record``), which the next round's report lists. Every pair it tests is remembered, so a
    round never repeats a check; its wall, rounds, endpoints and pairs are reported in
    ``sweep_stats``.

    With ``planner_finished`` (``run``) the sweep does not end when a round finds nothing new: it
    follows the Hunt (state ``following``), running a round on each route or input the planner's
    own requests reveal, and ends with a last look once the planner has finished.
    """

    def __init__(self, *, call: Call, create_candidate: CreateCandidate, state: dict[str, Any],
                 live: Callable[[], Awaitable[bool]], pace: WirePace | None = None) -> None:
        self._pace = pace
        self._call = call
        self._create = create_candidate
        self.state = state
        self._live = live
        self.counts: dict[str, int] = {}
        self.product_checks_run: set[str] = set()
        self.tested: set[tuple[str, str]] = set()  # pairs a sweep check ran on
        self.considered: set[tuple[str, str]] = set()  # pairs a round has looked at (never repeated)
        self.params_seen: dict[str, set[str]] = {}  # the inputs each endpoint had when a round looked at it
        self.logins: dict[str, tuple[str, str, str, bool]] = {}
        self.logins_tried: set[str] = set()
        self.signed_in_only: set[str] = set()
        self.seen: set[str] = set()
        self.js_done: set[str] = set()
        self.html_done: set[str] = set()
        self.started = time.monotonic()
        # The long-verifier queue: jobs run LONG_CONCURRENCY at a time beside the rounds.
        self._long_gate = asyncio.Semaphore(LONG_CONCURRENCY)
        self._long_jobs: set[asyncio.Task] = set()
        self.injection_queued = 0
        self.injection_done = 0
        self._request_gate = asyncio.Semaphore(REQUEST_CONCURRENCY)
        self.request_checks_queued = 0
        self.request_checks_done = 0
        self.request_checks_sent: set[str] = set()
        self.shape_probed: set[str] = set()
        self.signin_checked: set[str] = set()
        # The anonymous answer each read route gave (status, sample length, title), and the
        # mounts already queued for testing per route tail: one application served under several
        # mounts (/a/app.php, /b/app.php answering alike) is tested once.
        self.answers: dict[str, tuple[Any, int, str]] = {}
        self.mirror_tested: dict[tuple[str, str, tuple[Any, int, str]], str] = {}
        self.prefixes_tried: set[str] = set()
        self.request_verify = False
        self.sqli_tool = False
        self._long_keys: set[str] = set()

    def _count(self, name: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
        self.state["sweep_counts"] = dict(self.counts)

    def _stats(self, **extra: Any) -> None:
        stats = dict(self.state.get("sweep_stats") or {})
        stats.update(extra, seconds=int(time.monotonic() - self.started), pairs_tested=len(self.tested),
                     endpoints_seen=len(self.seen), injection_queued=self.injection_queued,
                     injection_done=self.injection_done, request_checks_queued=self.request_checks_queued,
                     request_checks_done=self.request_checks_done)
        self.state["sweep_stats"] = stats

    def _note(self, text: str) -> None:
        notes = self.state.setdefault("notes", [])
        if len(notes) < 40 and text not in notes:
            notes.append(text[:300])

    async def _safe(self, capability: str, values: Mapping[str, Any], key: str, *,
                    slot_wait_seconds: float = 0) -> Any:
        """One capability call; a refusal is counted and named. With ``slot_wait_seconds``, a
        refusal because the Hunt's long-action slots are all taken is retried (same key) once a
        slot may have settled, for at most that long."""
        waited = 0.0
        while True:
            if not await self._live():
                raise asyncio.CancelledError()
            try:
                if self._pace is not None and wire_cost(capability, values):
                    await self._pace.take(wire_cost(capability, values))
                result = await self._call(capability, values, key)
            except asyncio.CancelledError:
                raise
            except Refused as exc:
                if waited < slot_wait_seconds and _LONG_SLOTS_TAKEN.search(str(exc)):
                    await asyncio.sleep(LONG_SLOT_RETRY_SECONDS)
                    waited += LONG_SLOT_RETRY_SECONDS
                    continue
                self._count(f"{capability}:refused")
                self._note(f"{capability}: {exc}")
                return None
            self._count(capability)
            return result

    async def _candidate_and_verify(self, values: Mapping[str, Any], *, verify: bool = True) -> None:
        try:
            recorded = await self._create(values)
        except Exception as exc:  # noqa: BLE001 - a refused candidate is named, never fatal
            self._note(f"candidate {values.get('family')}: {type(exc).__name__}: {str(exc)[:120]}")
            return
        candidate = recorded.get("candidate") if isinstance(recorded, Mapping) else None
        candidate_id = str((candidate or {}).get("id") or "")
        if not candidate_id:
            return
        self._count("candidates")
        if not verify:
            return
        await self._safe("candidate.verify", {"candidate_id": candidate_id},
                         sweep_key("verify", candidate_id))

    async def run(self, run: Mapping[str, Any], report: Mapping[str, Any] | None = None, *,
                  load_report: Callable[[], Awaitable[Mapping[str, Any] | None]] | None = None,
                  record: Callable[[list[str]], Awaitable[Any]] | None = None,
                  planner_finished: Callable[[], bool] | None = None) -> None:
        policy = _json(run.get("policy_json"))
        allowed = {str(name) for name in policy.get("allowed_capabilities") or ()}
        writes = bool(policy.get("allow_state_changing_http"))
        slots = _signed_in_slots(run)
        self.request_verify = "request.verify" in allowed
        self.sqli_tool = "sqli.verify" in allowed
        templates = ("templates.scan" in allowed and bool(policy.get("active_testing"))
                     and bool(policy.get("approval_receipt_id")))
        self.state["sweep"] = "running"
        rounds = 0
        try:
            if templates:
                # The products discovery recognised are known before the first round.
                await self._product_templates("read_only")
            follow = planner_finished is not None and load_report is not None
            first, last_look, wait = report, False, FOLLOW_POLL_SECONDS
            while rounds < (MAX_ROUNDS + MAX_FOLLOW_ROUNDS if follow else MAX_ROUNDS):
                current = first if (rounds == 0 and first is not None) else (
                    await load_report() if load_report is not None else None)
                first = None
                if current is None:
                    break
                items = [item for item in current.get("open") or () if isinstance(item, Mapping)]
                fresh = [item for item in items if self._untested(item) or self._new_params(item)]
                if not fresh:
                    if not follow or last_look:
                        break
                    if planner_finished():
                        # One more look: what the planner's last requests mapped is tested too.
                        last_look = True
                        continue
                    if not await self._live():
                        break
                    self.state["sweep"] = "following"
                    waited = 0.0
                    while waited < wait and not planner_finished():  # a finish is noticed within a second
                        await asyncio.sleep(min(1.0, wait - waited))
                        waited += 1.0
                    wait = min(FOLLOW_POLL_MAX_SECONDS, wait * 1.5)
                    continue
                last_look, wait = False, FOLLOW_POLL_SECONDS
                self.state["sweep"] = "running"
                rounds += 1
                self._stats(rounds=rounds, endpoints_known=int(current.get("endpoints") or len(items)))
                found: list[str] = []
                if "http.request" in allowed:
                    found += await self._read_all(fresh, slots=slots, writes=writes)
                if "javascript.analyze" in allowed:
                    found += await self._javascript(items)
                if "http.request" in allowed and writes:
                    await self._default_credentials(request_checks="request.verify" in allowed)
                if "request.verify" in allowed:
                    self._request_checks(fresh, writes=writes, slots=slots, first=rounds == 1)
                if templates and writes and "state_changing" not in self.product_checks_run:
                    await self._product_templates("state_changing")
                if "authz.verify" in allowed and {"primary", "secondary"} <= set(slots):
                    await self._function_authz(fresh)
                await self._injection(fresh, allowed=allowed, writes=writes, slots=slots)
                if "http.request" in allowed:
                    # Last in the round: the checks queued above run while route names are tried
                    # (one engine call each, about a second apiece at the Hunt's call rate).
                    found += await self._api_routes(items)
                handled = {"review", "exposure", "unauthenticated_api", "default_credentials"}
                if {"primary", "secondary"} <= set(slots):
                    handled.add("function_authz")
                handled |= {klass for capability, klass in (("sqli.verify", "sqli"), ("xss.verify", "xss"))
                            if capability in allowed}
                if "request.verify" in allowed:
                    handled |= {"injection", "graphql"}
                for item in fresh:
                    self.params_seen.setdefault(str(item.get("endpoint")), set()).update(
                        str(name) for name in item.get("params") or ())
                    for klass in item.get("untested") or ():
                        pair = (str(item.get("endpoint")), str(klass))
                        self.considered.add(pair)
                        if klass in handled and (klass not in {"sqli", "xss", "injection"} or item.get("params")):
                            self.tested.add(pair)
                found = [entry for entry in dict.fromkeys(found) if entry not in self.seen]
                self.seen.update(found)
                if found and record is not None:
                    try:
                        await record(found)
                    except Exception as exc:  # noqa: BLE001 - the inventory is a worklist
                        self._note(f"sweep: discovered routes not recorded: {type(exc).__name__}")
                self._stats()
                if load_report is None:
                    break
            if templates and writes and "state_changing" not in self.product_checks_run:
                await self._product_templates("state_changing")
            # The rounds found nothing new; the queued long verifiers finish before the sweep does.
            self.state["sweep"] = "draining" if self._long_jobs else "running"
            while self._long_jobs:
                await asyncio.gather(*list(self._long_jobs))
            self.state["sweep"] = "done"
        except asyncio.CancelledError:
            self.state["sweep"] = "stopped"
            for job in list(self._long_jobs):
                job.cancel()
            raise
        finally:
            self._stats(rounds=rounds)

    def _untested(self, item: Mapping[str, Any]) -> list[str]:
        endpoint = str(item.get("endpoint") or "")
        return [str(klass) for klass in item.get("untested") or () if (endpoint, str(klass)) not in self.considered]

    def _new_params(self, item: Mapping[str, Any]) -> bool:
        """Whether an endpoint a round already looked at has since gained inputs (a later request
        of the planner's used them): its inputs are then tested like a new endpoint's."""
        seen = self.params_seen.get(str(item.get("endpoint") or ""))
        return seen is not None and any(str(name) not in seen for name in item.get("params") or ())

    async def _read_all(self, items: Sequence[Mapping[str, Any]], *, slots: Sequence[str],
                        writes: bool = False) -> list[str]:
        """GET every new endpoint (anonymously, then as each principal where anonymous is refused);
        record exposures; remember sign-ins; return same-origin links the answers carry."""
        gate = asyncio.Semaphore(SHORT_CONCURRENCY)
        links: list[str] = []
        targets = []
        for item in items[:MAX_READS]:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if not route.startswith("/"):
                continue
            if method == "GET":
                if route not in self.answers:  # an endpoint back for its new inputs was read already
                    targets.append(route)
            elif method == "POST" and "default_credentials" in (item.get("untested") or ()) and "/api" in route:
                self.logins.setdefault(route, (route, "username", "password", True))

        async def look(path: str, principal: str | None) -> Mapping[str, Any]:
            values = {"method": "GET", "path": path, "follow_redirects": False,
                      **({"as_principal": principal} if principal else {})}
            async with gate:
                result = await self._safe("http.request", values, sweep_key("read", path, principal or ""))
            response = _response(result)
            for link in (response.get("html") or {}).get("links") or () if isinstance(response.get("html"), Mapping) else ():
                text = str(link)
                if text.startswith("/") and not text.startswith("//") and len(text) < 500:
                    links.append(f"GET {text.split('#', 1)[0]}")
            form = login_form(response)
            if form:
                self.logins.setdefault(form[0], (form[0], form[1], form[2], False))
            links.extend(form_entries(response, path))
            links.extend(hint_entries(response, path))
            signal = exposure_signal(response)
            action = _action_id(result)
            status = response.get("status")
            if (self.request_verify and principal is None and isinstance(status, int) and 200 <= status < 300
                    and product_api_for(path) is not None):
                # A self-hosted product's management route answered an anonymous caller.
                self._queue_request_check({"check": "unauthenticated_api", "method": "GET", "path": path})
            if self.request_verify and principal is None and signal == "a directory index":
                # The listing proof: served twice, and not for a sibling directory that does not exist.
                self._queue_request_check({"check": "directory_listing", "method": "GET", "path": path})
            if (self.request_verify and principal is None and status == 200 and "?" not in path
                    and _EXPOSURE_ROUTE.search(path)):
                # The Scan's exposure classes (metrics, autoindex, debug pages, secret files ...).
                self._queue_request_check({"check": "exposure", "method": "GET", "path": path})
            if signal and action and not (principal and signal == "account records"):
                who = f"the {principal} principal" if principal else "an anonymous caller"
                await self._candidate_and_verify({
                    "family": "data_exposure",
                    "title": f"{path} serves {signal} to {who}",
                    "claim": (f"GET {path} as {who} answered {response.get('status')} with {signal} "
                              "(found by the engine's sweep of the mapped surface)."),
                    "severity": "high" if signal != "a directory index" else "medium",
                    "locus": {"method": "GET", "path": path, **({"principal": principal} if principal else {})},
                    "evidence_refs": [f"action:{action}"],
                })
            return response

        async def read(route: str) -> None:
            path = concrete(route)
            response = await look(path, None)
            html = response.get("html") if isinstance(response.get("html"), Mapping) else {}
            self.answers[route] = (response.get("status"), len(str(response.get("body_sample") or "")),
                                   str(html.get("title") or "")[:200])
            if _LOGIN_PATH.search(route) and response.get("status") in {405, 400} and "/api" in route:
                self.logins.setdefault(route, (route, "username", "password", True))
            if response.get("status") in {401, 403} and slots:
                self.signed_in_only.add(route)
                for slot in slots:
                    response = await look(path, slot)
            links.extend(self._shape_from(route, response, "GET"))
            if response.get("status") == 405 and writes and not _LOGIN_PATH.search(route):
                links.extend(await self._probe_shape(route, slots if route in self.signed_in_only else ()))

        await asyncio.gather(*(read(route) for route in targets))
        return links

    async def _api_routes(self, items: Sequence[Mapping[str, Any]]) -> list[str]:
        """Route names tried under each API root the mapped routes sit under (once per root)."""
        counts: dict[str, int] = {}
        for item in items:
            _method, _, route = str(item.get("endpoint") or "").partition(" ")
            match = _API_PREFIX.match(route)
            if match:
                counts[match.group(1)] = counts.get(match.group(1), 0) + 1
        # The roots most mapped routes sit under first.
        roots = sorted(counts, key=lambda root: (-counts[root], root))
        found: list[str] = []
        gate = asyncio.Semaphore(SHORT_CONCURRENCY)
        for root in roots:
            if root in self.prefixes_tried or len(self.prefixes_tried) >= MAX_API_PREFIXES:
                continue
            self.prefixes_tried.add(root)
            absent = f"{root}/shakerscan-absent-{uuid.uuid5(uuid.NAMESPACE_URL, 'route-control:' + root).hex[:10]}"
            control = _response(await self._safe("http.request", {"method": "GET", "path": absent,
                                                                  "follow_redirects": False},
                                                 sweep_key("route-control", root)))
            if not isinstance(control.get("status"), int):
                continue

            async def word(name: str, root: str = root, control: Mapping[str, Any] = control) -> None:
                path = f"{root}/{name}"
                async with gate:
                    answer = _response(await self._safe("http.request", {"method": "GET", "path": path,
                                                                         "follow_redirects": False},
                                                        sweep_key("route", path)))
                if _distinct(answer, control):
                    found.append(f"GET {path}")

            await asyncio.gather(*(word(name) for name in API_ROUTE_WORDS))
        self._stats(api_roots=sorted(self.prefixes_tried),
                    api_route_hits=int((self.state.get("sweep_stats") or {}).get("api_route_hits") or 0) + len(found))
        return found

    async def _javascript(self, items: Sequence[Mapping[str, Any]]) -> list[str]:
        """Routes the application's own JavaScript names (``javascript.analyze``)."""
        routes: list[str] = []
        # Scripts, and the HTML pages the reads found (their inline scripts call the same APIs).
        pages = [route for route, answer in self.answers.items()
                 if answer[0] == 200 and answer[2] and route not in self.html_done][:MAX_HTML_PAGES - len(self.html_done)]
        candidates = [str(item.get("endpoint") or "") for item in items] + [f"GET {route}" for route in pages]
        for endpoint in candidates:
            method, _, route = endpoint.partition(" ")
            script = route.endswith(".js")
            if method != "GET" or route in self.js_done or route in self.html_done:
                continue
            if script and len(self.js_done) >= MAX_SCRIPTS:
                continue
            if not script and route not in pages:
                continue
            (self.js_done if script else self.html_done).add(route)
            result = await self._safe("javascript.analyze", {"path": route}, sweep_key("javascript", route))
            action = (result or {}).get("action_result") if isinstance(result, Mapping) else None
            for observation in (action or {}).get("observations") or ():
                if isinstance(observation, Mapping) and observation.get("kind") == "javascript_analysis":
                    for found in observation.get("routes") or ():
                        text = str(found)
                        if text.startswith("/") and not text.startswith("//") and "[withheld" not in text:
                            routes.append(f"GET {text}")
        return routes

    async def _default_credentials(self, *, request_checks: bool = False) -> None:
        for path, (_path, user, secret, json_body) in list(self.logins.items())[:4]:
            if path in self.logins_tried:
                continue
            self.logins_tried.add(path)
            await self._try_default_pairs(path, user, secret, json_body)
            if request_checks:
                # After the default pairs: the rate-limit run's wrong passwords never lock them out.
                await self._signin_checks(path, user, secret, json_body)

    async def _try_default_pairs(self, path: str, user: str, secret: str, json_body: bool) -> None:
        for index, pair in enumerate(DEFAULT_PAIR_IDS):
            if index:
                # The default-credential module paces attempts on one login; keep to its pace.
                await asyncio.sleep(DEFAULT_CREDENTIAL_PACE_SECONDS)
            result = await self._safe(
                "http.request", _default_credential_request(path, user, secret, pair, json_body=json_body),
                sweep_key("default-credentials", path, pair))
            response = _response(result)
            verdict = str((response.get("login_attempt") or {}).get("verdict")
                          or ((result or {}).get("login_attempt") or {}).get("verdict") or "")
            if result is None or verdict in {"rate_limited", "locked", "not_sent"}:
                break
            action = _action_id(result)
            if verdict == "accepted" and action:
                await self._candidate_and_verify({
                    "family": "default_credentials",
                    "title": f"{path} accepts a built-in default credential pair",
                    "claim": f"The sign-in at {path} accepted the built-in pair {pair} (engine sweep).",
                    "severity": "critical",
                    "locus": {"method": "POST", "path": path},
                    "evidence_refs": [f"action:{action}"],
                })
                break

    async def _product_templates(self, checks: str) -> None:
        """Run each recognised product's own templates; every match becomes a candidate."""
        self.product_checks_run.add(checks)
        paths = self.state.get("product_paths") if isinstance(self.state.get("product_paths"), Mapping) else {}
        seen: set[tuple[str, str]] = set()
        for product in [str(key) for key in self.state.get("products") or () if key in PRODUCT_TEMPLATE_TAGS]:
            hits = [str(path) for path in paths.get(product) or ()]
            bases = ["/", *(mount for mount in PRODUCT_MOUNTS.get(product, ())
                            if any(hit.startswith(mount) for hit in hits))]
            for base in bases:
                for window in range(product_window_count(product, checks)):
                    values: dict[str, Any] = {"product": product, "product_checks": checks,
                                              "product_window": window}
                    if base != "/":
                        values["path"] = base
                    result = await self._safe("templates.scan", values,
                                              sweep_key("product", product, checks, base, str(window)),
                                              slot_wait_seconds=LONG_SLOT_WAIT_SECONDS)
                    action = _action_id(result)
                    for match in template_matches(result):
                        candidate = product_candidate(product, checks, match, action)
                        if candidate is None:
                            continue
                        identity = (str(match.get("template_id")), candidate["locus"]["path"])
                        if identity in seen:
                            continue
                        seen.add(identity)
                        self._count("product_template_matches")
                        # Only an exposure has a verifier that settles it from an anonymous read.
                        await self._candidate_and_verify(candidate, verify=candidate["family"] == "data_exposure")

    async def _function_authz(self, items: Sequence[Mapping[str, Any]]) -> None:
        routes = []
        for item in items:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if method == "GET" and "function_authz" in self._untested(item):
                routes.append(concrete(route))
        for start in range(0, len(routes), MAX_AUTHZ_ROUTES):
            chunk = routes[start:start + MAX_AUTHZ_ROUTES]
            await self._safe("authz.verify", {"mode": "function", "primary_principal": "primary",
                                              "secondary_principal": "secondary", "routes": chunk},
                             sweep_key("authz-function", *chunk))

    async def _injection(self, items: Sequence[Mapping[str, Any]], *, allowed: set[str], writes: bool,
                         slots: Sequence[str] = ()) -> None:
        jobs: list[tuple[str, dict[str, Any], str]] = []
        for item in items[:MAX_INJECTION_TARGETS]:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if self._mirror(method, route):
                self._count("mirror_skipped")
                continue
            params = [str(name) for name in item.get("params") or () if str(name)]
            # New inputs on an endpoint already looked at: the verifiers still open on it run again
            # (their keys carry the inputs, so no call repeats).
            untested = (set(str(klass) for klass in item.get("untested") or ()) if self._new_params(item)
                        else set(self._untested(item)))
            if not params or not route.startswith("/"):
                continue
            # A route that refuses anonymous callers is tested signed in, as the first principal.
            identity = {"as_principal": slots[0]} if route in self.signed_in_only and slots else {}
            # With request.verify the SQL injection proof screens each input first and the full tool
            # follows only where the screen saw the query break (``_queue_request_check``); a sign-in,
            # which the screen never probes, goes straight to the tool.
            screened = self.request_verify and not _LOGIN_PATH.search(route)
            for capability, klass in (("sqli.verify", "sqli"), ("xss.verify", "xss")):
                if capability not in allowed or klass not in untested or (capability == "sqli.verify" and screened):
                    continue
                if method == "GET":
                    jobs.append(_tool_job(capability, klass, method, route, params, None, identity))
                elif writes and method in {"POST", "PUT", "PATCH"}:
                    for field in params[:MAX_FIELDS_PER_BODY]:
                        jobs.append(_tool_job(capability, klass, method, route, params, field, identity))
        # XSS first on every target (about 20 s a call), then SQL injection (minutes a call): the
        # slower verifier never holds back the faster one.
        jobs.sort(key=lambda job: 0 if job[0] == "xss.verify" else 1)
        for job in jobs:
            self._queue_long(job)

    def _mirror(self, method: str, route: str) -> bool:
        """Whether ``route`` is another mount of a route already queued for testing: the same path
        after its first segment, answering the anonymous read exactly alike."""
        segments = route.split("/")
        answer = self.answers.get(route)
        if len(segments) < 3 or answer is None or not isinstance(answer[0], int) or answer[0] >= 400:
            return False
        key = (method, "/".join(segments[2:]), answer)
        first = self.mirror_tested.setdefault(key, route)
        return first != route

    def _shape_from(self, route: str, response: Mapping[str, Any], method: str) -> list[str]:
        """Inventory entries for the inputs a validation answer says ``route`` requires."""
        inputs = required_inputs(response)
        if not inputs:
            return []
        query = [name for location, name in inputs if location == "query"]
        body = [name for location, name in inputs if location in {"body", "form"}]
        entries: list[str] = []
        if query:
            entries.append(f"{method} {route}?" + "&".join(f"{name}=1" for name in query))
        if body and method != "GET":
            fields = {name.split(".")[-1]: "1" for name in body}
            entries.append(f"{method} {route} json:{json.dumps(fields, separators=(',', ':'))}")
        return entries

    async def _probe_shape(self, route: str, slots: Sequence[str]) -> list[str]:
        """A route that refuses GET (405): one POST with an empty JSON object, whose validation
        answer names the fields the route requires."""
        if (route in self.shape_probed or len(self.shape_probed) >= MAX_SHAPE_PROBES
                or _DESTRUCTIVE_ROUTE.search("/".join(route.split("/")[-2:]))):
            return []
        self.shape_probed.add(route)
        values = {"method": "POST", "path": concrete(route), "json_body": {}, "follow_redirects": False,
                  **({"as_principal": slots[0]} if slots else {})}
        result = await self._safe("http.request", values, sweep_key("shape", route))
        response = _response(result)
        entries = self._shape_from(route, response, "POST")
        if not entries and isinstance(response.get("status"), int) and response["status"] < 400:
            entries.append(f"POST {route}")
        return entries

    def _request_checks(self, items: Sequence[Mapping[str, Any]], *, writes: bool, slots: Sequence[str],
                        first: bool = False) -> None:
        """Queue request.verify on every input and endpoint the checks fit (short actions)."""
        jobs: list[tuple[int, dict[str, Any], tuple[str, dict[str, Any], str] | None]] = []
        if first:
            jobs += [(1, {"check": "cors", "method": "GET", "path": "/"}, None),
                     (1, {"check": "security_headers", "method": "GET", "path": "/"}, None),
                     (2, {"check": "host_header_injection", "method": "GET", "path": "/"}, None)]
        for item in items:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if not route.startswith("/") or method not in {"GET", "POST", "PUT", "PATCH"}:
                continue
            if method != "GET" and not writes:
                continue
            if self._mirror(method, route):
                continue
            untested = set(item.get("untested") or ())
            params = [str(name) for name in item.get("params") or () if str(name)]
            path = concrete(route)
            identity = {"as_principal": slots[0]} if route in self.signed_in_only and slots else {}
            if _GRAPHQL_PATH.search(route):
                jobs.append((0, {"check": "graphql", "method": "POST" if writes else "GET", "path": path, **identity}, None))
                continue
            if method == "GET" and "unauthenticated_api" in untested and \
                    sum(1 for _rank, job, _f in jobs if job["check"] == "cors") < MAX_HEADER_CHECK_ROUTES:
                jobs.append((2, {"check": "cors", "method": "GET", "path": path, **identity}, None))
            if method != "GET" and _XML_PATH.search(route):
                jobs.append((0, {"check": "xxe", "method": method, "path": path, **identity,
                                 "xml_body": '<?xml version="1.0"?><data><value>1</value></data>'}, None))
            if not params or _LOGIN_PATH.search(route):
                # A sign-in gets its own checks (_signin_checks); injection probes are never sent to one.
                continue
            if method == "GET":
                base: dict[str, Any] = {"method": "GET", "path": path, "query": {name: "1" for name in params[:10]}}
                names = params[:10]
            else:
                login = self.logins.get(route)
                body_key = "form_body" if login is not None and not login[3] else "json_body"
                base = {"method": method, "path": path, body_key: {name: "1" for name in params[:20]}}
                names = params[:MAX_FIELDS_PER_BODY]
                if _RESET_PATH.search(route):
                    jobs.append((1, {**base, **identity, "check": "host_header_injection"}, None))
            for name in names:
                for rank, check in input_checks(name, method):
                    follow = None
                    if check == "sql_injection" and self.sqli_tool:
                        follow = _tool_job("sqli.verify", "sqli", method, route, params,
                                           None if method == "GET" else name, identity)
                    jobs.append((rank, {**base, **identity, "check": check, "parameter": name}, follow))
        jobs.sort(key=lambda job: job[0])
        for _rank, values, follow in jobs:
            self._queue_request_check(values, follow_up=follow)

    async def _signin_checks(self, path: str, user: str, secret: str, json_body: bool) -> None:
        """A sign-in's own request checks: rate limiting, LDAP and NoSQL wildcards (request.verify)."""
        if path in self.signin_checked:
            return
        self.signin_checked.add(path)
        body = {user: "shakerscan-probe", secret: "shakerscan-probe-1"}
        base = {"method": "POST", "path": path, ("json_body" if json_body else "form_body"): body}
        self._queue_request_check({**base, "check": "rate_limit", "parameter": secret})
        self._queue_request_check({**base, "check": "ldap_injection", "parameter": user})
        if json_body:
            self._queue_request_check({**base, "check": "nosql_injection", "parameter": user})

    def _queue_request_check(self, values: Mapping[str, Any], *,
                             follow_up: tuple[str, dict[str, Any], str] | None = None) -> None:
        """Run one request.verify call from the short queue (REQUEST_CONCURRENCY at a time); a
        ``follow_up`` long verifier is queued when the check's answer says the tool should look."""
        identity = json.dumps(
            [values.get("check"), values.get("method"), values.get("path"), values.get("parameter"),
             values.get("as_principal")], sort_keys=True)
        if identity in self.request_checks_sent or len(self.request_checks_sent) >= MAX_REQUEST_CHECKS:
            return
        self.request_checks_sent.add(identity)

        async def one() -> None:
            async with self._request_gate:
                try:
                    result = await self._safe("request.verify", values, sweep_key("request", identity))
                finally:
                    self.request_checks_done += 1
                    self._stats()
            if follow_up is not None and sql_screen_escalates(result):
                self._queue_long(follow_up)

        task = asyncio.get_running_loop().create_task(one())
        self._long_jobs.add(task)
        task.add_done_callback(self._long_jobs.discard)
        self.request_checks_queued += 1

    def _queue_long(self, job: tuple[str, dict[str, Any], str]) -> None:
        """Run one long verifier call from the queue (LONG_CONCURRENCY at a time); never awaited
        by the round that queued it; a job already queued is not queued again."""
        if job[2] in self._long_keys:
            return
        self._long_keys.add(job[2])
        async def one() -> None:
            async with self._long_gate:
                try:
                    await self._safe(*job, slot_wait_seconds=LONG_SLOT_WAIT_SECONDS)
                finally:
                    self.injection_done += 1
                    self._stats()

        task = asyncio.get_running_loop().create_task(one())
        self._long_jobs.add(task)
        task.add_done_callback(self._long_jobs.discard)
        self.injection_queued += 1


# Template tags that make a match an exposure ``candidate.verify`` can settle (a sensitive value
# an anonymous read returns), a code-execution or file-read claim, or a bare detection.
_EXPOSURE_TAGS = frozenset({"exposure", "disclosure", "config", "token", "secret", "secrets", "logs",
                            "debug", "backup", "files", "listing"})
_EXECUTION_TAGS = frozenset({"rce", "cmdi", "code-injection", "injection", "deserialization", "ssti"})
_FILE_READ_TAGS = frozenset({"lfi", "pathtraversal", "path-traversal", "traversal"})
_DETECTION_TAGS = frozenset({"detect", "tech", "panel"})
_FINDING_TAGS = frozenset({"exposure", "misconfig", "unauth", "vuln", "cve", "auth-bypass", "disclosure"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_DISCLOSURE_NAME = re.compile(r"disclos|leak|exposed|exposure", re.I)


def template_matches(result: Any) -> list[Mapping[str, Any]]:
    """The template matches a ``templates.scan`` call answered with."""
    if not isinstance(result, Mapping):
        return []
    sources = [result.get("observations"), (result.get("action_result") or {}).get("observations")
               if isinstance(result.get("action_result"), Mapping) else None]
    return [item for source in sources for item in source or ()
            if isinstance(item, Mapping) and item.get("kind") == "template_match" and item.get("matched_at")]


def product_candidate(product: str, checks: str, match: Mapping[str, Any],
                      action: str | None) -> dict[str, Any] | None:
    """The candidate a product template match records, or None (a bare detection, no action)."""
    template_id = str(match.get("template_id") or "")
    try:
        parsed = urllib.parse.urlsplit(str(match.get("matched_at") or ""))
    except ValueError:
        return None
    # A template that joins "{{BaseURL}}/" to a base ending in "/" requests "//x"; the route is "/x".
    # Scanner output is untrusted, so its query values arrive masked ("<...>"); a masked query is
    # dropped rather than replayed as the mask.
    query = "" if "<" in urllib.parse.unquote(parsed.query or "") else parsed.query
    path = "/" + (parsed.path or "/").lstrip("/") + (f"?{query}" if query else "")
    tags = frozenset(str(tag).lower() for tag in match.get("tags") or ())
    severity = str(match.get("severity") or "info").lower()
    if not template_id or not action or not path.startswith("/"):
        return None
    if severity == "info" and tags & _DETECTION_TAGS and not tags & _FINDING_TAGS:
        return None
    name = str(match.get("name") or template_id)[:200]
    if tags & _EXECUTION_TAGS:
        family = "command_injection"
    elif tags & _FILE_READ_TAGS:
        family = "path_traversal"
    elif checks == "read_only" and (tags & _EXPOSURE_TAGS or (
            "misconfig" not in tags and _DISCLOSURE_NAME.search(name))):
        # A CVE template is often tagged only by product and year; its name says what it reads.
        family = "data_exposure"
    else:
        family = "security_misconfiguration"
    locus: dict[str, Any] = {"path": path}
    if checks == "read_only":
        locus["method"] = "GET"
    return {
        "family": family,
        "title": f"{name} ({template_id})"[:300],
        "claim": (f"The {product} template {template_id} matched {path} (engine template sweep of a "
                  "recognised product; the match is the template's own matcher, not yet re-executed proof)."),
        "severity": severity if severity in _SEVERITIES else "info",
        "locus": locus,
        "evidence_refs": [f"action:{action}"],
    }


_ROBOTS_LINE = re.compile(r"(?im)^\s*(?:dis)?allow\s*:\s*(/[^\s*$#?]*)")
_SITEMAP_LOC = re.compile(r"(?i)<loc>\s*([^<\s]+)\s*</loc>")


def form_entries(response: Mapping[str, Any], page: str) -> list[str]:
    """Inventory entries for the forms an HTML answer carries: the form's own action and method
    with its named fields as inputs (a search box, a comment form, a settings page ...)."""
    html = response.get("html") if isinstance(response.get("html"), Mapping) else {}
    entries: list[str] = []
    for form in html.get("forms") or ():
        if not isinstance(form, Mapping):
            continue
        action = str(form.get("action") or "").split("#", 1)[0] or page.split("?", 1)[0]
        if not action.startswith("/") or action.startswith("//"):
            continue
        names = [str(field.get("name")) for field in form.get("fields") or ()
                 if isinstance(field, Mapping) and field.get("name")
                 and str(field.get("type") or "text").lower() not in {"submit", "button", "image", "reset", "file"}]
        names = list(dict.fromkeys(name for name in names if re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,64}", name)))[:20]
        if not names:
            continue
        path = action.split("?", 1)[0]
        method = str(form.get("method") or "GET").upper()
        query = "&".join(f"{urllib.parse.quote(name)}=1" for name in names)
        entries.append(f"POST {path} form:{query}" if method == "POST" else f"GET {path}?{query}")
    return entries


def hint_entries(response: Mapping[str, Any], page: str) -> list[str]:
    """Routes a robots.txt (Allow/Disallow lines) or a sitemap (<loc>) names, same origin only."""
    status = response.get("status")
    if not isinstance(status, int) or status >= 300:
        return []
    text = str(response.get("body_sample") or "")
    name = page.split("?", 1)[0].rsplit("/", 1)[-1].lower()
    found: list[str] = []
    if name == "robots.txt":
        found = [path for path in _ROBOTS_LINE.findall(text) if path != "/"]
    elif name.startswith("sitemap") and name.endswith(".xml"):
        for loc in _SITEMAP_LOC.findall(text):
            parts = urllib.parse.urlsplit(loc)
            path = parts.path if parts.scheme else loc
            if path.startswith("/") and not path.startswith("//"):
                found.append(path + (f"?{parts.query}" if parts.scheme and parts.query else ""))
    return [f"GET {path}" for path in dict.fromkeys(found)][:200]


def _tool_job(capability: str, klass: str, method: str, route: str, params: Sequence[str], field: str | None,
              identity: Mapping[str, Any]) -> tuple[str, dict[str, Any], str]:
    """One sqli.verify or xss.verify call on a route's query (GET) or one body field."""
    if method == "GET":
        path = f"{concrete(route)}?" + "&".join(f"{name}=1" for name in params[:10])
        return capability, {"path": path, **identity}, sweep_key(klass, path)
    values = {"path": concrete(route), "method": method, "body_field_names": list(params[:20]),
              "injection_field": field, **identity}
    return capability, values, sweep_key(klass, method, route, str(field))


def sql_screen_escalates(result: Any) -> bool:
    """Whether the SQL injection proof's answer calls for the full tool: it could not run, or a quote
    changed the answer (status) or raised a database error without a repeatable proof."""
    if not isinstance(result, Mapping):
        return True
    action = result.get("action_result") if isinstance(result.get("action_result"), Mapping) else {}
    proofs = [item for item in action.get("observations") or ()
              if isinstance(item, Mapping) and item.get("kind") == "sqli_proof"]
    if not proofs:
        return str(action.get("status") or "") not in {"success", "completed"}
    proof = proofs[0]
    if proof.get("proof_state") == "verified" or proof.get("finding_verdict") == "inconclusive":
        return False
    if proof.get("database_error_signatures"):
        return True
    return any(isinstance(pair, Mapping) and pair.get("control_status") != pair.get("payload_status")
               for pair in proof.get("response_pairs") or ())


def _distinct(answer: Mapping[str, Any], control: Mapping[str, Any]) -> bool:
    """Whether a route probe answered unlike the root's answer for a route that cannot exist."""
    status = answer.get("status")
    if not isinstance(status, int) or status in {404, 410} or status >= 500 or status == 429:
        return False
    if status != control.get("status"):
        return True
    length = len(str(answer.get("body_sample") or ""))
    control_length = len(str(control.get("body_sample") or ""))
    return abs(length - control_length) > max(16, 0.05 * max(length, control_length))


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _signed_in_slots(run: Mapping[str, Any]) -> list[str]:
    """The principal slots the Hunt selected, when it may use them (credential access + approval)."""
    policy = _json(run.get("policy_json"))
    if not policy.get("credential_access") or not policy.get("approval_receipt_id"):
        return []
    context = _json(run.get("context_pack"))
    slots: list[str] = []
    for item in context.get("credential_refs") or ():
        if isinstance(item, Mapping) and item.get("source") == "credential_profiles":
            slot = str(item.get("principal_slot") or "")
            if slot in {"primary", "secondary"} and slot not in slots:
                slots.append(slot)
    return slots


def _two_principals(run: Mapping[str, Any]) -> bool:
    policy = _json(run.get("policy_json"))
    if not policy.get("credential_access") or not policy.get("approval_receipt_id"):
        return False
    context = _json(run.get("context_pack"))
    slots = {str(item.get("principal_slot")) for item in context.get("credential_refs") or ()
             if isinstance(item, Mapping) and item.get("source") == "credential_profiles"}
    return {"primary", "secondary"} <= slots


__all__ = ["KEY_PREFIX", "Refused", "Sweep", "WirePace", "wire_cost", "concrete", "exposure_signal", "login_form", "product_candidate",
           "sweep_key", "template_matches"]

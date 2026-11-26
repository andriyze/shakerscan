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
5. **Product templates**: for every product discovery recognised (``products``), its own templates
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

try:
    from runtime.product_templates import PRODUCT_MOUNTS, PRODUCT_TEMPLATE_TAGS, product_window_count
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.product_templates import PRODUCT_MOUNTS, PRODUCT_TEMPLATE_TAGS, product_window_count

KEY_PREFIX = "auto-sweep"
# Engine checks at once: leaves the planner a long slot (agent_job_concurrency gives a Hunt two
# long slots per agent-tool worker).
LONG_CONCURRENCY = 2
SHORT_CONCURRENCY = 3
MAX_READS = 800
MAX_INJECTION_TARGETS = 400
MAX_FIELDS_PER_BODY = 4
MAX_AUTHZ_ROUTES = 50
MAX_SCRIPTS = 40
# Rounds of read-record-test; each round only tests what earlier rounds did not.
MAX_ROUNDS = 8
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
_SECRET_FIELDS = ("password", "pass", "passwd", "pwd")

Call = Callable[[str, Mapping[str, Any], str], Awaitable[Any]]
CreateCandidate = Callable[[Mapping[str, Any]], Awaitable[Any]]


class Refused(Exception):
    """A check the server refused; it is skipped and named."""


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
    match = _SECRET_TEXT.search(text)
    if match:
        found = match.group(0).lower()
        if "index of" in found:
            return "a directory index"
        if "private key" in found:
            return "a private key"
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
    """

    def __init__(self, *, call: Call, create_candidate: CreateCandidate, state: dict[str, Any],
                 live: Callable[[], Awaitable[bool]]) -> None:
        self._call = call
        self._create = create_candidate
        self.state = state
        self._live = live
        self.counts: dict[str, int] = {}
        self.product_checks_run: set[str] = set()
        self.tested: set[tuple[str, str]] = set()  # pairs a sweep check ran on
        self.considered: set[tuple[str, str]] = set()  # pairs a round has looked at (never repeated)
        self.logins: dict[str, tuple[str, str, str, bool]] = {}
        self.logins_tried: set[str] = set()
        self.signed_in_only: set[str] = set()
        self.seen: set[str] = set()
        self.js_done: set[str] = set()
        self.started = time.monotonic()
        # The long-verifier queue: jobs run LONG_CONCURRENCY at a time beside the rounds.
        self._long_gate = asyncio.Semaphore(LONG_CONCURRENCY)
        self._long_jobs: set[asyncio.Task] = set()
        self.injection_queued = 0
        self.injection_done = 0

    def _count(self, name: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
        self.state["sweep_counts"] = dict(self.counts)

    def _stats(self, **extra: Any) -> None:
        stats = dict(self.state.get("sweep_stats") or {})
        stats.update(extra, seconds=int(time.monotonic() - self.started), pairs_tested=len(self.tested),
                     endpoints_seen=len(self.seen), injection_queued=self.injection_queued,
                     injection_done=self.injection_done)
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
                  record: Callable[[list[str]], Awaitable[Any]] | None = None) -> None:
        policy = _json(run.get("policy_json"))
        allowed = {str(name) for name in policy.get("allowed_capabilities") or ()}
        writes = bool(policy.get("allow_state_changing_http"))
        slots = _signed_in_slots(run)
        templates = ("templates.scan" in allowed and bool(policy.get("active_testing"))
                     and bool(policy.get("approval_receipt_id")))
        self.state["sweep"] = "running"
        rounds = 0
        try:
            if templates:
                # The products discovery recognised are known before the first round.
                await self._product_templates("read_only")
            while rounds < MAX_ROUNDS:
                current = report if (rounds == 0 and report is not None) else (
                    await load_report() if load_report is not None else None)
                if current is None:
                    break
                items = [item for item in current.get("open") or () if isinstance(item, Mapping)]
                fresh = [item for item in items if self._untested(item)]
                if not fresh:
                    break
                rounds += 1
                self._stats(rounds=rounds, endpoints_known=int(current.get("endpoints") or len(items)))
                found: list[str] = []
                if "http.request" in allowed:
                    found += await self._read_all(fresh, slots=slots)
                if "javascript.analyze" in allowed:
                    found += await self._javascript(items)
                if "http.request" in allowed and writes:
                    await self._default_credentials()
                if templates and writes and "state_changing" not in self.product_checks_run:
                    await self._product_templates("state_changing")
                if "authz.verify" in allowed and {"primary", "secondary"} <= set(slots):
                    await self._function_authz(fresh)
                await self._injection(fresh, allowed=allowed, writes=writes, slots=slots)
                handled = {"review", "exposure", "unauthenticated_api", "default_credentials"}
                if {"primary", "secondary"} <= set(slots):
                    handled.add("function_authz")
                handled |= {klass for capability, klass in (("sqli.verify", "sqli"), ("xss.verify", "xss"))
                            if capability in allowed}
                for item in fresh:
                    for klass in item.get("untested") or ():
                        pair = (str(item.get("endpoint")), str(klass))
                        self.considered.add(pair)
                        if klass in handled and (klass not in {"sqli", "xss"} or item.get("params")):
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

    async def _read_all(self, items: Sequence[Mapping[str, Any]], *, slots: Sequence[str]) -> list[str]:
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
            signal = exposure_signal(response)
            action = _action_id(result)
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
            if _LOGIN_PATH.search(route) and response.get("status") in {405, 400} and "/api" in route:
                self.logins.setdefault(route, (route, "username", "password", True))
            if response.get("status") in {401, 403} and slots:
                self.signed_in_only.add(route)
                for slot in slots:
                    await look(path, slot)

        await asyncio.gather(*(read(route) for route in targets))
        return links

    async def _javascript(self, items: Sequence[Mapping[str, Any]]) -> list[str]:
        """Routes the application's own JavaScript names (``javascript.analyze``)."""
        routes: list[str] = []
        for item in items:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if method != "GET" or not route.endswith(".js") or route in self.js_done or len(self.js_done) >= MAX_SCRIPTS:
                continue
            self.js_done.add(route)
            result = await self._safe("javascript.analyze", {"path": route}, sweep_key("javascript", route))
            action = (result or {}).get("action_result") if isinstance(result, Mapping) else None
            for observation in (action or {}).get("observations") or ():
                if isinstance(observation, Mapping) and observation.get("kind") == "javascript_analysis":
                    for found in observation.get("routes") or ():
                        text = str(found)
                        if text.startswith("/") and not text.startswith("//") and "[withheld" not in text:
                            routes.append(f"GET {text}")
        return routes

    async def _default_credentials(self) -> None:
        for path, (_path, user, secret, json_body) in list(self.logins.items())[:4]:
            if path in self.logins_tried:
                continue
            self.logins_tried.add(path)
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
            params = [str(name) for name in item.get("params") or () if str(name)]
            untested = set(self._untested(item))
            if not params or not route.startswith("/"):
                continue
            # A route that refuses anonymous callers is tested signed in, as the first principal.
            identity = {"as_principal": slots[0]} if route in self.signed_in_only and slots else {}
            for capability, klass in (("sqli.verify", "sqli"), ("xss.verify", "xss")):
                if capability not in allowed or klass not in untested:
                    continue
                if method == "GET":
                    query = "&".join(f"{name}=1" for name in params[:10])
                    path = f"{concrete(route)}?{query}"
                    jobs.append((capability, {"path": path, **identity}, sweep_key(klass, path)))
                elif writes and method in {"POST", "PUT", "PATCH"}:
                    for field in params[:MAX_FIELDS_PER_BODY]:
                        values = {"path": concrete(route), "method": method, "body_field_names": params[:20],
                                  "injection_field": field, **identity}
                        jobs.append((capability, values, sweep_key(klass, method, route, field)))
        # XSS first on every target (about 20 s a call), then SQL injection (minutes a call): the
        # slower verifier never holds back the faster one.
        jobs.sort(key=lambda job: 0 if job[0] == "xss.verify" else 1)
        for job in jobs:
            self._queue_long(job)

    def _queue_long(self, job: tuple[str, dict[str, Any], str]) -> None:
        """Run one long verifier call from the queue (LONG_CONCURRENCY at a time); never awaited
        by the round that queued it."""
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


__all__ = ["KEY_PREFIX", "Refused", "Sweep", "concrete", "exposure_signal", "login_form", "product_candidate",
           "sweep_key", "template_matches"]

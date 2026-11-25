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
4. **Injection verifiers**: ``sqli.verify`` then ``xss.verify`` on every endpoint parameter (query
   parameters; body fields when state-changing HTTP is allowed). They record proven findings
   themselves.

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
from typing import Any

KEY_PREFIX = "auto-sweep"
# Engine checks at once: leaves the planner a long slot (agent_job_concurrency gives a Hunt two
# long slots per agent-tool worker).
LONG_CONCURRENCY = 2
SHORT_CONCURRENCY = 3
MAX_READS = 800
MAX_INJECTION_TARGETS = 400
MAX_FIELDS_PER_BODY = 4
MAX_AUTHZ_ROUTES = 50
DEFAULT_CREDENTIAL_PACE_SECONDS = 2.2
DEFAULT_PAIR_IDS = tuple(f"dc-{index:02d}" for index in range(1, 21))
_SECRET_TEXT = re.compile(
    r"\[withheld:\d+\]|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|"
    r"<title>\s*index of /|\bindex of /", re.I)
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
    match = _SECRET_TEXT.search(text)
    if not match:
        return None
    found = match.group(0).lower()
    if "index of" in found:
        return "a directory index"
    if "private key" in found:
        return "a private key"
    return "credential-shaped values"


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
    """One Hunt's sweep. ``call`` runs one capability call; ``create_candidate`` records one."""

    def __init__(self, *, call: Call, create_candidate: CreateCandidate, state: dict[str, Any],
                 live: Callable[[], Awaitable[bool]]) -> None:
        self._call = call
        self._create = create_candidate
        self.state = state
        self._live = live
        self.counts: dict[str, int] = {}

    def _count(self, name: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
        self.state["sweep_counts"] = dict(self.counts)

    def _note(self, text: str) -> None:
        notes = self.state.setdefault("notes", [])
        if len(notes) < 40 and text not in notes:
            notes.append(text[:300])

    async def _safe(self, capability: str, values: Mapping[str, Any], key: str) -> Any:
        if not await self._live():
            raise asyncio.CancelledError()
        try:
            result = await self._call(capability, values, key)
        except asyncio.CancelledError:
            raise
        except Refused as exc:
            self._count(f"{capability}:refused")
            self._note(f"{capability}: {exc}")
            return None
        self._count(capability)
        return result

    async def _candidate_and_verify(self, values: Mapping[str, Any]) -> None:
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
        await self._safe("candidate.verify", {"candidate_id": candidate_id},
                         sweep_key("verify", candidate_id))

    async def run(self, run: Mapping[str, Any], report: Mapping[str, Any]) -> None:
        policy = _json(run.get("policy_json"))
        allowed = {str(name) for name in policy.get("allowed_capabilities") or ()}
        writes = bool(policy.get("allow_state_changing_http"))
        items = [item for item in report.get("open") or () if isinstance(item, Mapping)]
        self.state["sweep"] = "running"
        try:
            logins: list[tuple[str, str, str, bool]] = []
            if "http.request" in allowed:
                logins = await self._read_all(items)
            if "http.request" in allowed and writes and logins:
                await self._default_credentials(logins)
            if "authz.verify" in allowed and _two_principals(run):
                await self._function_authz(items)
            await self._injection(items, allowed=allowed, writes=writes)
            self.state["sweep"] = "done"
        except asyncio.CancelledError:
            self.state["sweep"] = "stopped"
            raise

    async def _read_all(self, items: Sequence[Mapping[str, Any]]) -> list[tuple[str, str, str, bool]]:
        """GET every mapped endpoint; record exposures; return the sign-ins found."""
        gate = asyncio.Semaphore(SHORT_CONCURRENCY)
        logins: dict[str, tuple[str, str, str, bool]] = {}
        targets = []
        for item in items[:MAX_READS]:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if not route.startswith("/"):
                continue
            if method == "GET":
                targets.append(route)
            elif method == "POST" and "default_credentials" in (item.get("untested") or ()) and "/api" in route:
                logins.setdefault(route, (route, "username", "password", True))

        async def read(route: str) -> None:
            async with gate:
                path = concrete(route)
                result = await self._safe("http.request", {"method": "GET", "path": path, "follow_redirects": False},
                                          sweep_key("read", path))
            response = _response(result)
            form = login_form(response)
            if form:
                logins.setdefault(form[0], (form[0], form[1], form[2], False))
            elif _LOGIN_PATH.search(route) and response.get("status") in {405, 400} and "/api" in route:
                logins.setdefault(route, (route, "username", "password", True))
            signal = exposure_signal(response)
            action = _action_id(result)
            if signal and action:
                await self._candidate_and_verify({
                    "family": "data_exposure",
                    "title": f"{path} serves {signal} without authentication",
                    "claim": (f"An anonymous GET {path} answered {response.get('status')} with {signal} "
                              "(found by the engine's sweep of the mapped surface)."),
                    "severity": "high" if signal != "a directory index" else "medium",
                    "locus": {"method": "GET", "path": path},
                    "evidence_refs": [f"action:{action}"],
                })

        await asyncio.gather(*(read(route) for route in targets))
        return list(logins.values())[:4]

    async def _default_credentials(self, logins: Sequence[tuple[str, str, str, bool]]) -> None:
        for path, user, secret, json_body in logins:
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

    async def _function_authz(self, items: Sequence[Mapping[str, Any]]) -> None:
        routes = []
        for item in items:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if method == "GET" and "function_authz" in (item.get("untested") or ()):
                routes.append(concrete(route))
        for start in range(0, len(routes), MAX_AUTHZ_ROUTES):
            chunk = routes[start:start + MAX_AUTHZ_ROUTES]
            await self._safe("authz.verify", {"mode": "function", "primary_principal": "primary",
                                              "secondary_principal": "secondary", "routes": chunk},
                             sweep_key("authz-function", *chunk))

    async def _injection(self, items: Sequence[Mapping[str, Any]], *, allowed: set[str], writes: bool) -> None:
        jobs: list[tuple[str, dict[str, Any], str]] = []
        for item in items[:MAX_INJECTION_TARGETS]:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            params = [str(name) for name in item.get("params") or () if str(name)]
            untested = set(item.get("untested") or ())
            if not params or not route.startswith("/"):
                continue
            for capability, klass in (("sqli.verify", "sqli"), ("xss.verify", "xss")):
                if capability not in allowed or klass not in untested:
                    continue
                if method == "GET":
                    query = "&".join(f"{name}=1" for name in params[:10])
                    path = f"{concrete(route)}?{query}"
                    jobs.append((capability, {"path": path}, sweep_key(klass, path)))
                elif writes and method in {"POST", "PUT", "PATCH"}:
                    for field in params[:MAX_FIELDS_PER_BODY]:
                        values = {"path": concrete(route), "method": method, "body_field_names": params[:20],
                                  "injection_field": field}
                        jobs.append((capability, values, sweep_key(klass, method, route, field)))
        # SQL injection first on every target, then XSS: the slower verifier never starves the other.
        jobs.sort(key=lambda job: 0 if job[0] == "sqli.verify" else 1)
        gate = asyncio.Semaphore(LONG_CONCURRENCY)

        async def one(job: tuple[str, dict[str, Any], str]) -> None:
            async with gate:
                await self._safe(*job)

        await asyncio.gather(*(one(job) for job in jobs))


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _two_principals(run: Mapping[str, Any]) -> bool:
    policy = _json(run.get("policy_json"))
    if not policy.get("credential_access") or not policy.get("approval_receipt_id"):
        return False
    context = _json(run.get("context_pack"))
    slots = {str(item.get("principal_slot")) for item in context.get("credential_refs") or ()
             if isinstance(item, Mapping) and item.get("source") == "credential_profiles"}
    return {"primary", "secondary"} <= slots


__all__ = ["KEY_PREFIX", "Refused", "Sweep", "concrete", "exposure_signal", "login_form", "sweep_key"]

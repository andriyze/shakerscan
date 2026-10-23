#!/usr/bin/env python3
"""First-class CLI for canonical ShakerScan V2 workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import re
import time
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
import uuid


MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 52 * 1024 * 1024
MAX_DOCUMENT_BYTES = 50 * 1024 * 1024


class CliError(RuntimeError):
    """A safe, user-facing CLI failure."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str = "client_error",
        http_status: int | None = None,
        api_detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.http_status = http_status
        self.api_detail = api_detail

    def public_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "shakerscan-cli-error/v1",
            "error": self.error_type,
            "message": str(self),
        }
        if self.http_status is not None:
            result["http_status"] = self.http_status
        if self.api_detail is not None:
            result["api_detail"] = self.api_detail
        return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never replay an authenticated request against another origin.

    The https:// guard above only covers the URL the operator supplied. Following a
    redirect with urllib's default handler re-sends the Authorization header to
    whatever Location names -- another host, or plain HTTP. Refuse instead, and let
    the caller surface the 3xx.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


# A Hunt capability runs synchronously inside its request and can take minutes; a proxy or the
# client's own timeout may end the wait first. The engine answers a replay of the same key and
# input with the action's current state and never starts it twice, so an unknown outcome is
# settled by replaying until the action is no longer in flight, within a bounded wait.
ACTION_WAIT_SECONDS = 900.0
ACTION_POLL_SECONDS = 5.0
IN_FLIGHT_ACTION_STATUSES = frozenset({"requested", "reserved", "queued", "running"})


def _action_wait_seconds() -> float:
    try:
        value = float(os.environ.get("SHAKERSCAN_HUNT_ACTION_WAIT_SECONDS", ACTION_WAIT_SECONDS))
    except ValueError:
        value = ACTION_WAIT_SECONDS
    return max(0.0, min(value, 3600.0))


def _unknown_outcome(exc: "CliError") -> bool:
    return exc.error_type == "network_error" or exc.http_status in {502, 503, 504}


def _in_flight(response: Any) -> bool:
    action = response.get("action_result") if isinstance(response, Mapping) else None
    return isinstance(action, Mapping) and str(action.get("status") or "") in IN_FLIGHT_ACTION_STATUSES


def _settled_capability(client: "ApiClient", path: str, body: dict[str, Any], *,
                        poll_seconds: float = ACTION_POLL_SECONDS) -> Any:
    try:
        response = client.post(path, body)
    except CliError as exc:
        if not _unknown_outcome(exc):
            raise
        response, last = None, exc
    else:
        if not _in_flight(response):
            return response
        last = None
    deadline = time.monotonic() + _action_wait_seconds()
    while time.monotonic() < deadline:
        time.sleep(poll_seconds)
        try:
            response = client.post(path, body)
        except CliError as exc:
            if not _unknown_outcome(exc):
                raise
            last = exc
            continue
        if not _in_flight(response):
            return response
        last = None
    if last is not None:
        raise last
    return response


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect())


def _redirect_text(exc: urllib.error.HTTPError, request_url: str) -> str:
    """D17: say where the instance is and which option points there, not only "HTTP 308"."""
    try:
        from redirect_hint import redirect_explanation
    except ModuleNotFoundError:
        from scripts.redirect_hint import redirect_explanation
    location = exc.headers.get("Location") if exc.headers is not None else None
    return redirect_explanation(exc.code, location, request_url, option="--url")


def _certificate_text(message: str, reason: object) -> str:
    """Name the remedy when the failure is an untrusted (private CA) certificate."""
    try:
        from redirect_hint import with_certificate_hint
    except ModuleNotFoundError:
        from scripts.redirect_hint import with_certificate_hint
    return with_certificate_hint(message, reason)


def _approval():
    """The terminal approval protocol (scripts/hunt_approve.py), loaded when a command needs it."""
    try:
        import hunt_approve
    except ModuleNotFoundError:
        from scripts import hunt_approve
    return hunt_approve


def _approval_send(client: "ApiClient"):
    """``send(method, path, payload, headers) -> (status, body)`` over this CLI's own client:
    the bearer token, https only, and never a followed redirect."""
    approval = _approval()

    def send(method: str, path: str, payload: Mapping[str, Any] | None = None,
             headers: Mapping[str, str] | None = None, *, timeout: float | None = None) -> tuple[int, Any]:
        try:
            bound = {} if timeout is None else {"timeout": timeout}
            return 200, client.request(method, path, payload=payload, headers=headers, **bound)
        except CliError as exc:
            if exc.http_status is None:
                raise approval.ApprovalError(str(exc)) from exc
            return exc.http_status, exc.api_detail if exc.api_detail is not None else str(exc)

    return send


def _person_decision():
    try:
        import person_decision
    except ModuleNotFoundError:
        from scripts import person_decision
    return person_decision


def _launch_bounds() -> tuple[list[str], str | None]:
    """``shakerscan agent --allow``: the person's bounds and the gateway pre-authorization id."""
    try:
        bounds = json.loads(os.environ.get("SHAKERSCAN_HUNT_ALLOW") or "[]")
    except ValueError:
        bounds = []
    bounds = [str(item) for item in bounds if isinstance(item, str) and item.strip()] if isinstance(bounds, list) else []
    return bounds, (os.environ.get("SHAKERSCAN_PREAUTHORIZATION_ID") or "").strip() or None


class ApiClient:
    def __init__(self, base_url: str, *, timeout: float = 60.0, api_token: str | None = None) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.timeout = timeout
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CliError("the configured ShakerScan API URL is invalid")
        # A bearer token (an Enterprise gateway service token) authenticates a remote API; it is
        # only ever sent over HTTPS and never printed.
        if api_token and parsed.scheme != "https":
            raise CliError("SHAKERSCAN_API_TOKEN requires an https:// API URL")
        self.api_token = api_token or None

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.api_token} if self.api_token else {}

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        _person_proof: str | None = None,
    ) -> Any:
        """``timeout`` (seconds) overrides this client's own for one request. A request an
        Enterprise gateway refuses for a person's security-key touch is completed in the person's
        own terminal and sent again once (person_decision.py)."""
        body = None
        headers_in = headers
        headers = {"Accept": "application/json", **dict(headers or {}), **self._auth_headers()}
        if _person_proof:
            headers[_person_decision().PROOF_HEADER] = _person_proof
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_REQUEST_BYTES:
                raise CliError("request JSON exceeds the 52 MiB CLI limit")
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=headers, method=method,
        )
        try:
            with _opener().open(request, timeout=self.timeout if timeout is None else timeout) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise CliError(
                    _redirect_text(exc, request.full_url),
                    error_type="api_error",
                    http_status=exc.code,
                ) from exc
            raw = exc.read(MAX_JSON_BYTES + 1)
            message, detail = _safe_api_error(
                raw, fallback=f"API returned HTTP {exc.code}"
            )
            if _person_proof is None and _person_decision().required(exc.code, exc.headers, detail):
                return self._person_decision(
                    method, path, body or b"", detail,
                    payload=payload, idempotency_key=idempotency_key, headers=headers_in, timeout=timeout,
                )
            raise CliError(
                message,
                error_type="api_error",
                http_status=exc.code,
                api_detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise CliError(
                _certificate_text(f"cannot reach ShakerScan API: {exc.reason}", exc.reason),
                error_type="network_error",
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise CliError(
                "the ShakerScan API did not answer in time",
                error_type="network_error",
            ) from exc
        if len(raw) > MAX_JSON_BYTES:
            raise CliError("API response exceeds the 4 MiB CLI limit")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CliError("ShakerScan API returned invalid JSON") from exc

    def _person_decision(self, method: str, path: str, body: bytes, detail: Mapping[str, Any], **again: Any) -> Any:
        """A person's decision the gateway wants a security-key touch for: one touch and one
        resend of exactly this request in the person's terminal; elsewhere a refusal naming the
        person's command (exit 3)."""
        decision = _person_decision()
        parsed = urllib.parse.urlsplit(self.base_url)
        try:
            return decision.handle(
                decision.json_poster(self.base_url, self.api_token),
                origin=f"{parsed.scheme}://{parsed.netloc}", method=method, path=path, body=body, detail=detail,
                resend=lambda grant: self.request(method, path, _person_proof=grant, **again),
            )
        except decision.PersonDecisionRefused as exc:
            raise CliError(exc.line, error_type="person_decision_required", http_status=403,
                           api_detail={**exc.detail, "command": exc.command}) from None
        except decision.PersonDecisionCancelled as exc:
            raise CliError(str(exc), error_type="person_decision_cancelled") from None
        except decision.PersonDecisionError as exc:
            raise CliError(str(exc), error_type="person_decision_failed", http_status=403, api_detail=detail) from None

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(
        self,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> Any:
        return self.request(
            "POST", path, payload=payload, idempotency_key=idempotency_key,
        )

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def download(self, path: str, *, max_bytes: int = MAX_REQUEST_BYTES) -> tuple[bytes, str]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"Accept": "application/json, application/zip", **self._auth_headers()},
            method="GET",
        )
        try:
            with _opener().open(request, timeout=self.timeout) as response:
                raw = response.read(max_bytes + 1)
                content_type = str(response.headers.get("Content-Type") or "")
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise CliError(
                    _redirect_text(exc, request.full_url),
                    error_type="api_error",
                    http_status=exc.code,
                ) from exc
            raw = exc.read(MAX_JSON_BYTES + 1)
            message, detail = _safe_api_error(
                raw, fallback=f"API returned HTTP {exc.code}"
            )
            raise CliError(
                message,
                error_type="api_error",
                http_status=exc.code,
                api_detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise CliError(
                _certificate_text(f"cannot reach ShakerScan API: {exc.reason}", exc.reason),
                error_type="network_error",
            ) from exc
        if len(raw) > max_bytes:
            raise CliError("evidence export exceeds the 52 MiB CLI limit")
        return raw, content_type


def _safe_api_error(raw: bytes, *, fallback: str) -> tuple[str, Any]:
    try:
        value = json.loads(raw[:MAX_JSON_BYTES])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return fallback, None
    detail = value.get("detail") if isinstance(value, Mapping) else None
    if isinstance(detail, str) and detail.strip():
        message = detail.strip()[:2_000]
        return message, message
    if isinstance(detail, list):
        # D48: name the field ("family: Field required"); never the rejected input.
        messages = [
            ": ".join(part for part in (
                ".".join(str(segment) for segment in item.get("loc") or () if segment != "body"),
                str(item.get("msg") or "invalid request"),
            ) if part)
            for item in detail
            if isinstance(item, Mapping)
        ]
        if messages:
            return "; ".join(messages)[:2_000], detail
    if isinstance(detail, Mapping):
        message = str(
            detail.get("message") or detail.get("error") or fallback
        )[:2_000]
        return message, dict(detail)
    return fallback, detail


def _validate_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = str(value)
    if not 8 <= len(key) <= 200:
        raise CliError("idempotency key must contain 8 to 200 characters")
    if not key[0].isalnum() or any(
        not (character.isalnum() or character in "_.:-") for character in key
    ):
        raise CliError(
            "idempotency key must start with an alphanumeric character and use only "
            "letters, numbers, underscore, dot, colon, or hyphen"
        )
    return key


def _content_idempotency_key(*values: Any) -> str:
    material = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return "cli-" + hashlib.sha256(material).hexdigest()


def _read_json(path: str | None, *, default: Any) -> Any:
    if path is None:
        return default
    if path == "-":
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    else:
        file_path = Path(path).expanduser()
        try:
            if file_path.stat().st_size > MAX_JSON_BYTES:
                raise CliError("input JSON exceeds the 4 MiB CLI limit")
            raw = file_path.read_bytes()
        except OSError as exc:
            raise CliError(f"cannot read JSON input: {exc}") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise CliError("input JSON exceeds the 4 MiB CLI limit")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("input is not valid UTF-8 JSON") from exc


def _pairs(values: Sequence[str], *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        name, separator, value = str(raw).partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or not value:
            raise CliError(f"{label} must use NAME=VALUE")
        if name in result:
            raise CliError(f"duplicate {label} name: {name}")
        result[name] = value
    return result


# `--credential-ref SLOT=ID` takes the short slot names the help documents as aliases of the
# start contract's fields (primary -> primary_credential_profile_id); the full names still work.
CREDENTIAL_REF_SLOTS = {
    "primary": "primary_credential_profile_id",
    "secondary": "secondary_credential_profile_id",
    "service": "service_credential_profile_id",
    "web": "web_credential_profile_id",
    "ssh": "ssh_credential_profile_id",
    "oauth": "oauth_credential_profile_id",
    "authorization_header": "authorization_header_credential_id",
    "cookie": "cookie_credential_id",
}


def _credential_refs(values: Sequence[str]) -> dict[str, str]:
    aliased = []
    for raw in values:
        name, separator, value = str(raw).partition("=")
        name = name.strip()
        aliased.append(f"{CREDENTIAL_REF_SLOTS.get(name, name)}{separator}{value}")
    return _pairs(aliased, label="credential reference")


def _openapi_schema(client: ApiClient, name: str) -> Mapping[str, Any]:
    contract = client.get("/openapi.json")
    try:
        schema = contract["components"]["schemas"][name]
    except (KeyError, TypeError) as exc:
        raise CliError(f"running server does not publish the {name} contract") from exc
    if not isinstance(schema, Mapping):
        raise CliError(f"running server returned an invalid {name} contract")
    return schema


def _validate_schema_object(
    value: Any, schema: Mapping[str, Any], *, label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CliError(f"{label} must be one JSON object")
    properties = set((schema.get("properties") or {}).keys())
    unknown = sorted(set(value) - properties)
    if unknown and schema.get("additionalProperties") is False:
        raise CliError(f"{label} contains unsupported fields: {', '.join(unknown)}")
    missing = sorted(set(schema.get("required") or ()) - set(value))
    if missing:
        raise CliError(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _read_document(path: str) -> Any:
    file_path = Path(path).expanduser()
    try:
        if file_path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise CliError("request collection document exceeds 50 MiB")
        raw = file_path.read_bytes()
    except OSError as exc:
        raise CliError(f"cannot read request collection document: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError("request collection document must be UTF-8") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _hunt_start_payload(args: argparse.Namespace, contract: Mapping[str, Any]) -> dict[str, Any]:
    if args.request:
        value = _read_json(args.request, default={})
        if not isinstance(value, dict):
            raise CliError("Hunt start request must be one JSON object")
        if value.get("schema_version") != contract.get("schema_version"):
            raise CliError("Hunt request schema_version does not match the server contract")
        return value

    target_kinds = {str(item) for item in contract.get("target_kinds") or ()}
    if not args.target_id:
        raise CliError("--target-id is required unless --request is used")
    if not args.target_kind:
        raise CliError("--target-kind is required unless --request is used")
    if args.target_kind not in target_kinds:
        raise CliError("target kind is not supported by the running server")
    profiles = contract.get("budget_profiles") or {}
    if args.budget_profile not in profiles:
        raise CliError("budget profile is not supported by the running server")

    dimensions = {
        str(item.get("name")): item
        for item in contract.get("budget_dimensions") or ()
        if isinstance(item, Mapping) and item.get("name")
    }
    budgets: dict[str, int] = {}
    for name, raw_value in _pairs(args.budget, label="budget").items():
        if name not in dimensions:
            raise CliError(f"budget dimension is not supported by the server: {name}")
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise CliError(f"budget {name} must be an integer") from exc
        minimum = int(dimensions[name].get("minimum") or 0)
        if value < minimum:
            raise CliError(f"budget {name} must be at least {minimum}")
        profile_max = int((profiles.get(args.budget_profile) or {}).get(name) or 0)
        if value > profile_max:
            raise CliError(
                f"budget {name} exceeds the server's {args.budget_profile} ceiling"
            )
        budgets[name] = value

    return {
        "schema_version": str(contract["schema_version"]),
        "target_id": args.target_id,
        "target_kind": args.target_kind,
        "goal": args.goal,
        "budget_profile": args.budget_profile,
        "policy": {
            "active_testing": bool(args.active_testing),
            "allow_state_changing_http": bool(args.allow_state_changing_http),
            "network_discovery": bool(args.network_discovery),
            "allow_oob_interactions": bool(args.allow_oob_interactions),
            "authorization_confirmed": bool(args.authorized),
            "approval_receipt_id": args.approval_receipt_id,
            "scope_receipt_id": args.scope_receipt_id,
        },
        "budgets": budgets,
        "credential_refs": _credential_refs(args.credential_ref),
        "capabilities": list(dict.fromkeys(args.capability)),
        "request_collection_ids": list(dict.fromkeys(args.collection_id)),
        "skill_ids": list(dict.fromkeys(args.skill_id)),
    }


def _start_preauthorization(
    args: argparse.Namespace, client: ApiClient, payload: dict[str, Any],
) -> dict[str, str]:
    """Put the start bounds into ``payload``; return the headers that carry their proof.

    ``--allow`` bounds are the person's own. On an open-source engine they are sent as given:
    the operator at the host is the trust boundary. On Enterprise they need the person's
    step-up, done here before the Hunt starts (or named with ``--preauthorization`` / inherited
    from ``shakerscan agent --allow``), and the gateway records them as that person's.
    ``--propose-allow`` bounds are a proposal: one pending request a person approves."""
    allow = list(dict.fromkeys(getattr(args, "allow", None) or ()))
    launch_allow, launch_id = _launch_bounds()
    if allow and payload.get("allow"):
        raise CliError("give the bounds with --allow or in the request's allow, not both")
    if not allow and not payload.get("allow") and launch_allow:
        allow = launch_allow
    if allow:
        payload["allow"] = allow
    if getattr(args, "propose_allow", None):
        payload["proposed_allow"] = list(dict.fromkeys(args.propose_allow))
    if getattr(args, "agent_may_see_secrets", False):
        if client.api_token:
            # A connected instance records this as the person's only after their step-up, which
            # its gateway does not offer for this setting yet: refuse rather than send it unproven.
            raise CliError(
                "--agent-may-see-secrets needs your step-up on a connected instance, which it does "
                "not offer yet. No Hunt was started.", error_type="preauthorization_required",
            )
        payload["secret_visibility"] = "agent_may_see"
        # The engine accepts it only with the person who chose it; on a local install that is you,
        # at this host (anyone with local API access can say the same: the host is the boundary).
        import getpass
        try:
            person = getpass.getuser() or "local-operator"
        except Exception:  # noqa: BLE001 - no login name in this environment
            person = "local-operator"
        payload.setdefault("allow_asserted_by", {"person": person[:200], "proof": "local"})
    if not payload.get("allow") or not client.api_token:
        return {}
    approval = _approval()
    preauthorization = getattr(args, "preauthorization", None) or launch_id
    if not preauthorization:
        try:
            granted = approval.preauthorize(
                _approval_send(client), client.base_url, approval.Terminal(sys.stdin, sys.stderr),
                payload["allow"], use="hunt_start", account=getattr(args, "account", None),
                method=getattr(args, "method", None),
            )
        except approval.ApprovalError as exc:
            raise CliError(
                f"{str(exc).rstrip('.')}. No Hunt was started. An agent proposes bounds with --propose-allow instead.",
                error_type="preauthorization_required",
            ) from exc
        preauthorization = str(granted["id"])
    return {approval.PREAUTHORIZATION_HEADER: preauthorization}


def _permission_wait_outcome(request: Mapping[str, Any]) -> dict[str, Any]:
    status = str(request.get("status") or "")
    outcome = status if status in {"granted", "denied", "expired", "withdrawn"} else "still_pending"
    return {"outcome": outcome, "permission_request": dict(request), "next": {
        "granted": "Call the refused capability again with the same idempotency key and input.",
        "still_pending": f"The person runs `shakerscan approve {request.get('id')}`; wait again.",
    }.get(outcome, "Do not retry the refused action; the permission was not granted.")}


def _run_permissions(args: argparse.Namespace, client: ApiClient) -> Any:
    approval = _approval()
    send = _approval_send(client)
    try:
        if args.permissions_command == "list":
            if args.hunt_id:
                suffix = f"?status={urllib.parse.quote(args.status)}" if args.status else ""
                return client.get(f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/permission-requests{suffix}")
            return {"requests": approval.list_pending(send)}
        request = approval.find_request(send, args.request_id, args.hunt)
        if args.permissions_command == "show":
            return request
        return _permission_wait_outcome(approval.wait_for(send, request, args.seconds))
    except approval.ApprovalError as exc:
        raise CliError(str(exc)) from exc


def _awaiting_permission(exc: CliError, key: str) -> CliError:
    """``hunt call`` refused with 409 permission_required: name the request and the command."""
    detail = exc.api_detail if isinstance(exc.api_detail, Mapping) else {}
    request = detail.get("permission_request") if isinstance(detail.get("permission_request"), Mapping) else None
    if exc.http_status != 409 or detail.get("code") != "permission_required" or not request:
        return exc
    return CliError(
        f"awaiting permission: {request.get('title')}. Ask the person to run `shakerscan approve "
        f"{request.get('id')}` in their own terminal; meanwhile do other work, check with `shakerscan "
        f"hunt permissions wait {request.get('id')}`, and on granted call again with --idempotency-key "
        f"{key} and the same input. On denied or expired, do not retry.",
        error_type="awaiting_permission", http_status=409, api_detail=dict(detail),
    )


def _run_hunt(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.hunt_command == "skills":
        query = {}
        if args.target_kind:
            query["target_kind"] = args.target_kind
        if args.support:
            query["support"] = args.support
        if args.goal is not None:
            query["goal"] = args.goal
        suffix = f"?{urllib.parse.urlencode(query)}" if query else ""
        return client.get(f"/hunt/skills{suffix}")
    if args.hunt_command == "skill-suggest":
        return client.post(
            f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/skills/suggestions",
            {"signals": list(dict.fromkeys(args.signal))},
        )
    if args.hunt_command == "skill-read":
        return client.post(
            "/hunts/{}/skills/{}/read".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.skill_id, safe=""),
            ),
            {},
        )
    if args.hunt_command == "skill-bind":
        return client.post(
            "/hunts/{}/skills/{}/bind".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.skill_id, safe=""),
            ),
            {
                "reason": args.reason or "",
                "evidence_refs": list(dict.fromkeys(args.evidence_ref)),
            },
        )
    if args.hunt_command == "skill-unbind":
        query = urllib.parse.urlencode({"reason": args.reason}) if args.reason else ""
        path = "/hunts/{}/skills/{}".format(
            urllib.parse.quote(args.hunt_id, safe=""),
            urllib.parse.quote(args.skill_id, safe=""),
        )
        return client.delete(f"{path}?{query}" if query else path)
    if args.hunt_command == "skill-usage":
        return client.post(
            "/hunts/{}/skills/{}/usage".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.skill_id, safe=""),
            ),
            {
                "state": args.state,
                "action_id": args.action_id,
                "evidence_refs": list(dict.fromkeys(args.evidence_ref)),
                "reason": args.reason or "",
            },
        )
    if args.hunt_command == "start":
        contract = client.get("/hunts/contract")
        if not isinstance(contract, Mapping):
            raise CliError("running server returned an invalid Hunt contract")
        payload = _hunt_start_payload(args, contract)
        headers = _start_preauthorization(args, client, payload)
        return client.request(
            "POST", "/hunts", payload=payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key), headers=headers,
        )
    if args.hunt_command == "get":
        return client.get(f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}")
    if args.hunt_command == "list":
        query = {"limit": str(args.limit)}
        if args.target_id:
            query["target_id"] = args.target_id
        if args.status:
            query["status"] = args.status
        return client.get(f"/hunts?{urllib.parse.urlencode(query)}")
    if args.hunt_command == "query":
        filters = _read_json(args.filter, default={})
        if not isinstance(filters, dict):
            raise CliError("Hunt query filter must be one JSON object")
        return client.post(
            f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/query",
            {"kind": args.kind, "filter": filters, "limit": args.limit,
             **({"cursor": args.cursor} if getattr(args, "cursor", None) else {})},
        )
    if args.hunt_command == "call":
        run = client.get(f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}")
        if not isinstance(run, Mapping):
            raise CliError("running server returned an invalid Hunt record")
        capability_names = {
            str(item.get("name") if isinstance(item, Mapping) else item)
            for item in run.get("capabilities") or ()
        }
        if args.capability_name not in capability_names:
            raise CliError("capability is not present in the server-returned Hunt manifest")
        inputs = _read_json(args.input, default={})
        if not isinstance(inputs, dict):
            raise CliError("Hunt capability input must be one JSON object")
        key = _validate_idempotency_key(args.idempotency_key) or _content_idempotency_key(
            args.hunt_id, args.capability_name, inputs,
        )
        path = "/hunts/{}/capabilities/{}".format(
            urllib.parse.quote(args.hunt_id, safe=""),
            urllib.parse.quote(args.capability_name, safe=""),
        )
        # Exactly the engine's request body (HuntCapabilityRequest); D43.
        body = {"idempotency_key": key, "input": inputs}
        try:
            response = _settled_capability(client, path, body)
        except CliError as exc:
            raise _awaiting_permission(exc, key) from exc
        return {"idempotency_key": key, "response": response}
    if args.hunt_command == "candidate":
        if args.request:
            payload = _read_json(args.request, default={})
            if not isinstance(payload, dict):
                raise CliError("Hunt candidate request must be one JSON object")
        else:
            if not args.family or not args.title or not args.claim or not args.evidence_ref:
                raise CliError(
                    "candidate requires --family, --title, --claim, and --evidence-ref"
                )
            locus = _read_json(args.locus, default={})
            if not isinstance(locus, dict):
                raise CliError("Hunt candidate locus must be one JSON object")
            payload = {
                "family": args.family,
                "locus": locus,
                "title": args.title,
                "claim": args.claim,
                "severity": args.severity,
                "evidence_refs": list(dict.fromkeys(args.evidence_ref)),
            }
            if args.verifier_contract_id:
                payload["verifier_contract_id"] = args.verifier_contract_id
        return client.post(
            f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/candidates",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.hunt_command == "candidate-update":
        if args.request:
            payload = _read_json(args.request, default={})
            if not isinstance(payload, dict):
                raise CliError("Hunt candidate update must be one JSON object")
        else:
            payload = {
                key: value
                for key, value in {
                    "title": args.title,
                    "claim": args.claim,
                    "severity": args.severity,
                    "evidence_refs": (
                        list(dict.fromkeys(args.evidence_ref))
                        if args.evidence_ref else None
                    ),
                    "verifier_contract_id": args.verifier_contract_id,
                }.items()
                if value is not None
            }
        if not payload:
            raise CliError("candidate-update requires --request or at least one changed field")
        return client.request(
            "PATCH",
            "/hunts/{}/candidates/{}".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.candidate_id, safe=""),
            ),
            payload=payload,
        )
    if args.hunt_command == "candidate-delete":
        return client.request(
            "DELETE",
            "/hunts/{}/candidates/{}".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.candidate_id, safe=""),
            ),
        )
    if args.hunt_command == "verify":
        return client.post(
            "/hunts/{}/candidates/{}/verify".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.candidate_id, safe=""),
            ),
        )
    if args.hunt_command == "finish":
        return client.post(
            f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/finish",
            {"summary": args.summary, "next_actions": args.next_action},
        )
    if args.hunt_command == "permissions":
        return _run_permissions(args, client)
    if args.hunt_command in {"cancel", "resume"}:
        return client.post(
            f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}/{args.hunt_command}",
        )
    raise CliError("unknown Hunt command")


def _run_credentials(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.credentials_command == "create":
        schema = _openapi_schema(client, "CredentialProfileCreate")
        payload = _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="credential create request",
        )
        return client.post(
            "/credential-profiles",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.credentials_command == "rotate":
        schema = _openapi_schema(client, "CredentialProfileRotate")
        payload = _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="credential rotation request",
        )
        profile_id = urllib.parse.quote(args.profile_id, safe="")
        return client.post(
            f"/credential-profiles/{profile_id}/rotate",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.credentials_command == "test":
        profile_id = urllib.parse.quote(args.profile_id, safe="")
        result = client.get(f"/credential-profiles/{profile_id}")
        profile = result.get("profile") if isinstance(result, Mapping) else None
        if not isinstance(profile, Mapping):
            raise CliError("running server returned invalid credential metadata")
        checks = {
            "active": profile.get("status") == "active",
            "execution_compatible": profile.get("execution_compatible") is True,
            "storage_encrypted": profile.get("storage_encrypted") is True,
            "encryption_available": profile.get("encryption_available") is True,
            "target_bound": bool(profile.get("target_id") and profile.get("target_kind")),
        }
        if args.capability:
            allowed = {str(item) for item in profile.get("allowed_capabilities") or ()}
            checks["capability_allowed"] = args.capability in allowed
        return {
            "schema_version": "credential-admission-test/v1",
            "profile_id": str(profile.get("profile_id") or args.profile_id),
            "test_mode": "metadata_admission",
            "passed": all(checks.values()),
            "checks": checks,
            "profile": profile,
            "note": (
                "This content-free check validates storage, lifecycle, target binding, and "
                "capability admission. Exercise the profile against its target through a "
                "target-bound Hunt capability."
            ),
        }
    raise CliError("unknown credentials command")


def _collection_upload_payload(
    args: argparse.Namespace, client: ApiClient,
) -> dict[str, Any]:
    schema = _openapi_schema(client, "RequestCollectionCreate")
    if args.request:
        return _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="request collection upload",
        )
    if not args.target_id or not args.document:
        raise CliError("collections upload requires --target-id and a document")
    payload: dict[str, Any] = {
        "target_id": args.target_id,
        "document": _read_document(args.document),
        "format": args.format,
        "import_limit": args.import_limit,
        "max_document_bytes": MAX_DOCUMENT_BYTES,
    }
    for name in ("name", "environment_name", "base_url"):
        value = getattr(args, name)
        if value is not None:
            payload[name] = value
    if args.environment:
        payload["environment"] = _read_document(args.environment)
    return _validate_schema_object(payload, schema, label="request collection upload")


def _run_collections(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.collections_command == "upload":
        return client.post(
            "/request-collections",
            _collection_upload_payload(args, client),
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    collection_id = urllib.parse.quote(args.collection_id, safe="")
    if args.collections_command == "bind":
        schema = _openapi_schema(client, "RequestCollectionBindingUpsert")
        if args.request:
            payload = _read_json(args.request, default={})
        else:
            payload = {
                "target_kind": args.target_kind,
                "target_id": args.target_id,
                "allowed_origins": list(dict.fromkeys(args.allowed_origin)),
            }
            if args.environment_id:
                payload["environment_id"] = args.environment_id
        payload = _validate_schema_object(
            payload, schema, label="request collection binding",
        )
        return client.post(
            f"/request-collections/{collection_id}/bindings",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.collections_command == "select":
        schema_name = (
            "RequestCollectionSelect"
            if args.preview
            else "RequestCollectionSelectionUpsert"
        )
        schema = _openapi_schema(client, schema_name)
        if args.request:
            payload = _read_json(args.request, default={})
        elif args.preview:
            if args.name or args.binding_id or args.disposable_credentials:
                raise CliError(
                    "collection preview does not accept durable selection fields"
                )
            payload = {
                "request_ids": list(dict.fromkeys(args.request_id)),
                "folders": list(dict.fromkeys(args.folder)),
                "methods": list(dict.fromkeys(method.upper() for method in args.method)),
                "tags": list(dict.fromkeys(args.tag)),
                "safe_methods_only": not args.include_mutating,
                "limit": args.limit,
            }
            if args.path_regex:
                payload["path_regex"] = args.path_regex
        else:
            if not args.name or not args.binding_id:
                raise CliError(
                    "durable collection selection requires --name and --binding-id; "
                    "use --preview for a non-durable preview"
                )
            if (
                args.include_mutating
                and args.replay_policy not in {"confirmed_active", "safe_authentication"}
            ):
                raise CliError(
                    "--include-mutating requires --replay-policy confirmed_active "
                    "or safe_authentication"
                )
            payload = {
                "name": args.name,
                "binding_id": args.binding_id,
                "replay_policy": args.replay_policy,
                "request_ids": list(dict.fromkeys(args.request_id)),
                "folders": list(dict.fromkeys(args.folder)),
                "methods": list(dict.fromkeys(method.upper() for method in args.method)),
                "tags": list(dict.fromkeys(args.tag)),
                "safe_methods_only": not args.include_mutating,
                "max_requests": args.limit,
                "disposable_credentials": args.disposable_credentials,
            }
            if args.path_regex:
                payload["path_regex"] = args.path_regex
        payload = _validate_schema_object(
            payload, schema, label="request collection selection",
        )
        endpoint = "select" if args.preview else "selections"
        return client.post(
            f"/request-collections/{collection_id}/{endpoint}",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    raise CliError("unknown collections command")


def _write_export(path: str, value: bytes, *, force: bool) -> Path:
    output = Path(path).expanduser()
    if output.exists() and not force:
        raise CliError("evidence export output already exists; use --force to replace it")
    temporary: Path | None = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_bytes(value)
        if force:
            temporary.replace(output)
        else:
            os.link(temporary, output)
            temporary.unlink()
    except FileExistsError as exc:
        raise CliError(
            "evidence export output already exists; use --force to replace it"
        ) from exc
    except OSError as exc:
        raise CliError(f"cannot write evidence export: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return output.resolve()


def _run_evidence(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.evidence_command != "export":
        raise CliError("unknown evidence command")
    query: dict[str, str] = {"limit": str(args.limit)}
    for name in ("scan_id", "finding_id", "retention_class"):
        value = getattr(args, name)
        if value:
            query[name] = str(value)
    if args.format == "manifest":
        path = f"/evidence/export-manifest?{urllib.parse.urlencode(query)}"
    else:
        query["format"] = args.format
        query["record_event"] = "true" if args.record_event else "false"
        path = f"/evidence/export-bundle?{urllib.parse.urlencode(query)}"
    raw, content_type = client.download(path)
    if args.format == "zip" and "zip" not in content_type.lower():
        raise CliError("running server did not return the requested evidence zip")
    if args.output:
        output = _write_export(args.output, raw, force=args.force)
        return {
            "schema_version": "evidence-cli-export/v1",
            "format": args.format,
            "output": str(output),
            "bytes": len(raw),
            "content_type": content_type,
        }
    if args.format == "zip":
        raise CliError("zip evidence export requires --output")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("running server returned invalid evidence JSON") from exc


DEFAULT_TIMEOUT_SECONDS = 60.0


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number of seconds") from None
    if not 0 < seconds <= 3600:
        raise argparse.ArgumentTypeError("must be between 0 and 3600 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan",
        description="Canonical ShakerScan V2 command line",
    )
    parser.add_argument("--api-url", required=True, help=argparse.SUPPRESS)
    parser.add_argument(
        "--timeout", type=_positive_seconds, metavar="SECONDS",
        help=f"seconds to wait for each API answer (default {DEFAULT_TIMEOUT_SECONDS:g})",
    )
    products = parser.add_subparsers(dest="product", required=True)

    hunt = products.add_parser("hunt", help="Manage the complete canonical Hunt lifecycle")
    hunt_commands = hunt.add_subparsers(dest="hunt_command", required=True)
    hunt_skills = hunt_commands.add_parser(
        "skills", help="List or suggest server-shipped Hunt methodologies",
    )
    hunt_skills.add_argument("--target-kind")
    hunt_skills.add_argument("--support", choices=("supported", "partial", "reference"))
    hunt_skills.add_argument("--goal", help="Return deterministic advisory suggestions for this objective")
    hunt_skill_suggest = hunt_commands.add_parser(
        "skill-suggest", help="Get a compact adaptive methodology shortlist for one Hunt",
    )
    hunt_skill_suggest.add_argument("hunt_id")
    hunt_skill_suggest.add_argument(
        "--signal", action="append", default=[],
        help="Observed technology or surface signal (repeatable; bodies are not loaded)",
    )
    hunt_skill_read = hunt_commands.add_parser(
        "skill-read", help="Load exactly one methodology for an active Hunt",
    )
    hunt_skill_read.add_argument("hunt_id")
    hunt_skill_read.add_argument("skill_id")
    hunt_skill_bind = hunt_commands.add_parser(
        "skill-bind", help="Bind one reviewed methodology without changing Hunt authority",
    )
    hunt_skill_bind.add_argument("hunt_id")
    hunt_skill_bind.add_argument("skill_id")
    hunt_skill_bind.add_argument("--reason")
    hunt_skill_bind.add_argument("--evidence-ref", action="append", default=[])
    hunt_skill_unbind = hunt_commands.add_parser(
        "skill-unbind", help="Remove one explicitly selected methodology",
    )
    hunt_skill_unbind.add_argument("hunt_id")
    hunt_skill_unbind.add_argument("skill_id")
    hunt_skill_unbind.add_argument("--reason")
    hunt_skill_usage = hunt_commands.add_parser(
        "skill-usage", help="Record evidenced methodology use or completion",
    )
    hunt_skill_usage.add_argument("hunt_id")
    hunt_skill_usage.add_argument("skill_id")
    hunt_skill_usage.add_argument("state", choices=("used", "completed", "deferred"))
    hunt_skill_usage.add_argument("--action-id")
    hunt_skill_usage.add_argument("--evidence-ref", action="append", default=[])
    hunt_skill_usage.add_argument("--reason")
    hunt_start = hunt_commands.add_parser("start", help="Start a target-bound Hunt")
    hunt_start.add_argument("--request", metavar="FILE", help="Complete JSON contract; use - for stdin")
    hunt_start.add_argument("--idempotency-key")
    hunt_start.add_argument("--target-id")
    hunt_start.add_argument("--target-kind")
    hunt_start.add_argument("--goal", default="Investigate the authorized target.")
    hunt_start.add_argument("--budget-profile", default="balanced")
    hunt_start.add_argument("--active-testing", action="store_true")
    hunt_start.add_argument("--allow-state-changing-http", action="store_true")
    hunt_start.add_argument("--network-discovery", action="store_true")
    hunt_start.add_argument("--allow-oob-interactions", action="store_true")
    hunt_start.add_argument("--authorized", action="store_true")
    hunt_start.add_argument("--approval-receipt-id")
    hunt_start.add_argument("--scope-receipt-id")
    hunt_start.add_argument("--budget", action="append", default=[], metavar="NAME=VALUE")
    hunt_start.add_argument(
        "--credential-ref", action="append", default=[], metavar="SLOT=ID",
        help=(
            "attach a credential profile (repeatable). SLOT is "
            + ", ".join(CREDENTIAL_REF_SLOTS)
            + " or the full field name (primary_credential_profile_id, ...)"
        ),
    )
    hunt_start.add_argument("--capability", action="append", default=[])
    hunt_start.add_argument("--collection-id", action="append", default=[])
    hunt_start.add_argument(
        "--allow", action="append", default=[], metavar="BOUND",
        help=(
            "pre-authorize requests inside this bound (repeatable): budget.raise:2x, "
            "credential.use:<targets>, target.authorize:<patterns>, capability:state-changing, "
            "capability:active-testing. Enterprise asks for your step-up first"
        ),
    )
    hunt_start.add_argument(
        "--propose-allow", action="append", default=[], metavar="BOUND",
        help="propose bounds for a person to approve (one pending request); for agents",
    )
    hunt_start.add_argument(
        "--agent-may-see-secrets", action="store_true",
        help=(
            "let this Hunt's agent read the values of the target's discovered secrets through "
            "secrets.inspect (off by default: the agent sends them by secret:// reference only). "
            "Your choice, recorded as yours; an agent cannot set it"
        ),
    )
    hunt_start.add_argument("--preauthorization", help="Enterprise: a pre-authorization id from an earlier step-up")
    hunt_start.add_argument("--account", help="Enterprise step-up: your sign-in name")
    hunt_start.add_argument("--method", choices=("totp", "security_key", "sso"), help="Enterprise step-up method")
    hunt_start.add_argument(
        "--skill-id", action="append", default=[],
        help=(
            "Pre-bind an already reviewed methodology (repeatable; normally start empty and "
            "use skill-suggest, skill-read, then skill-bind)"
        ),
    )

    hunt_get = hunt_commands.add_parser("get", help="Read one Hunt and its capability manifest")
    hunt_get.add_argument("hunt_id")

    hunt_list = hunt_commands.add_parser("list", help="List Hunts using bounded server filters")
    hunt_list.add_argument("--target-id")
    hunt_list.add_argument("--status")
    hunt_list.add_argument("--limit", type=int, choices=range(1, 201), default=50, metavar="N", help="1-200 (default: 50)")

    hunt_query = hunt_commands.add_parser("query", help="Query bounded Hunt context")
    hunt_query.add_argument("hunt_id")
    hunt_query.add_argument(
        "kind",
        choices=(
            "summary", "endpoints", "endpoint_groups", "findings", "hypotheses", "principals",
            "graph_nodes", "graph_edges", "services", "service_intelligence", "scans", "collections",
            "candidates", "notes", "receipts", "interpretations", "negative_results", "changes",
            "continue",
        ),
    )
    hunt_query.add_argument("--filter", metavar="FILE", help="JSON object; use - for stdin")
    hunt_query.add_argument("--limit", type=int, choices=range(1, 501), default=100, metavar="N", help="1-500 (default: 100)")
    hunt_query.add_argument(
        "--cursor", help="next_cursor from the previous page; keep kind and filter unchanged",
    )

    hunt_permissions = hunt_commands.add_parser(
        "permissions", help="Read permission requests (server-rendered text) and wait for decisions",
    )
    permission_commands = hunt_permissions.add_subparsers(dest="permissions_command", required=True)
    permissions_list = permission_commands.add_parser(
        "list", help="Pending requests of every open Hunt, or every request of one Hunt",
    )
    permissions_list.add_argument("hunt_id", nargs="?")
    permissions_list.add_argument("--status", choices=("pending", "granted", "denied", "expired", "withdrawn"))
    permissions_show = permission_commands.add_parser("show", help="One request, with its server-rendered text")
    permissions_show.add_argument("request_id", help="the permission request id (the Hunt goes in --hunt)")
    permissions_show.add_argument("--hunt", help="the request's Hunt (found automatically otherwise)")
    permissions_wait = permission_commands.add_parser(
        "wait", help="Wait for the person's decision: granted, denied, expired, withdrawn or still_pending",
    )
    permissions_wait.add_argument("request_id", help="the permission request id (the Hunt goes in --hunt)")
    permissions_wait.add_argument("--hunt", help="the request's Hunt (found automatically otherwise)")
    permissions_wait.add_argument("--seconds", type=_positive_seconds, default=300.0, help="how long to wait (default 300)")

    hunt_call = hunt_commands.add_parser("call", help="Call one server-returned capability")
    hunt_call.add_argument("hunt_id")
    hunt_call.add_argument("capability_name")
    hunt_call.add_argument("--input", metavar="FILE", help="JSON object; use - for stdin")
    hunt_call.add_argument("--idempotency-key")

    hunt_candidate = hunt_commands.add_parser("candidate", help="Record a bounded investigation candidate")
    hunt_candidate.add_argument("hunt_id")
    hunt_candidate.add_argument("--request", metavar="FILE", help="Complete JSON request; use - for stdin")
    hunt_candidate.add_argument("--family")
    hunt_candidate.add_argument("--locus", metavar="FILE", help="JSON locus object; use - for stdin")
    hunt_candidate.add_argument("--title")
    hunt_candidate.add_argument("--claim")
    hunt_candidate.add_argument("--severity", choices=("critical", "high", "medium", "low", "info"), default="info")
    hunt_candidate.add_argument("--evidence-ref", action="append", default=[])
    hunt_candidate.add_argument("--verifier-contract-id")
    hunt_candidate.add_argument("--idempotency-key")

    hunt_candidate_update = hunt_commands.add_parser(
        "candidate-update", help="Correct metadata on a Hunt-owned candidate",
    )
    hunt_candidate_update.add_argument("hunt_id")
    hunt_candidate_update.add_argument("candidate_id")
    hunt_candidate_update.add_argument("--request", metavar="FILE", help="Complete JSON update; use - for stdin")
    hunt_candidate_update.add_argument("--title")
    hunt_candidate_update.add_argument("--claim")
    hunt_candidate_update.add_argument("--severity", choices=("critical", "high", "medium", "low", "info"))
    hunt_candidate_update.add_argument("--evidence-ref", action="append", default=[])
    hunt_candidate_update.add_argument("--verifier-contract-id")

    hunt_candidate_delete = hunt_commands.add_parser(
        "candidate-delete", help="Delete a Hunt-owned candidate while preserving its audit record",
    )
    hunt_candidate_delete.add_argument("hunt_id")
    hunt_candidate_delete.add_argument("candidate_id")

    hunt_verify = hunt_commands.add_parser("verify", help="Run canonical deterministic candidate verification")
    hunt_verify.add_argument("hunt_id")
    hunt_verify.add_argument("candidate_id")

    hunt_finish = hunt_commands.add_parser("finish", help="Finish a Hunt with its debrief")
    hunt_finish.add_argument("hunt_id")
    hunt_finish.add_argument("--summary", required=True)
    hunt_finish.add_argument("--next-action", action="append", default=[])

    hunt_cancel = hunt_commands.add_parser("cancel", help="Cancel an active Hunt")
    hunt_cancel.add_argument("hunt_id")
    hunt_resume = hunt_commands.add_parser("resume", help="Resume a paused or interrupted Hunt")
    hunt_resume.add_argument("hunt_id")

    for command, text in (
        ("approve", "Allow a Hunt permission request in your own terminal (Enterprise: with your step-up)"),
        ("deny", "Deny a Hunt permission request in your own terminal (Enterprise: with your step-up)"),
    ):
        _approval().add_arguments(products.add_parser(command, help=text), command)

    secrets = products.add_parser(
        "secrets", help="Secrets discovered on a target: list (never values), revoke, expiry, grant, promote, reveal",
    )
    secret_commands = secrets.add_subparsers(dest="store_command", required=True)
    listed = secret_commands.add_parser("list", help="A target's discovered secrets: reference, kind, field, "
                                                     "length, when seen, uses (never the value)")
    listed.add_argument("target_id")
    listed.add_argument("--usable", action="store_true", help="only those a Hunt can use now")
    listed.add_argument("--limit", type=_reference_list_limit, default=REFERENCE_LIST_DEFAULT, metavar="N",
                        help=f"show at most N, newest sighting first (default {REFERENCE_LIST_DEFAULT}, "
                             f"at most {REFERENCE_LIST_MAX})")
    listed.add_argument("--json", action="store_true", help="print the raw API answer")
    for name, text in (("revoke", "Stop Hunts using a secret (an operator decision later sightings keep)"),
                       ("reactivate", "Let Hunts use a revoked secret again")):
        command = secret_commands.add_parser(name, help=text)
        command.add_argument("target_id")
        command.add_argument("reference", metavar="SECRET", help="the id or secret://<id> reference")
    expiry = secret_commands.add_parser("expiry", help="Set a secret's expiry, 1-365 days from now")
    expiry.add_argument("target_id")
    expiry.add_argument("reference", metavar="SECRET")
    expiry.add_argument("--days", type=int, required=True)
    for name, text in (("grant", "Let another target's Hunts use a secret (your step-up on Enterprise)"),
                       ("ungrant", "Stop another target's Hunts using a secret")):
        command = secret_commands.add_parser(name, help=text)
        command.add_argument("target_id")
        command.add_argument("reference", metavar="SECRET")
        command.add_argument("--to", required=True, metavar="TARGET_ID", help="the other target")
    promote = secret_commands.add_parser(
        "promote", help="Move a secret into a new credential profile of the target (your step-up on Enterprise)")
    promote.add_argument("target_id")
    promote.add_argument("reference", metavar="SECRET")
    promote.add_argument("--name", required=True)
    promote.add_argument("--auth-kind", required=True,
                         help="bearer_token, api_key_header, authorization_header, cookie, basic_auth, ...")
    promote.add_argument("--header-name")
    promote.add_argument("--parameter-name")
    promote.add_argument("--username")
    reveal = secret_commands.add_parser(
        "reveal", help="Show a secret's value to you, in your own terminal (your step-up on Enterprise)")
    reveal.add_argument("target_id")
    reveal.add_argument("reference", metavar="SECRET")
    for command in (promote, reveal) + tuple(
            secret_commands.choices[name] for name in ("grant",)):
        command.add_argument("--account", default=None, help="Enterprise: your account (default: the token's)")
        command.add_argument("--method", choices=["totp", "security-key", "security_key", "sso"], default=None)

    knowledge = products.add_parser(
        "knowledge", help="Review proposals, read interpretations, and dismiss or reopen findings in your own terminal",
    )
    knowledge_commands = knowledge.add_subparsers(dest="knowledge_command", required=True)
    review = knowledge_commands.add_parser(
        "review",
        help=("Show each pending instruction or saved-action proposal as a diff, and agent-written instructions "
              "no operator confirmed, and decide each with a keypress"),
    )
    review.add_argument("target_id", nargs="?", help="only this target's proposals (default: every target)")
    decided = review.add_mutually_exclusive_group()
    decided.add_argument("--accept", metavar="ID", help="show this proposal and accept it after a keypress")
    decided.add_argument("--reject", metavar="ID", help="show this proposal and reject it after a keypress")
    review.add_argument("--note", default=None, help="a note recorded with the decision")
    show = knowledge_commands.add_parser(
        "show", help="Show a target's interpretations and negative results (read-only)",
    )
    show.add_argument("target_id", help="the target whose interpretations to show")
    show.add_argument("--kind", choices=["observation", "hypothesis", "explanation", "next_step", "note",
                                         "negative_result"])
    show.add_argument("--status", choices=["active", "superseded", "retracted", "reopened"], default="active")
    show.add_argument("--limit", type=int, default=50)
    show.add_argument("--json", action="store_true", help="print the raw API answers")
    changes = knowledge_commands.add_parser(
        "changes", help="Show what changed on a target since a point and which interpretations it affects (read-only)",
    )
    changes.add_argument("target_id", help="the target to compare")
    changes.add_argument("--since", default="last_hunt",
                         help="last_hunt (default), release, scan:<id>, hunt:<id>, or an ISO-8601 time with a time zone")
    changes.add_argument("--json", action="store_true", help="print the raw API answer")
    proceed = knowledge_commands.add_parser(
        "continue",
        help=("Continue investigating a target after its latest release: what changed, what still applies, what "
              "needs re-testing, and the next experiments ranked (read-only; --refresh offers a passive Scan)"),
    )
    proceed.add_argument("target_id", help="the target to continue")
    proceed.add_argument("--since", default="release",
                         help="release (default), release:<marker id>, last_hunt, scan:<id>, hunt:<id>, or an ISO time")
    proceed.add_argument("--refresh", action="store_true",
                         help="after showing the report, offer the passive refresh it proposes and start it only "
                              "after a keypress")
    proceed.add_argument("--json", action="store_true", help="print the raw API answer")
    pages = proceed.add_mutually_exclusive_group()
    pages.add_argument("--after", default=None, help="the next_after cursor of a previous page")
    pages.add_argument("--all", action="store_true",
                       help="every page of ranked experiments (starts again if the set changes while reading)")
    measures = knowledge_commands.add_parser(
        "measures",
        help=("How continuing after the release went on a target, from server records: required re-tests run, "
              "time to the first useful step, redundant requests, new results, contradicted skip advice (read-only)"),
    )
    measures.add_argument("target_id")
    measures.add_argument("--since", default="release",
                          help="release (default), release:<marker id>, scan:<id>, hunt:<id>, or an ISO time")
    measures.add_argument("--json", action="store_true", help="print the raw API answer")
    usage = knowledge_commands.add_parser(
        "usage", help="Who read continue reports, per ISO week, across this installation (read-only)")
    usage.add_argument("--weeks", type=int, default=8)
    usage.add_argument("--json", action="store_true", help="print the raw API answer")
    release = knowledge_commands.add_parser(
        "release", help="Declare that a target was released (the point `continue` starts from), after a keypress",
    )
    release.add_argument("target_id")
    release.add_argument("--label", default=None, help="a short label, for example the version")
    release.add_argument("--at", default=None, help="when it was released (ISO-8601 with a time zone; default now)")
    releases = knowledge_commands.add_parser("releases", help="List the releases declared for a target (read-only)")
    releases.add_argument("target_id")
    releases.add_argument("--json", action="store_true", help="print the raw API answer")
    dismiss = knowledge_commands.add_parser(
        "dismiss", help="Dismiss a finding (false positive, accepted risk or duplicate) after a keypress",
    )
    dismiss.add_argument("target_id")
    dismiss.add_argument("finding_id")
    dismiss.add_argument("--reason", required=True, choices=["false_positive", "accepted_risk", "duplicate"])
    dismiss.add_argument("--note", required=True, help="why; recorded with the decision")
    reopen = knowledge_commands.add_parser(
        "reopen", help="Reopen a dismissed finding for review after a keypress",
    )
    reopen.add_argument("target_id")
    reopen.add_argument("finding_id")
    reopen.add_argument("--note", required=True, help="why; recorded with the decision")
    allow_changes = knowledge_commands.add_parser(
        "allow-changes",
        help=("Let Hunts edit one target's instructions and saved actions directly instead of proposing "
              "changes (instruction_changes), after a keypress; --off turns it off again"),
    )
    allow_changes.add_argument("target_id", help="the target whose Hunt permissions change")
    allow_changes.add_argument("--off", action="store_true",
                               help="stop Hunts editing the instructions directly (no step-up needed)")
    for command in (review, allow_changes, release, dismiss, reopen):
        command.add_argument("--account", help="Enterprise: your sign-in name (asked for otherwise)")
        command.add_argument("--method", choices=("totp", "security_key", "sso"),
                             help="Enterprise step-up: a TOTP code, or a USB/NFC security key (needs python-fido2)")

    credentials = products.add_parser(
        "credentials", help="Create, rotate, or admission-test an encrypted profile",
    )
    credential_commands = credentials.add_subparsers(
        dest="credentials_command", required=True,
    )
    credential_create = credential_commands.add_parser(
        "create", help="Create from server-contract JSON read from a file or stdin",
    )
    credential_create.add_argument("--request", required=True, metavar="FILE")
    credential_create.add_argument("--idempotency-key")
    credential_rotate = credential_commands.add_parser(
        "rotate", help="Rotate from server-contract JSON read from a file or stdin",
    )
    credential_rotate.add_argument("profile_id")
    credential_rotate.add_argument("--request", required=True, metavar="FILE")
    credential_rotate.add_argument("--idempotency-key")
    credential_test = credential_commands.add_parser(
        "test", help="Run a content-free storage and execution-admission check",
    )
    credential_test.add_argument("profile_id")
    credential_test.add_argument("--capability")

    collections = products.add_parser(
        "collections", help="Upload, bind, or select an encrypted request collection",
    )
    collection_commands = collections.add_subparsers(
        dest="collections_command", required=True,
    )
    collection_upload = collection_commands.add_parser(
        "upload", help="Import Postman, HAR, OpenAPI, or Swagger input",
    )
    collection_upload.add_argument("document", nargs="?")
    collection_upload.add_argument("--request", metavar="FILE")
    collection_upload.add_argument("--target-id")
    collection_upload.add_argument("--name")
    collection_upload.add_argument("--format", default="auto")
    collection_upload.add_argument("--environment")
    collection_upload.add_argument("--environment-name")
    collection_upload.add_argument("--base-url")
    collection_upload.add_argument("--import-limit", type=int, default=5_000)
    collection_upload.add_argument("--idempotency-key")
    collection_bind = collection_commands.add_parser(
        "bind", help="Bind a collection to one exact target and origin set",
    )
    collection_bind.add_argument("collection_id")
    collection_bind.add_argument("--request", metavar="FILE")
    collection_bind.add_argument("--target-kind")
    collection_bind.add_argument("--target-id")
    collection_bind.add_argument("--allowed-origin", action="append", default=[])
    collection_bind.add_argument("--environment-id")
    collection_bind.add_argument("--idempotency-key")
    collection_select = collection_commands.add_parser(
        "select", help="Save one bounded request selection and return its durable ID",
    )
    collection_select.add_argument("collection_id")
    collection_select.add_argument("--request", metavar="FILE")
    collection_select.add_argument("--name")
    collection_select.add_argument("--binding-id")
    collection_select.add_argument(
        "--replay-policy",
        choices=(
            "discovery_only", "safe_reads", "safe_authentication",
            "confirmed_active",
        ),
        default="safe_reads",
    )
    collection_select.add_argument("--request-id", action="append", default=[])
    collection_select.add_argument("--folder", action="append", default=[])
    collection_select.add_argument("--method", action="append", default=[])
    collection_select.add_argument("--path-regex")
    collection_select.add_argument("--tag", action="append", default=[])
    collection_select.add_argument("--include-mutating", action="store_true")
    collection_select.add_argument("--disposable-credentials", action="store_true")
    collection_select.add_argument(
        "--preview", action="store_true",
        help="Preview matching redacted requests without saving a selection",
    )
    collection_select.add_argument("--limit", type=int, default=500)
    collection_select.add_argument("--idempotency-key")

    evidence = products.add_parser(
        "evidence", help="Export content-free evidence manifests or bundles",
    )
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_export = evidence_commands.add_parser(
        "export", help="Export a filtered manifest, JSON bundle, or metadata zip",
    )
    evidence_export.add_argument("--scan-id")
    evidence_export.add_argument("--finding-id")
    evidence_export.add_argument("--retention-class")
    evidence_export.add_argument("--limit", type=int, default=200)
    evidence_export.add_argument("--format", choices=("manifest", "json", "zip"), default="manifest")
    evidence_export.add_argument("--record-event", action="store_true")
    evidence_export.add_argument("--output")
    evidence_export.add_argument("--force", action="store_true")
    return parser


def _selected_parser(parser: argparse.ArgumentParser, args: argparse.Namespace) -> argparse.ArgumentParser:
    """The innermost subcommand parser ``args`` went through (``hunt permissions show``)."""
    for action in parser._actions:  # argparse keeps its subparsers only here
        if isinstance(action, argparse._SubParsersAction):
            chosen = action.choices.get(getattr(args, action.dest, None) or "")
            if chosen is not None:
                return _selected_parser(chosen, args)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    # O3: argparse reports arguments left over by a subcommand with the top-level usage, so
    # `hunt permissions show <hunt> <request>` printed the whole CLI's usage. The subcommand that
    # was used reports them instead, with its own usage.
    args, extra = parser.parse_known_args(argv)
    if extra:
        _selected_parser(parser, args).error(f"unrecognized arguments: {' '.join(extra)}")
    try:
        token = os.environ.get("SHAKERSCAN_API_TOKEN", "").strip() or None
        if token and (len(token) > 4096 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in token)):
            raise CliError("SHAKERSCAN_API_TOKEN must be printable ASCII without spaces")
        client = ApiClient(args.api_url, api_token=token, timeout=args.timeout or DEFAULT_TIMEOUT_SECONDS)
        if args.product in {"approve", "deny"}:
            return _run_approval(args, client)
        if args.product == "secrets":
            return _run_secrets(args, client)
        if args.product == "knowledge":
            if args.knowledge_command == "show":
                return _run_knowledge_show(args, client)
            if args.knowledge_command == "changes":
                return _run_knowledge_changes(args, client)
            if args.knowledge_command == "continue":
                return _run_knowledge_continue(args, client)
            if args.knowledge_command == "measures":
                return _run_knowledge_measures(args, client)
            if args.knowledge_command == "usage":
                return _run_knowledge_usage(args, client)
            if args.knowledge_command == "release":
                return _run_knowledge_release(args, client)
            if args.knowledge_command == "releases":
                return _run_knowledge_releases(args, client)
            if args.knowledge_command in {"dismiss", "reopen"}:
                return _run_knowledge_decision(args, client)
            if args.knowledge_command == "allow-changes":
                return _run_allow_changes(args, client)
            return _run_knowledge_review(args, client)
        if args.product == "hunt":
            result = _run_hunt(args, client)
        elif args.product == "credentials":
            result = _run_credentials(args, client)
        elif args.product == "collections":
            result = _run_collections(args, client)
        elif args.product == "evidence":
            result = _run_evidence(args, client)
        else:
            raise CliError("unknown command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return _hunt_call_exit(args, result)
    except CliError as exc:
        print(json.dumps(exc.public_dict(), sort_keys=True), file=sys.stderr)
        # 3: a person's decision this shell cannot ask for; refused, nothing ran. 130: the
        # person pressed Ctrl-C at the touch; nothing changed.
        return {"person_decision_required": 3, "person_decision_cancelled": 130}.get(exc.error_type, 2)


def _hunt_call_exit(args: argparse.Namespace, result: Any) -> int:
    """``hunt call`` whose action was refused (a denied, expired or withdrawn permission replayed
    as ``blocked``) exits 2 like any other refusal: the body is a 2xx replay, but nothing ran."""
    if getattr(args, "product", None) != "hunt" or getattr(args, "hunt_command", None) != "call":
        return 0
    response = result.get("response") if isinstance(result, Mapping) else None
    action = response.get("action_result") if isinstance(response, Mapping) else None
    if not isinstance(action, Mapping) or str(action.get("status") or "") != "blocked":
        return 0
    errors = [str(item) for item in action.get("errors") or () if item]
    reason = errors[0] if errors else "blocked"
    print(json.dumps({"error": f"the action was refused ({reason}) and did not run",
                      "error_type": "action_blocked"}, sort_keys=True), file=sys.stderr)
    return 2


def _run_approval(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan approve|deny``: human output, not JSON; the person reads it."""
    approval = _approval()
    try:
        return approval.run(
            args.product, args, _approval_send(client), enterprise=client.api_token is not None,
            origin=client.base_url,
        )
    except approval.ApprovalError as exc:
        print(f"shakerscan {args.product}: {exc}", file=sys.stderr)
        return 2


# --- knowledge review --------------------------------------------------------------------------
#
# Proposals are suggestions (often from a Hunt) to replace a target's instructions or to create,
# change or delete one of its saved actions. Instructions a Hunt wrote that no operator confirmed
# are listed too: confirming saves them, unchanged, as operator instructions.
# Deciding one is the person's act, at their own terminal, with the same keypress hardening as
# `approve --watch`: only a lone key decides; an arrow key, an escape sequence or a paste never does.
# On ShakerScan Enterprise (the connection holds a service token) accepting, confirming and letting
# Hunts edit instructions also take the person's step-up, bound to that one decision (the gateway's
# approval protocol, purpose knowledge_decision, hunt_approve.py): the token alone never does them,
# and the gateway applies the decision itself after the proof. Rejecting and rebasing need no step-up.

KNOWLEDGE_DIFF_LINES = 400
# C0/C1 controls, DEL and bidirectional overrides/isolates, which could reorder the diff on screen.
_CONTROL = {code: "?" for code in [*range(0x00, 0x09), *range(0x0B, 0x20), *range(0x7F, 0xA0),
                                   *range(0x202A, 0x202F), *range(0x2066, 0x206A)]}


def _invisible(character: str) -> bool:
    import unicodedata
    return unicodedata.category(character) in {"Cf", "Zl", "Zp"}


def _shown(value: Any) -> str:
    """Proposal text is written by a Hunt: never let it move the cursor or rewrite the screen.

    Invisible format characters (zero-width, direction marks, tag characters) and line separators
    are shown as visible escapes, so what the person reads is what would be applied."""
    text = str(value if value is not None else "").translate(_CONTROL)
    return "".join((f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}") if _invisible(ch) else ch
                   for ch in text)


def _fully_shown(proposal: Mapping[str, Any]) -> bool:
    diff = proposal.get("diff") if isinstance(proposal.get("diff"), Mapping) else {}
    return not diff.get("truncated") and len(str(diff.get("text") or "").splitlines()) <= KNOWLEDGE_DIFF_LINES


def _render_proposal(proposal: Mapping[str, Any]) -> str:
    target = proposal.get("target_name") or proposal.get("target_url") or proposal.get("target_id")
    proposal = {key: (_shown(value) if isinstance(value, str) else value) for key, value in proposal.items()}
    target = _shown(target)
    kind = "saved action" if proposal.get("kind") == "saved_action" else "instructions"
    if kind == "saved action":
        kind += f" ({proposal.get('action_operation')}" + (
            f" {proposal.get('action_id')})" if proposal.get("action_id") else ")")
    lines = [
        "",
        f"proposal {proposal.get('id')}  target {target} ({proposal.get('target_id')})",
        f"  changes:  {kind}",
        f"  title:    {proposal.get('title')}",
        f"  from:     {proposal.get('proposed_by')}  at {proposal.get('created_at')}",
        f"  reason:   {proposal.get('reason')}",
        f"  evidence: {_shown(', '.join(str(ref) for ref in proposal.get('evidence_refs') or [])) or 'none'}",
        f"  based on: revision {proposal.get('base_revision')} (target now at {proposal.get('current_revision')})",
    ]
    if proposal.get("stale"):
        lines.append("  STALE: the instructions changed after this proposal was made; rebase it before accepting.")
    diff = proposal.get("diff") if isinstance(proposal.get("diff"), Mapping) else {}
    text = _shown(diff.get("text")).splitlines()
    lines.append(f"  diff (+{diff.get('added_lines', 0)} -{diff.get('removed_lines', 0)}):")
    lines.extend("    " + line for line in text[:KNOWLEDGE_DIFF_LINES])
    if len(text) > KNOWLEDGE_DIFF_LINES or diff.get("truncated"):
        lines.append(f"    ... diff cut here; the full text is in GET /targets/{proposal.get('target_id')}"
                     "/instruction-proposals. It cannot be accepted here because it was not shown in full.")
    return "\n".join(lines)


def _proposal_path(proposal: Mapping[str, Any], action: str) -> str:
    return (f"/targets/{urllib.parse.quote(str(proposal['target_id']), safe='')}/instruction-proposals/"
            f"{urllib.parse.quote(str(proposal['id']), safe='')}/{action}")


def _pending_review(send: Any, target_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = (f"/targets/{urllib.parse.quote(target_id, safe='')}/instruction-proposals?status=pending"
            if target_id else "/instruction-proposals?status=pending")
    status, body = send("GET", path)
    if not 200 <= status < 300 or not isinstance(body, Mapping):
        raise _approval().ApprovalError(f"could not list instruction proposals: HTTP {status}: {body}")
    return ([dict(item) for item in body.get("proposals") or [] if isinstance(item, Mapping)],
            [dict(item) for item in body.get("unconfirmed_instructions") or [] if isinstance(item, Mapping)])


def _pending_proposals(send: Any, target_id: str | None) -> list[dict[str, Any]]:
    return _pending_review(send, target_id)[0]


def _render_unconfirmed(item: Mapping[str, Any]) -> tuple[str, bool]:
    """(what is shown, whether it was shown in full) for agent-written, unconfirmed instructions."""
    target = _shown(item.get("target_name") or item.get("target_url") or item.get("target_id"))
    text = _shown(item.get("methodology")).splitlines()
    lines = [
        "",
        f"agent-written, unconfirmed instructions  target {target} ({item.get('target_id')})",
        f"  written by: {_shown(item.get('written_by'))}  at {_shown(item.get('updated_at'))}",
        f"  title:      {_shown(item.get('title'))}  (revision {item.get('revision')})",
        "  Hunts receive this text only as advisory notes. Confirming saves it, unchanged, as the target's "
        "operator instructions.",
        "  text:",
    ]
    lines.extend("    " + line for line in text[:KNOWLEDGE_DIFF_LINES])
    complete = len(text) <= KNOWLEDGE_DIFF_LINES
    if not complete:
        lines.append(f"    ... cut here; read it in GET /targets/{item.get('target_id')}/skill. It cannot be "
                     "confirmed here because it was not shown in full.")
    return "\n".join(lines), complete


def _review_unconfirmed(send: Any, terminal: Any, item: dict[str, Any], stepup: Any = None) -> str:
    shown, complete = _render_unconfirmed(item)
    terminal.say(shown)
    if not complete:
        terminal.key("  [n] not now  [q] quit: ", "nq")
        return "skipped"
    choice = terminal.key("  [c] confirm as operator instructions  [n] not now  [q] quit: ", "cnq")
    if choice == "q":
        return "quit"
    if choice != "c":
        terminal.say("  left unconfirmed")
        return "skipped"
    # Bound to the text that was shown: the server refuses any other text or revision.
    approval = _approval()
    path = f"/targets/{urllib.parse.quote(str(item['target_id']), safe='')}/skill/confirm"
    try:
        status, body = apply_knowledge_decision(
            send, stepup, approval.knowledge_entry(
                "confirm", str(item.get("target_id")), text_sha256=item.get("body_sha256"),
                expected_revision=item.get("revision")) if stepup is not None else {},
            "POST", path, {"expected_revision": item.get("revision"), "body_sha256": item.get("body_sha256")})
    except approval.StepUpUnavailable:
        raise
    except approval.OutcomeUnknown as exc:
        terminal.say(UNKNOWN_OUTCOME.format(_shown(exc)))
        return "failed"
    except approval.ApprovalError as exc:
        terminal.say(f"  not confirmed: {exc}")
        return "failed"
    if 200 <= status < 300:
        terminal.say("  confirmed: these are now the target's operator instructions"
                     + _decided_by(body))
        return "accepted"
    detail = body.get("detail") if isinstance(body, Mapping) else body
    terminal.say(f"  not confirmed: HTTP {status}: {_shown(detail)}")
    return "failed"


UNKNOWN_OUTCOME = ("  outcome unknown: {}. It may have been applied: check with `shakerscan knowledge "
                   "review` (or the target) before deciding again.")


def apply_knowledge_decision(send: Any, stepup: Any, entry: Mapping[str, Any], method: str, path: str,
                             payload: Any) -> tuple[int, Any]:
    """Make one knowledge decision: through the gateway's step-up on Enterprise (``stepup``), as
    the request ``method path payload`` to a local engine otherwise. Raises OutcomeUnknown when it
    was sent and no answer came back, so the caller says so instead of "not applied".

    Ready for every decision kind, finding dismissal and interpretation retraction included
    (``knowledge_entry("dismiss", target, subject_id=finding, reason=..., note=...)`` with
    ``POST /targets/{id}/findings/{fid}/dismiss``)."""
    approval = _approval()
    if stepup is not None:
        return approval.decide_knowledge(stepup, entry)
    try:
        return send(method, path, payload)
    except approval.ApprovalError as exc:
        raise approval.OutcomeUnknown(str(exc)) from exc


def _decided_by(body: Any) -> str:
    who = body.get("decided_by") if isinstance(body, Mapping) else None
    return f" (by {_shown(who)}, with your step-up)" if who else ""


def _decide_proposal(send: Any, terminal: Any, proposal: Mapping[str, Any], action: str,
                     note: str | None, stepup: Any = None) -> tuple[bool, Any]:
    payload = None if action == "rebase" else {"note": note}
    if action == "accept" and stepup is not None:
        # Enterprise: the person's step-up for exactly this proposal and text; the gateway applies it.
        approval = _approval()
        try:
            status, body = apply_knowledge_decision(send, stepup, approval.knowledge_entry(
                "accept", str(proposal.get("target_id")), subject_id=str(proposal.get("id")),
                text_sha256=proposal.get("methodology_sha256"), note=note), "POST", "", None)
        except approval.StepUpUnavailable:
            raise
        except approval.OutcomeUnknown as exc:
            terminal.say(UNKNOWN_OUTCOME.format(_shown(exc)))
            return False, None
        except approval.ApprovalError as exc:
            terminal.say(f"  not applied: {exc}")
            return False, None
        if 200 <= status < 300:
            return True, body
        detail = (body.get("message") or body.get("detail") or body.get("error")) if isinstance(body, Mapping) else body
        terminal.say(f"  not applied: HTTP {status}: {_shown(detail)}")
        return False, body
    if action == "accept":
        # Bind the decision to the text that was shown: the server refuses any other text.
        payload["methodology_sha256"] = proposal.get("methodology_sha256")
    try:
        status, body = send("POST", _proposal_path(proposal, action), payload)
    except _approval().ApprovalError as exc:
        if action != "accept":
            raise
        terminal.say(UNKNOWN_OUTCOME.format(_shown(exc)))
        return False, None
    if 200 <= status < 300:
        return True, body
    detail = body.get("message") if isinstance(body, Mapping) else body
    terminal.say(f"  not applied: HTTP {status}: {detail}")
    return False, body


def _review_one(send: Any, terminal: Any, proposal: dict[str, Any], note: str | None,
                only: str | None = None, stepup: Any = None) -> str:
    """Show ``proposal`` and decide it with one key. Returns accepted|rejected|skipped|quit|failed."""
    while True:
        terminal.say(_render_proposal(proposal))
        if proposal.get("stale"):
            prompt, choices = "  [b] rebase onto the current instructions  [n] not now  [r] reject  [q] quit: ", "bnrq"
        elif not _fully_shown(proposal):
            prompt, choices = "  [n] not now  [r] reject  [q] quit: ", "nrq"
        elif only == "accept":
            prompt, choices = (("  Accept it and apply the saved-action change? [y] yes  [n] no: "
                                if proposal.get("kind") == "saved_action"
                                else "  Accept it and replace the target instructions? [y] yes  [n] no: "), "yn")
        elif only == "reject":
            prompt, choices = "  Reject it? [r] reject  [n] no: ", "rn"
        else:
            prompt, choices = "  [y] accept  [n] not now  [r] reject  [q] quit: ", "ynrq"
        choice = terminal.key(prompt, choices)
        if choice == "q":
            return "quit"
        if choice == "b":
            ok, body = _decide_proposal(send, terminal, proposal, "rebase", None)
            if not ok:
                return "failed"
            if not isinstance(body, Mapping) or not isinstance(body.get("proposal"), Mapping):
                terminal.say(f"  {body.get('message') if isinstance(body, Mapping) else 'rebased'}")
                return "skipped"
            proposal = {**proposal, **body["proposal"]}
            terminal.say(f"  rebased as proposal {proposal['id']}: review the new difference")
            continue
        if choice == "y" and not proposal.get("stale") and _fully_shown(proposal):
            ok, body = _decide_proposal(send, terminal, proposal, "accept", note, stepup)
            if ok:
                applied = body if isinstance(body, Mapping) else {}
                if proposal.get("kind") == "saved_action":
                    revision = (applied.get("saved_actions") or {}).get("revision")
                    terminal.say(f"  accepted: the target's saved actions are now revision {revision}"
                                 + _decided_by(applied))
                else:
                    revision = (applied.get("instructions") or {}).get("revision")
                    terminal.say(f"  accepted: the target instructions are now revision {revision}"
                                 + _decided_by(applied))
                return "accepted"
            return "failed"
        if choice == "r":
            ok, _ = _decide_proposal(send, terminal, proposal, "reject", note)
            if ok:
                terminal.say("  rejected")
                return "rejected"
            return "failed"
        terminal.say("  left pending")
        return "skipped"


def _run_knowledge_review(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge review``: human output; the person decides, never an agent."""
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    stepup = None
    try:
        terminal.require("shakerscan knowledge review")
        wanted = args.accept or args.reject
        proposals, unconfirmed = _pending_review(send, args.target_id)
        if wanted:
            unconfirmed = []
            proposals = [item for item in proposals if str(item.get("id")) == str(wanted).strip().lower()]
            if not proposals:
                raise approval.ApprovalError(f"no pending instruction proposal {wanted}"
                                             + (f" on target {args.target_id}" if args.target_id else ""))
        if not proposals and not unconfirmed:
            terminal.say("no pending instruction proposals")
            return 0
        terminal.say(f"{len(proposals)} pending proposal(s). Accepting one replaces the target's instructions, "
                     "or applies the saved-action change, for future Hunts; nothing here grants testing authority.")
        if unconfirmed:
            terminal.say(f"{len(unconfirmed)} target(s) have agent-written, unconfirmed instructions.")
        if approval.instance_kind(send) == "local":
            terminal.say("This engine has no accounts: anyone who can reach its API could decide. "
                         "The keypress below is the only check.")
        else:
            stepup = approval.StepUp(send, client.base_url, terminal, account=args.account, method=args.method)
            terminal.say("Accepting or confirming one also asks for your step-up (a TOTP code or your security "
                         "key) for that one decision, as an administrator: the connection's token alone never "
                         "does it. Rejecting and rebasing need only the keypress.")
        failures = 0
        with terminal.keypresses():
            for proposal in proposals:
                outcome = _review_one(send, terminal, proposal, args.note,
                                      only="accept" if args.accept else "reject" if args.reject else None,
                                      stepup=stepup)
                failures += outcome == "failed"
                if outcome == "quit":
                    terminal.say("stopped; the remaining proposals stay pending")
                    return 1 if failures else 0
            for item in unconfirmed:
                outcome = _review_unconfirmed(send, terminal, item, stepup)
                failures += outcome == "failed"
                if outcome == "quit":
                    terminal.say("stopped; the remaining instructions stay unconfirmed")
                    break
        return 1 if failures else 0
    except approval.ApprovalError as exc:
        print(f"shakerscan knowledge review: {exc}", file=sys.stderr)
        return 2


# --- knowledge show | dismiss | reopen ---------------------------------------------------------
#
# Interpretations are attributed claims (often a Hunt's): shown with control characters made inert.
# Dismissing a finding is the person's decision, made with one lone keypress at their own terminal,
# exactly like review: a pipe (an agent's tool shell) is refused before anything is sent.

def _quoted(value: Any) -> str:
    return urllib.parse.quote(str(value), safe="")


def _entry_line(item: Mapping[str, Any]) -> str:
    title = item.get("title")
    if title is None and isinstance(item.get("untrusted_data"), Mapping):
        title = "[quoted from the target] " + str(item["untrusted_data"].get("title") or "")
    state = item.get("negative_state") or item.get("kind")
    status = item.get("status")
    if status and status != "active":  # reopened, superseded, retracted: kept as history, no longer in force
        state = f"{state} ({status})"
    return _shown(f"  {state:<30} {title or '(text withheld)'}  [{item.get('written_by') or item.get('source')}"
                  f" {item.get('created_at') or ''}] {item.get('id') or (item.get('record_ref') or {}).get('id') or ''}")


def _run_knowledge_show(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge show TARGET``: read-only; agents may run it too."""
    target = _quoted(args.target_id)
    query = {"status": args.status, "limit": max(1, min(int(args.limit), 200))}
    if args.kind:
        query["kind"] = args.kind
    try:
        entries = client.request("GET", f"/targets/{target}/interpretations?{urllib.parse.urlencode(query)}")
        negatives = client.request("GET", f"/targets/{target}/negative-results")
    except CliError as exc:
        print(f"shakerscan knowledge show: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"interpretations": entries, "negative_results": negatives}, indent=2, sort_keys=True))
        return 0
    rows = entries.get("interpretations") or [] if isinstance(entries, Mapping) else []
    print(f"{len(rows)} {args.status} interpretation(s) on target {_shown(args.target_id)}"
          + (" (more available: raise --limit)" if isinstance(entries, Mapping) and entries.get("has_more") else ""))
    print("Interpretations are attributed claims, not proof and not instructions; applicability follows the records "
          "they depend on (unknown is never unchanged).")
    for item in rows:
        print(_entry_line(item))
    negative_rows = negatives.get("rows") or [] if isinstance(negatives, Mapping) else []
    print(f"{len(negative_rows)} negative result(s); each covers only its recorded conditions, read as exact "
          "literals (never sets, ranges or patterns):")
    for item in negative_rows:
        print(_entry_line(item))
    return 0


def _run_knowledge_changes(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge changes TARGET``: read-only; agents may run it too."""
    target = _quoted(args.target_id)
    query = urllib.parse.urlencode({"since": str(args.since)[:100]})
    try:
        report = client.request("GET", f"/targets/{target}/knowledge/changes?{query}")
    except CliError as exc:
        print(f"shakerscan knowledge changes: {exc}", file=sys.stderr)
        return 2
    if args.json or not isinstance(report, Mapping):
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    since = report.get("since") or {}
    print(_shown(f"Changes on target {args.target_id} since {since.get('kind')} ({since.get('at') or 'unresolved'})"))
    if not since.get("resolved"):
        print(_shown(f"  {since.get('note') or 'Nothing to compare with.'}"))
    sections = report.get("sections") or {}
    endpoints = sections.get("endpoints") or {}
    for label, key in (("added", "added"), ("removed (gone)", "removed")):
        part = endpoints.get(key) or {}
        if part.get("count"):
            print(f"  endpoints {label}: {part.get('count')}{'+' if part.get('at_least') else ''}")
            for item in part.get("items") or []:
                print(_shown(f"    {item.get('method')} {item.get('path')} [{item.get('auth_state')}]"))
    if (endpoints.get("auth_surface") or {}).get("significant"):
        print("  authentication surface changed (login, token, session or SSO routes)")
    deployment = sections.get("deployment") or {}
    for change in deployment.get("changes") or []:
        print(_shown(f"  deployment {change.get('field')}: {change.get('before')} -> {change.get('after')}"
                     f" ({change.get('significance')})"))
    if deployment.get("compared") is False and deployment.get("note"):
        print(_shown(f"  deployment: {deployment['note']}"))
    for item in (sections.get("responses") or {}).get("changed") or []:
        fields = ", ".join(f"{c.get('field')} ({c.get('significance')})" for c in item.get("changes") or [])
        print(_shown(f"  response {item.get('method')} {item.get('path')}: {fields}"))
    findings = (sections.get("findings") or {}).get("new") or {}
    if findings.get("count"):
        print(f"  new findings: {findings['count']}")
    for item in (sections.get("subdomains") or {}).get("new_targets") or []:
        print(_shown(f"  new subdomain {item.get('host')} ({item.get('source')})"))
    knowledge = report.get("knowledge") or {}
    states = knowledge.get("active_by_applicability") or {}
    print("  interpretations by applicability: " + (", ".join(f"{k} {v}" for k, v in sorted(states.items())) or "none"))
    for item in knowledge.get("affected") or []:
        causes = "; ".join(f"{c.get('type')} {c.get('key')} {c.get('field')}" for c in item.get("caused_by") or [])
        state = "reopened for review" if item.get("reopened_for_review") else item.get("applicability")
        print(_shown(f"    {item.get('negative_state') or item.get('kind')} {item.get('id')}: {state}"
                     + (f" ({causes})" if causes else "")))
    print("Changes come from existing records (Scans, the endpoint inventory, earlier requests, discovery); "
          "nothing was sent to the target.")
    _print_cache_note(report)
    return 0


def _print_cache_note(report: Mapping[str, Any]) -> None:
    """Say when the engine served its short-lived cached report (and how old it is)."""
    cache = report.get("cache") if isinstance(report.get("cache"), Mapping) else {}
    if cache.get("cached"):
        print(_shown(f"Served from the engine's cache: built {cache.get('age_seconds')} s ago (at "
                     f"{report.get('built_at')}; kept up to {cache.get('max_age_seconds')} s). Run again in a "
                     "moment for a fresh report after a change."))


def _suggestion_line(item: Mapping[str, Any]) -> str:
    values = item.get("input") if isinstance(item.get("input"), Mapping) else None
    route = item.get("route") if isinstance(item.get("route"), Mapping) else None
    who = item.get("principal") or values.get("session_ref") if values else None
    what = (f"{values.get('method')} {values.get('path')}" + (f" as {who}" if who else "")
            if values else f"{route.get('method')} {route.get('path')} (state-changing; ask the operator)"
            if route and item.get("state_changing")
            else f"{route.get('method')} {route.get('path')} (choose an object)" if route
            else "the identical experiment from its recorded conditions")
    basis = item.get("basis") if isinstance(item.get("basis"), Mapping) else {}
    authority = (item.get("authority") or {}).get("status")
    return _shown(f"  {item.get('rank'):>3}. [{item.get('rule')}] {item.get('capability') or 'agent chooses'}: {what}"
                  f"  ({basis.get('type')} {basis.get('id')}; authority {authority})"
                  + ("  REQUIRED RE-TEST" if item.get("required_retest") else ""))


def _run_knowledge_continue(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge continue TARGET``: read-only; agents may run it too. ``--refresh`` starts
    the offered passive refresh only after a lone keypress at the person's own terminal."""
    target = _quoted(args.target_id)
    reports: list[Any] = []
    restarts = 0
    after = args.after
    try:
        while True:
            params = {"since": str(args.since)[:100], **({"after": after} if after else {})}
            report = client.request("GET", f"/targets/{target}/knowledge/continue?{urllib.parse.urlencode(params)}")
            nxt = ((report or {}).get("next_experiments") or {}) if isinstance(report, Mapping) else {}
            if args.all and nxt.get("changed_since_cursor") and restarts < 3:
                # The candidates changed between pages: read them all again from the first page.
                restarts += 1
                reports, after = [], None
                continue
            reports.append(report)
            after = nxt.get("next_after")
            if not args.all or not isinstance(after, str) or len(reports) >= 1000:
                break
    except CliError as exc:
        print(f"shakerscan knowledge continue: {exc}", file=sys.stderr)
        return 2
    report = reports[0]
    if args.json or not isinstance(report, Mapping):
        print(json.dumps(reports if args.all else report, indent=2, sort_keys=True))
    else:
        _print_continue(args.target_id, report)
        for later in reports[1:]:
            _print_continue_page(later)
    if not args.refresh:
        return 0
    return _offer_refresh(args, client, report if isinstance(report, Mapping) else {})


def _print_continue(target_id: str, report: Mapping[str, Any]) -> None:
    since = report.get("since") or {}
    origin = {"declared": "declared by an operator", "scan_detected": "detected by Scans"}.get(since.get("source"), "")
    print(_shown(f"Continue on target {target_id} after the release of {since.get('at') or 'unknown'}"
                 + (f" ({origin}" + (f": {since.get('label')}" if since.get("label") else "") + ")" if origin else "")))
    if not since.get("resolved"):
        print(_shown(f"  {since.get('note') or 'No release point.'}"))
    sections = (report.get("changes") or {}).get("sections") or {}
    endpoints = sections.get("endpoints") or {}
    deployment = sections.get("deployment") or {}
    print(f"  changes: endpoints added {(endpoints.get('added') or {}).get('count', 0)}, removed "
          f"{(endpoints.get('removed') or {}).get('count', 0)}; authentication surface changed: "
          f"{'yes' if (endpoints.get('auth_surface') or {}).get('significant') else 'no'}; deployment changed: "
          f"{'yes' if deployment.get('significant') else 'no' if deployment.get('compared') else 'not compared'}")
    for change in deployment.get("changes") or []:
        print(_shown(f"    deployment {change.get('field')}: {change.get('before')} -> {change.get('after')}"))
    counts = (report.get("knowledge") or {}).get("counts") or {}
    print("  knowledge: " + ", ".join(f"{name.replace('_', ' ')} {counts.get(name, 0)}" for name in (
        "still_applicable", "needs_revalidation", "not_reobserved_since_release", "historical",
        "inconclusive_experiments", "open_next_steps", "reopened_for_review")))
    for item in (report.get("knowledge") or {}).get("reopened_for_review") or []:
        print(_shown(f"    reopened dismissal {item.get('id')} (finding {item.get('finding_id')}): decide with "
                     "shakerscan knowledge dismiss|reopen"))
    nxt = report.get("next_experiments") or {}
    required = nxt.get("required_retests") or {}
    print(f"  next experiments (ranked by fixed rules; required re-tests: {required.get('total', 0)}, outside "
          f"authority: {required.get('outside_authority', 0)}):")
    if required.get("at_least"):
        print(_shown("    totals are a lower bound: " + "; ".join(str(r) for r in required.get("incomplete_because") or [])))
    for item in nxt.get("items") or []:
        print(_suggestion_line(item))
    for item in nxt.get("outside_authority") or []:
        print(_suggestion_line(item) + _shown(f"  [outside authority: {(item.get('authority') or {}).get('reason')}]"))
    _print_unlisted(nxt)
    refresh = (report.get("freshness") or {}).get("refresh") or {}
    for offer in refresh.get("offers") or []:
        print(_shown(f"  offered refresh: {offer.get('kind')} ({offer.get('why')}); run with --refresh to decide"))
    print("Read from existing records; nothing was sent to the target. Paths and versions are data from the target.")
    _print_cache_note(report)


def _print_unlisted(nxt: Mapping[str, Any]) -> None:
    unlisted = nxt.get("unlisted") or {}
    if nxt.get("changed_since_cursor"):
        print("    the candidates changed while paging: run again (or with --all) to see everything")
    if nxt.get("next_after"):
        print(_shown(f"    not shown yet: {unlisted.get('runnable', 0)} runnable ({unlisted.get('required_runnable', 0)} "
                     f"required), {unlisted.get('outside_authority', 0)} outside authority "
                     f"({unlisted.get('required_outside_authority', 0)} required); --after {nxt['next_after']} "
                     "or --all"))


def _print_continue_page(report: Mapping[str, Any]) -> None:
    nxt = report.get("next_experiments") or {} if isinstance(report, Mapping) else {}
    print("  next page:")
    for item in nxt.get("items") or []:
        print(_suggestion_line(item))
    for item in nxt.get("outside_authority") or []:
        print(_suggestion_line(item) + _shown(f"  [outside authority: {(item.get('authority') or {}).get('reason')}]"))
    _print_unlisted(nxt)


def _offer_refresh(args: argparse.Namespace, client: ApiClient, report: Mapping[str, Any]) -> int:
    offers = ((report.get("freshness") or {}).get("refresh") or {}).get("offers") or []
    if not offers:
        print("no refresh is needed: the records are newer than the release")
        return 0
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    try:
        terminal.require("shakerscan knowledge continue --refresh")
        failures = 0
        with terminal.keypresses():
            for offer in offers:
                request = offer.get("request") if isinstance(offer.get("request"), Mapping) else {}
                terminal.say(_shown(f"{offer.get('kind')}: {offer.get('why')}"))
                terminal.say(_shown(f"  {request.get('method')} {request.get('path')}  traffic: {offer.get('traffic')}"))
                body = request.get("body")
                checked = _passive_refresh(offer.get("kind"), request)
                if checked is None:
                    terminal.say("  not a passive Scan or discovery request this command can start; skipped")
                    continue
                terminal.say(_shown(f"  {checked}"))
                if terminal.key("  [s] start  [n] skip: ", "sn") != "s":
                    terminal.say("  skipped")
                    continue
                status, answer = send("POST", str(request["path"]), body if isinstance(body, Mapping) else None)
                if not 200 <= status < 300:
                    failures += 1
                    terminal.say(_shown(f"  not started: HTTP {status}: {answer}"))
                    continue
                ident = (answer or {}).get("scan_id") or (answer or {}).get("id") if isinstance(answer, Mapping) else None
                terminal.say(_shown(f"  started{f' ({ident})' if ident else ''}"))
        return 1 if failures else 0
    except approval.ApprovalError as exc:
        print(f"shakerscan knowledge continue --refresh: {exc}", file=sys.stderr)
        return 2


_DISCOVERY_PATH = re.compile(r"^/discovery\?root_domain=[A-Za-z0-9.-]{1,253}$")


def _passive_refresh(kind: Any, request: Mapping[str, Any]) -> str | None:
    """What a refresh offer would do, if it is exactly a passive Scan of one http(s) URL
    (``POST /scans`` with only target, target_kind and ``policy: {active_testing: false}``) or a passive
    discovery of one apex (``POST /discovery?root_domain=...`` without a body); otherwise None."""
    if request.get("method") != "POST":
        return None
    body = request.get("body")
    if kind == "passive_scan" and request.get("path") == "/scans" and isinstance(body, Mapping) \
            and set(body) <= {"target", "target_kind", "policy"} and body.get("policy") == {"active_testing": False} \
            and body.get("target_kind", "web") in {"web", "api"} \
            and isinstance(body.get("target"), str) and body["target"].startswith(("https://", "http://")):
        return f"passive Scan of {body['target']} (no active testing)"
    if kind == "passive_discovery" and body is None and _DISCOVERY_PATH.match(str(request.get("path") or "")):
        return f"passive subdomain discovery of {str(request['path']).split('=', 1)[1]} (nothing sent to the target)"
    return None


def _run_knowledge_measures(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge measures TARGET``: read-only."""
    target = _quoted(args.target_id)
    query = urllib.parse.urlencode({"since": str(args.since)[:100]})
    try:
        report = client.request("GET", f"/targets/{target}/knowledge/continue/measures?{query}")
    except CliError as exc:
        print(f"shakerscan knowledge measures: {exc}", file=sys.stderr)
        return 2
    if args.json or not isinstance(report, Mapping):
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    since = report.get("since") or {}
    print(_shown(f"Continuing on target {args.target_id} since {since.get('kind')} ({since.get('at') or 'unresolved'})"))
    if report.get("note"):
        print(_shown(f"  {report['note']}"))
    reads = report.get("reads") or {}
    if reads:
        print(f"  report reads: {reads.get('total', 0)} (operators {reads.get('operators', 0)}, Hunts {reads.get('hunts', 0)})")
    if report.get("started_at"):
        print(_shown(f"  started: {report['started_at']} (first read by an {report.get('started_by')})"))
    required = report.get("required_retests") or {}
    if required:
        print(f"  required re-tests listed at the start: {required.get('listed_at_start', 0)}, run "
              f"{required.get('run', 0)}, not run {required.get('not_run', 0)}")
        for item in required.get("not_run_items") or []:
            print(_shown(f"    not run: [{item.get('rule')}] {item.get('method') or ''} {item.get('path') or ''} "
                         f"({(item.get('basis') or {}).get('type')} {(item.get('basis') or {}).get('id')})"))
    useful = report.get("first_useful_step") or {}
    if useful:
        seconds = useful.get("seconds")
        print("  first useful step: " + (f"{seconds} s after the start (action {useful.get('action_id')})"
                                        if seconds is not None else "none yet"))
    redundant = report.get("redundant_requests") or {}
    if redundant:
        share = redundant.get("share")
        print(f"  redundant requests: {redundant.get('redundant', 0)} of {redundant.get('requests_after_start', 0)}"
              + (f" ({round(share * 100, 1)}%)" if isinstance(share, (int, float)) else ""))
    results = report.get("new_results") or {}
    if results:
        print(f"  findings first seen since the release: {results.get('findings_first_seen_total', 0)}; changed "
              f"outcomes on identical conditions: {len(results.get('changed_outcomes') or [])}")
        for item in results.get("changed_outcomes") or []:
            print(_shown(f"    {item.get('earlier_outcome')} -> {item.get('outcome')} (entry {item.get('id')})"))
    suppression = report.get("incorrect_suppression") or {}
    if suppression:
        print(f"  skip advice: {suppression.get('skip_advice', 0)}; later contradicted (incorrect suppression, "
              f"expected 0): {suppression.get('contradicted', 0)}")
        for item in suppression.get("items") or []:
            print(_shown(f"    entry {item.get('entry_id')}: {item.get('why')}"))
    print("Measured from existing records; nothing was sent to the target.")
    return 0


def _run_knowledge_usage(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge usage``: read-only."""
    try:
        report = client.request("GET", f"/knowledge/continue/usage?weeks={max(1, min(int(args.weeks), 52))}")
    except CliError as exc:
        print(f"shakerscan knowledge usage: {exc}", file=sys.stderr)
        return 2
    if args.json or not isinstance(report, Mapping):
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    items = report.get("items") or []
    if not items:
        print("No continue reports were read in this period.")
    for item in items:
        print(f"{item.get('week')}: operators {item.get('operators')}, Hunts {item.get('hunts')}, targets "
              f"{item.get('targets')}, reads {item.get('reads')}")
    return 0


def _run_knowledge_release(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge release TARGET``: the release point `continue` starts from. Declared by
    the person with a keypress (a pipe, such as an agent's tool shell, is refused)."""
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    payload: dict[str, Any] = {}
    if args.label is not None:
        payload["label"] = args.label
    if args.at is not None:
        payload["released_at"] = args.at
    try:
        terminal.require("shakerscan knowledge release")
        terminal.say(_shown(f"declare a release of target {args.target_id}"
                            + (f" labelled {args.label!r}" if args.label else "")
                            + f" at {args.at or 'now'}"))
        terminal.say("`continue` then starts from this point; applicability still follows the records, and nothing "
                     "is suppressed or granted.")
        with terminal.keypresses():
            choice = terminal.key("  [r] declare  [n] cancel: ", "rn")
        if choice != "r":
            terminal.say("  nothing changed")
            return 0
        stepup = (approval.StepUp(send, client.base_url, terminal, account=args.account, method=args.method)
                  if approval.instance_kind(send) == "enterprise" else None)
        status, body = apply_knowledge_decision(
            send, stepup, approval.knowledge_entry("release_marker", args.target_id,
                release_label=args.label, released_at=args.at) if stepup is not None else {},
            "POST", f"/targets/{_quoted(args.target_id)}/knowledge/releases", payload)
        if not 200 <= status < 300:
            detail = body.get("detail") if isinstance(body, Mapping) else body
            terminal.say(_shown(f"  not declared: HTTP {status}: {detail}"))
            return 1
        terminal.say(_shown(f"  declared release {(body or {}).get('id')} at {(body or {}).get('released_at')}"))
        return 0
    except approval.ApprovalError as exc:
        print(f"shakerscan knowledge release: {exc}", file=sys.stderr)
        return 2


def _run_knowledge_releases(args: argparse.Namespace, client: ApiClient) -> int:
    try:
        listed = client.request("GET", f"/targets/{_quoted(args.target_id)}/knowledge/releases")
    except CliError as exc:
        print(f"shakerscan knowledge releases: {exc}", file=sys.stderr)
        return 2
    if args.json or not isinstance(listed, Mapping):
        print(json.dumps(listed, indent=2, sort_keys=True))
        return 0
    rows = listed.get("releases") or []
    print(_shown(f"{len(rows)} declared release(s) on target {args.target_id} (newest first):"))
    for item in rows:
        print(_shown(f"  {item.get('released_at')}  {item.get('label') or '(no label)'}  by {item.get('declared_by')}"
                     f"  {item.get('id')}"))
    return 0


def _run_knowledge_decision(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge dismiss|reopen``: one finding, decided by the person with a keypress."""
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    action = args.knowledge_command
    try:
        terminal.require(f"shakerscan knowledge {action}")
        status, finding = send("GET", f"/findings/{_quoted(args.finding_id)}")
        if not 200 <= status < 300 or not isinstance(finding, Mapping):
            raise approval.ApprovalError(f"could not read finding {args.finding_id}: HTTP {status}")
        terminal.say(_shown(f"finding {args.finding_id} on target {args.target_id}"))
        terminal.say(_shown(f"  title:    {finding.get('title')}"))
        terminal.say(_shown(f"  severity: {finding.get('severity')}  status: {finding.get('status')}  "
                            f"tool: {finding.get('tool')}"))
        terminal.say(_shown(f"  url:      {finding.get('url')}"))
        if action == "dismiss":
            terminal.say(_shown(f"  dismiss as {args.reason}: {args.note}"))
            terminal.say("Dismissing changes the finding's status and is recorded as your decision. An operator can "
                         "reopen it at any time.")
            prompt, choice_key = "  [d] dismiss  [n] cancel: ", "d"
        else:
            terminal.say(_shown(f"  reopen for review: {args.note}"))
            prompt, choice_key = "  [o] reopen  [n] cancel: ", "o"
        with terminal.keypresses():
            choice = terminal.key(prompt, choice_key + "n")
        if choice != choice_key:
            terminal.say("  nothing changed")
            return 0
        payload = ({"reason": args.reason, "note": args.note} if action == "dismiss" else {"note": args.note})
        stepup = (approval.StepUp(send, client.base_url, terminal, account=args.account, method=args.method)
                  if approval.instance_kind(send) == "enterprise" else None)
        try:
            status, body = apply_knowledge_decision(send, stepup, approval.knowledge_entry(
                action, args.target_id, subject_id=args.finding_id, reason=getattr(args, 'reason', None),
                note=args.note) if stepup is not None else {}, "POST",
                f"/targets/{_quoted(args.target_id)}/findings/{_quoted(args.finding_id)}/{action}", payload)
        except approval.OutcomeUnknown as exc:
            terminal.say(UNKNOWN_OUTCOME.format(_shown(exc)))
            return 1
        if not 200 <= status < 300:
            detail = body.get("detail") if isinstance(body, Mapping) else body
            terminal.say(_shown(f"  not applied: HTTP {status}: {detail}"))
            return 1
        result = (body or {}).get("finding") if isinstance(body, Mapping) else None
        terminal.say(_shown(f"  {action}ed: the finding is now {(result or {}).get('status')}"
                            if action == "reopen" else f"  dismissed: the finding is now {(result or {}).get('status')}"))
        return 0
    except approval.ApprovalError as exc:
        print(f"shakerscan knowledge {action}: {exc}", file=sys.stderr)
        return 2


REFERENCE_LIST_DEFAULT = 50
REFERENCE_LIST_MAX = 200
# The listing's rows: secret:// references with metadata (kind, length, state, sightings). The
# instance never puts a value in them ("values_visible": false); a value is only ever shown by
# `shakerscan secrets reveal`, after the person's own decision.
REFERENCE_LIST_FIELD = "secrets"


def _reference_list_limit(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--limit takes a whole number") from None
    if not 1 <= number <= REFERENCE_LIST_MAX:
        raise argparse.ArgumentTypeError(f"--limit is 1 to {REFERENCE_LIST_MAX}")
    return number


def _reference_id(value: str) -> str:
    return str(value or "").strip().removeprefix("secret://")


def _run_secrets(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan secrets``: a target's discovered secrets. Listing never shows a value; reveal,
    grant and promote are the person's decisions, made in their own terminal (Enterprise: with
    their step-up, applied by the gateway; an open-source engine: a keypress)."""
    command, target = args.store_command, str(args.target_id).strip().lower()
    base = f"/targets/{_quoted(target)}/discovered-secrets"
    if command == "list":
        # One more than shown, so "there are more" is known rather than guessed. An engine before
        # 2.11 ignores limit= and answers its own cap (200); the client cuts to --limit either way.
        asked = min(args.limit + 1, REFERENCE_LIST_MAX)
        query = urllib.parse.urlencode({**({"usable_only": "true"} if args.usable else {}), "limit": asked})
        body = client.request("GET", f"{base}?{query}")
        rows = body.get(REFERENCE_LIST_FIELD) or [] if isinstance(body, Mapping) else []
        if args.json:
            # The extra row only answers "are there more"; it is never printed.
            listed = {**body, REFERENCE_LIST_FIELD: rows[: args.limit], "count": len(rows[: args.limit]),
                      "has_more": len(rows) > args.limit,
                      "may_have_more": len(rows) > args.limit or len(rows) >= REFERENCE_LIST_MAX} \
                if isinstance(body, Mapping) else body
            print(json.dumps(listed, indent=2, sort_keys=True))
            return 0
        if not rows:
            print("no discovered secrets" + (" a Hunt can use" if args.usable else "") + " on this target")
            return 0
        shown = rows[: args.limit]
        for row in shown:
            origin = "" if row.get("found_on") == target else f"  granted from {row.get('found_on')}"
            print(_shown(f"{row.get('ref')}  {row.get('kind'):<14} {row.get('label') or '-':<20} "
                         f"{row.get('length')} chars  {row.get('state')}  seen {row.get('seen_count')}x, "
                         f"last {row.get('last_seen_at')}  uses {row.get('uses')}{origin}"))
        if len(rows) > args.limit:
            print(f"showing the {len(shown)} most recently seen; there are more: "
                  f"show more with --limit (at most {REFERENCE_LIST_MAX})")
        elif len(rows) >= REFERENCE_LIST_MAX:
            print(f"showing the {len(shown)} most recently seen; there may be more "
                  f"(the instance lists at most {REFERENCE_LIST_MAX})")
        return 0
    ref_id = _reference_id(args.reference)
    path = f"{base}/{_quoted(ref_id)}"
    if command in {"revoke", "reactivate"}:
        state = "revoked_by_operator" if command == "revoke" else "active"
        client.request("POST", path + "/state", payload={"state": state})
        print(f"secret://{ref_id}: {state}")
        return 0
    if command == "expiry":
        client.request("POST", path + "/expiry", payload={"days": args.days})
        print(f"secret://{ref_id}: expires in {args.days} day(s)")
        return 0
    if command == "ungrant":
        client.request("DELETE", f"{path}/grants/{_quoted(str(args.to).strip().lower())}")
        print(f"secret://{ref_id}: target {args.to} can no longer use it")
        return 0
    action = {"grant": "grants", "promote": "promote", "reveal": "reveal"}[command]
    payload: dict[str, Any] = {}
    if command == "grant":
        payload = {"target_id": str(args.to).strip().lower()}
    elif command == "promote":
        payload = {"name": args.name, "auth_kind": args.auth_kind}
        for key, value in (("header_name", args.header_name), ("parameter_name", args.parameter_name),
                           ("username", args.username)):
            if value:
                payload[key] = value
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    try:
        terminal.require(f"shakerscan secrets {command}")
        terminal.say(approval._knowledge_summary(approval.reference_decision(action, target, ref_id, payload)))
        if approval.instance_kind(send) == "enterprise":
            stepup = approval.StepUp(send, client.base_url, terminal, account=args.account, method=args.method)
            status, body = approval.decide_knowledge(stepup, approval.reference_decision(action, target, ref_id, payload))
        else:
            with terminal.keypresses():
                if terminal.key("  [y] yes  [n] cancel: ", "yn") != "y":
                    terminal.say("  nothing changed")
                    return 0
            status, body = send("POST", f"{path}/{action}", payload)
    except approval.ApprovalError as exc:
        print(f"shakerscan secrets {command}: {exc}", file=sys.stderr)
        return 2
    if not 200 <= status < 300:
        detail = body.get("detail") if isinstance(body, Mapping) else body
        print(_shown(f"  not applied: HTTP {status}: {detail}"), file=sys.stderr)
        return 1
    if command == "reveal":
        # The value goes to this terminal only. It came from a target: control and invisible
        # characters are shown as escapes, never interpreted by the terminal.
        terminal.say("  value: " + _shown((body or {}).get("value", "")))
    elif command == "promote":
        terminal.say(_shown(f"  credential profile {((body or {}).get('profile') or {}).get('id')} created; "
                            "the discovered secret is superseded"))
    else:
        terminal.say(_shown(f"  target {args.to} may now use secret://{ref_id}"))
    return 0


AUTHORITY_WRITE_KEYS = ("metadata_changes", "credential_profile_ids", "collection_ids", "ssh_trust_first_contact")


def authority_write(current: Mapping[str, Any], instruction_changes: bool) -> dict[str, Any]:
    """The Hunt-permissions write that changes only ``instruction_changes``: every other setting as
    the server just reported it, at the revision it reported (the server refuses any other)."""
    keys = []
    for item in current.get("ssh_host_keys") or []:
        if isinstance(item, Mapping):
            keys.append({"port": item.get("port"), "fingerprint": item.get("fingerprint")})
    return {"expected_revision": current.get("revision"),
            **{key: current.get(key) for key in AUTHORITY_WRITE_KEYS if key in current},
            "ssh_host_keys": keys, "instruction_changes": bool(instruction_changes)}


def _run_allow_changes(args: argparse.Namespace, client: ApiClient) -> int:
    """``shakerscan knowledge allow-changes <target>``: the person turns instruction_changes on
    (or, with --off, off) for one target, at their own terminal; Enterprise: with their step-up."""
    approval = _approval()
    send = _approval_send(client)
    terminal = approval.Terminal()
    command = "shakerscan knowledge allow-changes"
    try:
        terminal.require(command)
        target = str(args.target_id or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", target):
            raise approval.ApprovalError(f"{args.target_id!r} is not a target id")
        path = f"/targets/{urllib.parse.quote(target, safe='')}/hunt-authority"
        status, current = send("GET", path)
        if not 200 <= status < 300 or not isinstance(current, Mapping):
            raise approval.ApprovalError(f"cannot read the target's Hunt permissions: HTTP {status}: {_shown(current)}")
        if "instruction_changes" not in current or not isinstance(current.get("revision"), int):
            raise approval.ApprovalError("this engine has no instruction_changes setting (it arrives with 2.9)")
        named_status, named = send("GET", f"/targets/{urllib.parse.quote(target, safe='')}")
        name = (named.get("name") or named.get("url")) if 200 <= named_status < 300 and isinstance(named, Mapping) else None
        want = not args.off
        terminal.say(f"target {_shown(name or target)} ({target})")
        terminal.say(f"  Hunts edit its instructions directly: {'yes' if current['instruction_changes'] else 'no'} "
                     f"(Hunt permissions revision {current['revision']})")
        if bool(current["instruction_changes"]) == want:
            terminal.say("  nothing to change")
            return 0
        if want:
            terminal.say("  Turning it on lets every Hunt on this target replace its operator instructions and change "
                         "its saved actions without a proposal you review. Future Hunts follow what they write.")
            prompt = "  Let Hunts edit this target's instructions? [y] yes  [n] no: "
        else:
            terminal.say("  Turning it off makes Hunts propose instruction and saved-action changes for review again.")
            prompt = "  Stop Hunts editing this target's instructions? [y] yes  [n] no: "
        with terminal.keypresses():
            choice = terminal.key(prompt, "yn")
        if choice != "y":
            terminal.say("  nothing was changed")
            return 1
        stepup = None
        if want and approval.instance_kind(send) == "enterprise":
            stepup = approval.StepUp(send, client.base_url, terminal, account=args.account, method=args.method)
        try:
            status, body = apply_knowledge_decision(
                send, stepup, approval.knowledge_entry("allow_changes", target, expected_revision=current["revision"])
                if stepup is not None else {}, "PUT", path, authority_write(current, want))
        except approval.OutcomeUnknown as exc:
            terminal.say(UNKNOWN_OUTCOME.format(_shown(exc)))
            return 1
        if 200 <= status < 300:
            revision = body.get("revision") if isinstance(body, Mapping) else None
            terminal.say(f"  {'on' if want else 'off'}: Hunt permissions are now revision {revision}" + _decided_by(body))
            return 0
        detail = (body.get("message") or body.get("detail")) if isinstance(body, Mapping) else body
        terminal.say(f"  not changed: HTTP {status}: {_shown(detail)}")
        return 1
    except approval.ApprovalError as exc:
        print(f"{command}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

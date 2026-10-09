"""Worker-only chaining for authorized HTTP pairing and login workflows.

Uses the existing encrypted credential vault for supplied PINs and the existing
Hunt action row for ephemeral encrypted captures. No parallel secret registry,
plaintext planner result, arbitrary expression evaluator or new target authority.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Awaitable, Callable, Mapping
import uuid

from .hunt_http_exchange_contract import pointer_get, pointer_set
from .credential_refs import select_hunt_principal_reference
from .credential_resolver import WorkerCredentialResolver, validate_worker_credential_authority
from .models import TargetBinding
try:
    from secret_store import encrypt_secret, decrypt_secret
except ModuleNotFoundError:
    from api.secret_store import encrypt_secret, decrypt_secret

SCHEMA = "hunt-http-private-capture/v1"
MAX_VALUE_BYTES = 8_192
MAX_CAPTURE_BYTES = 65_536
CAPTURE_TTL_SECONDS = 3_600


def _target_digest(target: TargetBinding) -> str:
    # Services on the same admitted asset are not different authorization boundaries.
    return replace(target, allowed_origins=()).digest


def _scalar(value: Any) -> Any:
    if not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError("HTTP workflow binding value must be a scalar")
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, UnicodeError):
        raise ValueError("HTTP workflow binding value is invalid") from None
    if len(encoded) > MAX_VALUE_BYTES:
        raise ValueError("HTTP workflow binding value is too large")
    return value


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("HTTP workflow response has duplicate JSON fields")
        result[key] = value
    return result


@dataclass(repr=False)
class HttpWorkflowExchange:
    run_id: str
    action_id: str
    target: TargetBinding = field(repr=False)
    captures: tuple[Mapping[str, Any], ...] = field(default=(), repr=False)
    encrypted_result: str | None = field(default=None, repr=False)
    captured_names: tuple[str, ...] = ()
    capture_error: str | None = None
    # Withheld values this request sends (worker-private): scrubbed from the planner's view.
    bound_values: list[str] = field(default_factory=list, repr=False)

    def __repr__(self) -> str:
        return f"HttpWorkflowExchange(action_id={self.action_id!r}, secret_values_visible=False)"

    @property
    def response_headers(self) -> tuple[str, ...]:
        return tuple(str(item["header"]).lower() for item in self.captures if "header" in item)

    def capture_response(self, response: Any) -> None:
        """Capture only requested fields. Failure never erases the attempted write."""
        if not self.captures:
            return
        extracted: dict[str, Any] = {}
        try:
            if not 200 <= response.status_code < 300:
                raise ValueError("unsuccessful response")
            document = json.loads(response.body(), object_pairs_hook=_unique_json_pairs) if any(
                "json_pointer" in item for item in self.captures) else None
            headers = {str(key).lower(): value for key, value in response.headers().items()}
            for item in self.captures:
                value = pointer_get(document, item["json_pointer"]) if "json_pointer" in item else headers[item["header"].lower()]
                extracted[item["name"]] = _scalar(value)
            now = datetime.now(timezone.utc)
            payload = json.dumps({"schema_version": SCHEMA, "hunt_id": self.run_id,
                "source_action_id": self.action_id, "target_digest": _target_digest(self.target),
                "expires_at": (now + timedelta(seconds=CAPTURE_TTL_SECONDS)).isoformat(),
                "values": extracted}, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            if len(payload.encode()) > MAX_CAPTURE_BYTES:
                raise ValueError("capture too large")
            self.encrypted_result = encrypt_secret(payload)
            self.captured_names = tuple(extracted)
        except Exception:
            # Target content and decrypt/encrypt errors must never enter public errors.
            self.encrypted_result = None
            self.captured_names = ()
            self.capture_error = "http_workflow_capture_incomplete"
        finally:
            extracted.clear()

    def public_result(self) -> list[dict[str, str]]:
        return [{"source_action_id": self.action_id, "capture_name": name}
                for name in self.captured_names]

    async def persist(self, conn: Any, *, run: Mapping[str, Any], status: str) -> None:
        if self.encrypted_result and status == "success" and run["status"] in {"active", "awaiting_planner", "budget_exhausted"} and not run.get("completed_at"):
            await conn.execute("""UPDATE hunt_actions SET private_http_result=$3
                WHERE id=$1 AND hunt_run_id=$2 AND capability_name='http.request'""",
                uuid.UUID(self.action_id), uuid.UUID(self.run_id), self.encrypted_result)
        else:
            self.captured_names = ()
        self.encrypted_result = None


async def _captured_value(conn: Any, *, run_id: str, target: TargetBinding, binding: Mapping[str, Any]) -> Any:
    source_id = str(uuid.UUID(str(binding["source_action_id"])))
    row = await conn.fetchrow("""SELECT private_http_result FROM hunt_actions
        WHERE id=$1 AND hunt_run_id=$2 AND capability_name='http.request'
          AND status='completed'""", uuid.UUID(source_id), uuid.UUID(run_id))
    ciphertext = str(row["private_http_result"] or "") if row else ""
    if len(ciphertext) > 131_072 or not ciphertext.startswith("enc:fernet:"):
        raise ValueError("HTTP workflow response reference is unavailable")
    try:
        private = json.loads(decrypt_secret(ciphertext))
        expires_at = datetime.fromisoformat(private["expires_at"])
        if (private["schema_version"] != SCHEMA or private["hunt_id"] != run_id
                or private["source_action_id"] != source_id
                or private["target_digest"] != _target_digest(target)
                or expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc)):
            raise ValueError("binding changed or expired")
        return _scalar(private["values"][binding["capture_name"]])
    except Exception:
        raise ValueError("HTTP workflow response reference is expired or no longer bound to this Hunt") from None


# --- Withheld values -------------------------------------------------------------------------
# A capability output (an artifact window, an HTTP body sample) withholds credential-shaped values
# behind ``[withheld:n]`` markers (archive_body_masking). The raw values are sealed here, on the
# same encrypted, Hunt- and target-bound, expiring action row a response capture uses, and cleared
# with it when the Hunt ends. A later ``http.request`` binds one by ``withheld_ref`` under the same
# active-testing authority, budget and scope as any other workflow binding (N56).

WITHHELD_SCHEMA_KEY = "withheld"
_MAX_WITHHELD_PAYLOAD_BYTES = 65_536


def _private_payload(run_id: str, action_id: str, target: TargetBinding) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {"schema_version": SCHEMA, "hunt_id": run_id, "source_action_id": action_id,
        "target_digest": _target_digest(target),
        "expires_at": (now + timedelta(seconds=CAPTURE_TTL_SECONDS)).isoformat(), "values": {}}


# Capabilities whose planner-facing output carries a sample of the target's response body.
WITHHOLDING_CAPABILITIES = frozenset({"artifact.inspect", "http.request"})


def withholding_operation(capability_name: str, action_id: Any, operation: Callable[[], Awaitable[Any]]):
    """``(operation, collector)``: run a body-sampling capability with a withheld-value collector.

    Inside it, every value the body masking withholds becomes a ``[withheld:n]`` marker and stays
    in the collector; other capabilities run unchanged with no collector.
    """
    if capability_name not in WITHHOLDING_CAPABILITIES:
        return operation, None
    from .archive_body_masking import WithheldValues, collecting_withheld_values
    collector = WithheldValues(str(action_id))

    async def collecting() -> Any:
        with collecting_withheld_values(collector):
            return await operation()

    return collecting, collector


async def persist_withheld_values(
    conn: Any, *, run: Mapping[str, Any], action_id: Any, target: TargetBinding,
    values: Any, status: str, observations: Any = None,
) -> int:
    """Seal the values an action's output withheld; returns how many are referenceable.

    ``values`` is ``{number: value}`` or the action's collector, of which only the values whose
    markers reached ``observations`` (the planner's view) are sealed: a workflow response reduced
    to its status shows none. Merged into the action's private result, beside any response
    capture. Values past the payload bound are dropped, so their references refuse rather than
    send something else.
    """
    if values is None:
        return 0
    if not isinstance(values, Mapping):
        collector = values
        values = collector.shown_values(json.dumps(observations, default=str))
        collector.values.clear()
    if not values or status != "success" or run["status"] not in {
            "active", "awaiting_planner", "budget_exhausted"} or run.get("completed_at"):
        return 0
    run_id, source_id = str(run["id"]), str(uuid.UUID(str(action_id)))
    row = await conn.fetchrow("SELECT private_http_result FROM hunt_actions WHERE id=$1 AND hunt_run_id=$2",
        uuid.UUID(source_id), uuid.UUID(run_id))
    payload = _private_payload(run_id, source_id, target)
    existing = str(row["private_http_result"] or "") if row else ""
    if existing.startswith("enc:fernet:"):
        try:
            prior = json.loads(decrypt_secret(existing))
            if prior.get("hunt_id") == run_id and prior.get("source_action_id") == source_id:
                payload = prior
        except Exception:
            payload = _private_payload(run_id, source_id, target)
    kept: dict[str, str] = {}
    for number, value in sorted(values.items()):
        payload[WITHHELD_SCHEMA_KEY] = {**kept, str(int(number)): str(value)}
        if len(json.dumps(payload, ensure_ascii=False).encode()) > _MAX_WITHHELD_PAYLOAD_BYTES:
            break
        kept[str(int(number))] = str(value)
    payload[WITHHELD_SCHEMA_KEY] = kept
    try:
        sealed = encrypt_secret(json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    except Exception:
        sealed = None  # no encryption key: the values stay withheld and unreferenceable
    finally:
        payload.clear()
    if not str(sealed or "").startswith("enc:fernet:"):
        return 0  # never store a withheld value in clear
    await conn.execute("UPDATE hunt_actions SET private_http_result=$3 WHERE id=$1 AND hunt_run_id=$2",
        uuid.UUID(source_id), uuid.UUID(run_id), sealed)
    return len(kept)


async def settle_private_results(
    conn: Any, *, run: Mapping[str, Any], status: str, exchange: HttpWorkflowExchange | None,
    withheld: Any, action_id: Any, target: TargetBinding, observations: Any,
    receipt_result: dict[str, Any],
) -> None:
    """Inside the action's settlement: persist its response captures and seal its withheld values."""
    if exchange is not None:
        await exchange.persist(conn, run=run, status=status)
        receipt_result["captures"] = exchange.public_result()
    await persist_withheld_values(conn, run=run, action_id=action_id, target=target,
        values=withheld, status=status, observations=observations)


async def _withheld_value(conn: Any, *, run_id: str, target: TargetBinding, reference: str) -> str:
    from .archive_body_masking import WITHHELD_REF_RE
    match = WITHHELD_REF_RE.fullmatch(str(reference))
    if match is None:
        raise ValueError("withheld value reference is invalid")
    source_id, number = match.group(1), int(match.group(2))
    row = await conn.fetchrow("""SELECT private_http_result FROM hunt_actions
        WHERE id=$1 AND hunt_run_id=$2 AND status='completed'""", uuid.UUID(source_id), uuid.UUID(run_id))
    ciphertext = str(row["private_http_result"] or "") if row else ""
    if len(ciphertext) > 131_072 or not ciphertext.startswith("enc:fernet:"):
        raise ValueError("withheld value reference is unavailable in this Hunt")
    try:
        private = json.loads(decrypt_secret(ciphertext))
        expires_at = datetime.fromisoformat(private["expires_at"])
        if (private["schema_version"] != SCHEMA or private["hunt_id"] != run_id
                or private["source_action_id"] != source_id
                or private["target_digest"] != _target_digest(target)
                or expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc)):
            raise ValueError("binding changed or expired")
        return str(_scalar(private[WITHHELD_SCHEMA_KEY][str(number)]))
    except Exception:
        raise ValueError("withheld value reference is expired or no longer bound to this Hunt") from None


async def prepare_http_exchange(
    conn: Any, *, run: Mapping[str, Any], action_id: Any, target: TargetBinding,
    context: Mapping[str, Any], policy: Mapping[str, Any], values: Mapping[str, Any],
    trusted_headers: Mapping[str, str], capture_state: HttpWorkflowExchange | None = None,
) -> tuple[dict[str, Any], dict[str, str], HttpWorkflowExchange]:
    """Resolve values only after the caller holds a revalidated action reservation."""
    from .hunt_http_contract import require_http_request_authority
    from .capability_registry import CAPABILITY_REGISTRY
    CAPABILITY_REGISTRY.validate_hunt_input("http.request", values)
    require_http_request_authority(values, policy)
    run_id = str(run["id"])
    exchange = capture_state or HttpWorkflowExchange(run_id, str(action_id), target, tuple(values.get("capture") or ()))
    inputs = copy.deepcopy(dict(values))
    inputs.pop("capture", None)
    inputs.pop("request_bindings", None)
    headers = dict(trusted_headers)
    for binding in values.get("request_bindings") or ():
        if "withheld_ref" in binding:
            value = await _withheld_value(conn, run_id=run_id, target=target, reference=binding["withheld_ref"])
            exchange.bound_values.append(str(value))
        elif "source_action_id" in binding:
            value = await _captured_value(conn, run_id=run_id, target=target, binding=binding)
        else:
            selected = ({"profile_id": binding["profile_id"], "profile_version": binding["profile_version"]}
                if "profile_id" in binding else select_hunt_principal_reference(
                    context, binding["principal"], capability="http.request"))
            authority = await validate_worker_credential_authority(conn, owner_kind="hunt", owner_id=run_id,
                target=target, approval_receipt_id=policy.get("approval_receipt_id"),
                scope_receipt_id=target.scope_receipt_id, action_name="hunt.capability:http.request")
            async with WorkerCredentialResolver().resolve(conn, profile_id=selected["profile_id"], target=target,
                    capability="http.request", authority=authority, expected_version=selected["profile_version"],
                    expected_principal_slot=selected.get("principal_slot")) as resolved:
                value = _scalar(resolved.http_workflow_value(binding["credential_field"]))
        if "body_pointer" in binding:
            body_name = "json_body" if "json_body" in inputs else "form_body"
            pointer_set(inputs[body_name], binding["body_pointer"], value)
        else:
            name = binding["header"]
            if any(str(key).lower() == name.lower() for key in (*headers, *(inputs.get("headers") or {}))):
                raise ValueError("HTTP workflow header conflicts with another selected header")
            text = str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None
            if text is None or any(ord(char) < 32 or ord(char) == 127 for char in text):
                raise ValueError("HTTP workflow header value is invalid")
            headers[name] = str(binding.get("prefix") or "") + text
    CAPABILITY_REGISTRY.validate_hunt_input("http.request", inputs)
    if sum(len(str(key).encode()) + len(str(value).encode()) for key, value in headers.items()) > 65_536:
        raise ValueError("HTTP workflow headers exceed the request limit")
    return inputs, headers, exchange

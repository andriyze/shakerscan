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
# One budget for an action's serialized private result (captures, withheld values, dump column
# knowledge), enforced before every write. Fernet expands 65,536 plaintext bytes to about 87,500
# characters, inside the 131,072-character limit every reader enforces.
MAX_PRIVATE_RESULT_BYTES = 65_536
MAX_PRIVATE_RESULT_CHARS = 131_072
MAX_CAPTURE_BYTES = MAX_PRIVATE_RESULT_BYTES
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
    if len(ciphertext) > MAX_PRIVATE_RESULT_CHARS or not ciphertext.startswith("enc:fernet:"):
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
WITHHELD_EXPIRES_KEY = "withheld_expires_at"
# A withheld value lives as long as its Hunt does (finish and cancel clear it, a Hunt that is no
# longer live refuses it), and never longer than this: a leaked credential found early in a long
# Hunt must still be usable late in it.
WITHHELD_TTL_SECONDS = 24 * 3_600
_LIVE_HUNT_STATUSES = frozenset({"active", "awaiting_planner", "budget_exhausted"})


def _hunt_is_live(run: Mapping[str, Any]) -> bool:
    return run.get("status") in _LIVE_HUNT_STATUSES and not run.get("completed_at")


def _private_payload(run_id: str, action_id: str, target: TargetBinding) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {"schema_version": SCHEMA, "hunt_id": run_id, "source_action_id": action_id,
        "target_digest": _target_digest(target),
        "expires_at": (now + timedelta(seconds=CAPTURE_TTL_SECONDS)).isoformat(), "values": {}}


# Capabilities whose planner-facing output carries target response content.
WITHHOLDING_CAPABILITIES = frozenset({"artifact.inspect", "javascript.analyze", "http.request"})


# Seeding is bounded by the text it scans for, most recent first: a long Hunt's oldest values
# stop being searched before the scan gets slow.
_MAX_SEEDED_CHARS = 65_536
# Shorter values (a pairing PIN) would match ordinary text everywhere; their outputs are reduced.
_MIN_SEEDED_CHARS = 6
SQL_TABLES_KEY = "sql_tables"
CONTEXT_BYTES_KEY = "context_bytes"
_MAX_SQL_PATHS = 64
_MAX_SQL_TABLES = 256
_MAX_SQL_COLUMNS = 256


def _sql_entries(tables: Any) -> list[tuple[str, str, list[str]]]:
    """``(path, table, columns)`` of carried knowledge, names bounded, in its order."""
    entries: list[tuple[str, str, list[str]]] = []
    if not isinstance(tables, Mapping):
        return entries
    for path, by_table in tables.items():
        if not isinstance(by_table, Mapping):
            continue
        for table, columns in by_table.items():
            if isinstance(columns, (list, tuple)) and columns:
                entries.append((str(path)[:2048], str(table)[:128],
                                [str(column)[:128] for column in columns[:_MAX_SQL_COLUMNS]]))
    return entries


def _knowledge_entries(
    tables: Any, seeded: Any, prior: Any,
) -> list[tuple[str, str, list[str]]]:
    """The knowledge to seal, most worth keeping first, within the path and table bounds.

    Resource verdicts and COPY block positions (keys starting with ``\0``) come first: they are
    a few names each, and they decide whether rows fail closed. Then the column knowledge this
    action learned (``tables`` less what it was ``seeded`` with), then the rest: knowledge
    seeded from earlier actions (already sealed in their own results) and this action's
    ``prior`` private result. Earlier entries win a duplicate."""
    current, earlier = _sql_entries(tables), _sql_entries(prior)
    seeded_tables = seeded if isinstance(seeded, Mapping) else {}

    def learned(entry: tuple[str, str, list[str]]) -> bool:
        path, table, columns = entry
        by_table = seeded_tables.get(path)
        return not isinstance(by_table, Mapping) or by_table.get(table) != columns

    ordered = (
        [entry for entry in current + earlier if entry[1].startswith("\0")]
        + [entry for entry in current if learned(entry)]
        + current + earlier
    )
    result: list[tuple[str, str, list[str]]] = []
    seen: set[tuple[str, str]] = set()
    per_path: dict[str, int] = {}
    for path, table, columns in ordered:
        if (path, table) in seen:
            continue
        if path not in per_path and len(per_path) >= _MAX_SQL_PATHS:
            continue
        if per_path.get(path, 0) >= _MAX_SQL_TABLES:
            continue
        seen.add((path, table))
        per_path[path] = per_path.get(path, 0) + 1
        result.append((path, table, columns))
    return result


def _bounded_sql_tables(tables: Any) -> dict[str, dict[str, list[str]]]:
    """Column names per resource path and table: names only, never values, bounded."""
    result: dict[str, dict[str, list[str]]] = {}
    if not isinstance(tables, Mapping):
        return result
    for path, by_table in list(tables.items())[:_MAX_SQL_PATHS]:
        if not isinstance(by_table, Mapping):
            continue
        kept = {
            str(table)[:128]: [str(column)[:128] for column in columns[:_MAX_SQL_COLUMNS]]
            for table, columns in list(by_table.items())[:_MAX_SQL_TABLES]
            if isinstance(columns, (list, tuple)) and columns
        }
        if kept:
            result[str(path)[:2048]] = kept
    return result


async def sealed_hunt_knowledge(conn: Any, *, run_id: Any, target: TargetBinding) -> dict[str, Any]:
    """What this Hunt already knows about the target, from its sealed private results:
    ``values`` (withheld values and response captures, most recent first, bounded) and
    ``sql_tables`` (dump column names per resource path). Worker-private."""
    rows = await conn.fetch("""SELECT private_http_result FROM hunt_actions
        WHERE hunt_run_id=$1 AND private_http_result IS NOT NULL
        ORDER BY completed_at DESC NULLS LAST, id""", uuid.UUID(str(run_id)))
    digest, now = _target_digest(target), datetime.now(timezone.utc)
    values: list[str] = []
    tables: dict[str, dict[str, list[str]]] = {}
    context_bytes = 0
    budget = _MAX_SEEDED_CHARS
    for row in rows or ():
        try:
            ciphertext = str(row["private_http_result"])
            if len(ciphertext) > MAX_PRIVATE_RESULT_CHARS:
                continue
            private = json.loads(decrypt_secret(ciphertext))
            expires_at = datetime.fromisoformat(private.get(WITHHELD_EXPIRES_KEY) or private["expires_at"])
            if private.get("hunt_id") != str(run_id) or private.get("target_digest") != digest or expires_at <= now:
                continue
            found = [*(private.get(WITHHELD_SCHEMA_KEY) or {}).values(), *(private.get("values") or {}).values()]
            learned = _bounded_sql_tables(private.get(SQL_TABLES_KEY))
            context_bytes += max(0, int(private.get(CONTEXT_BYTES_KEY) or 0))
        except Exception:
            continue  # an unreadable row seeds nothing; its own references refuse
        for path, by_table in learned.items():
            tables.setdefault(path, {})
            for table, columns in by_table.items():
                tables[path].setdefault(table, columns)  # most recent first wins
        for value in found:
            if isinstance(value, str) and len(value) >= _MIN_SEEDED_CHARS and len(value) <= budget and value not in values:
                values.append(value)
                budget -= len(value)
    return {"values": values, "sql_tables": tables, "context_bytes": context_bytes}


async def sealed_hunt_values(conn: Any, *, run_id: Any, target: TargetBinding) -> list[str]:
    return (await sealed_hunt_knowledge(conn, run_id=run_id, target=target))["values"]


def known_values_seed(pool: Any, run_id: Any, target: TargetBinding) -> Callable[[], Awaitable[dict[str, Any]]]:
    async def seed() -> dict[str, Any]:
        async with pool.acquire() as conn:
            return await sealed_hunt_knowledge(conn, run_id=run_id, target=target)
    return seed


def withholding_operation(
    capability_name: str, action_id: Any, operation: Callable[[], Awaitable[Any]],
    seed: Callable[[], Awaitable[list[str]]] | None = None,
):
    """``(operation, collector)``: run a body-sampling capability with a withheld-value collector.

    Inside it, every value the body masking withholds becomes a ``[withheld:n]`` marker and stays
    in the collector; other capabilities run unchanged with no collector. ``seed`` gives the
    values this Hunt already sealed for the target: a re-read, a window split elsewhere, or a
    later echo of any of them is withheld too, whatever surrounds it.
    """
    if capability_name not in WITHHOLDING_CAPABILITIES:
        return operation, None
    from .archive_body_masking import WithheldValues, collecting_withheld_values
    collector = WithheldValues(str(action_id))

    async def collecting() -> Any:
        if seed is not None:
            knowledge = await seed()
            if isinstance(knowledge, Mapping):
                collector.bind_known(knowledge.get("values") or (), found=True)
                for path, by_table in (knowledge.get("sql_tables") or {}).items():
                    collector.sql_tables.setdefault(path, {}).update(by_table)
                collector.sql_seeded = copy.deepcopy(collector.sql_tables)
                collector.context_bytes_used = int(knowledge.get("context_bytes") or 0)
            else:
                collector.bind_known(knowledge, found=True)
        with collecting_withheld_values(collector):
            return await operation()

    return collecting, collector


def _serialized(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _byte_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode())


def _resolvable(value: str) -> bool:
    try:
        _scalar(value)
    except ValueError:
        return False
    return True


def _fit_private_payload(
    base: dict[str, Any], values: list[tuple[str, str]], tables: list[tuple[str, str, list[str]]],
) -> tuple[dict[str, Any], int, int]:
    """``(payload, values kept, table entries kept)`` within ``MAX_PRIVATE_RESULT_BYTES``.

    The base (captures, expiry, accounting) is kept whole. Secret references come next, in order,
    because a reference the planner was shown must resolve; dump knowledge fills what is left,
    in the order given (``_knowledge_entries``: verdicts, then the newest columns), and is the
    first to be evicted, last entry first."""
    payload = dict(base)
    budget = MAX_PRIVATE_RESULT_BYTES - _byte_size(payload) - 64  # the two keys and their braces
    kept_values: dict[str, str] = {}
    for key, value in values:
        cost = _byte_size(key) + _byte_size(value) + 2
        if cost > budget:
            break
        kept_values[key] = value
        budget -= cost
    kept: list[tuple[str, str, list[str]]] = []
    paths: set[str] = set()
    for path, table, columns in tables:
        cost = _byte_size(table) + _byte_size(columns) + 2 + (0 if path in paths else _byte_size(path) + 4)
        if cost > budget:
            continue
        kept.append((path, table, columns))
        paths.add(path)
        budget -= cost

    def place() -> None:
        nested: dict[str, dict[str, list[str]]] = {}
        for path, table, columns in kept:
            nested.setdefault(path, {})[table] = columns
        payload.pop(SQL_TABLES_KEY, None)
        payload.pop(WITHHELD_SCHEMA_KEY, None)
        if kept_values:
            payload[WITHHELD_SCHEMA_KEY] = kept_values
        if nested:
            payload[SQL_TABLES_KEY] = nested

    place()
    # The estimate is conservative; the exact serialized size is what is checked.
    while _byte_size(payload) > MAX_PRIVATE_RESULT_BYTES and (kept or kept_values):
        if kept:
            kept.pop()
        else:
            kept_values.popitem()
        place()
    return payload, len(kept_values), len(kept)


async def persist_withheld_values(
    conn: Any, *, run: Mapping[str, Any], action_id: Any, target: TargetBinding,
    values: Any, status: str, observations: Any = None,
) -> dict[str, Any]:
    """Seal the values an action's output withheld: ``{"sealed": n, "status": ...}``.

    ``values`` is ``{number: value}`` or the action's collector, of which only the values whose
    markers reached ``observations`` (the planner's view) are sealed: a workflow response reduced
    to its status shows none. Merged into the action's private result, beside any response
    capture, within one serialized-byte budget (``MAX_PRIVATE_RESULT_BYTES``): references first,
    dump column knowledge with what is left. What does not fit is reported in ``not_retained``
    and its references refuse rather than send something else. A prior private result that
    cannot be read is kept, never overwritten, and the status says so.

    A value's number is its identity: when this action's prior private result already holds a
    value under a number, the prior value is kept and the new one under that number is not
    sealed, so a reference the planner was shown never starts resolving to something else.
    """
    if values is None:
        return {"sealed": 0, "status": "none"}
    tables: dict[str, dict[str, list[str]]] = {}
    seeded: Any = {}
    context_bytes = 0
    if not isinstance(values, Mapping):
        collector = values
        values = collector.shown_values(json.dumps(observations, default=str))
        tables = collector.sql_tables if _sql_entries(collector.sql_tables) else {}
        seeded = getattr(collector, "sql_seeded", {}) or {}
        context_bytes = int(getattr(collector, "context_bytes", 0) or 0)
        collector.values.clear()
    if not values and not tables and not context_bytes:
        return {"sealed": 0, "status": "none"}
    if status != "success" or not _hunt_is_live(run):
        return {"sealed": 0, "status": "action_or_hunt_not_live"}
    run_id, source_id = str(run["id"]), str(uuid.UUID(str(action_id)))
    row = await conn.fetchrow("SELECT private_http_result FROM hunt_actions WHERE id=$1 AND hunt_run_id=$2",
        uuid.UUID(source_id), uuid.UUID(run_id))
    base = _private_payload(run_id, source_id, target)
    existing = str(row["private_http_result"] or "") if row else ""
    if existing:
        try:
            prior = (json.loads(decrypt_secret(existing))
                     if existing.startswith("enc:fernet:") and len(existing) <= MAX_PRIVATE_RESULT_CHARS else None)
        except Exception:
            prior = None
        if not (isinstance(prior, dict) and prior.get("hunt_id") == run_id
                and prior.get("source_action_id") == source_id):
            # Keep the response capture this action already sealed; its withheld values stay
            # withheld (shown, unreferenceable), and the planner is told why.
            return {"sealed": 0, "status": "prior_private_result_unreadable"}
        base = prior
    prior_values = base.pop(WITHHELD_SCHEMA_KEY, None) or {}
    prior_tables = base.pop(SQL_TABLES_KEY, None)
    base[WITHHELD_EXPIRES_KEY] = (
        datetime.now(timezone.utc) + timedelta(seconds=WITHHELD_TTL_SECONDS)).isoformat()
    if context_bytes:
        base[CONTEXT_BYTES_KEY] = int(base.get(CONTEXT_BYTES_KEY) or 0) + context_bytes
    if _byte_size(base) > MAX_PRIVATE_RESULT_BYTES:
        return {"sealed": 0, "status": "no_room", "not_retained": {"values": len(values)}}
    candidates = [(str(key), str(value)) for key, value in prior_values.items()
                  if isinstance(value, str)]
    # A value the resolver would refuse (``MAX_VALUE_BYTES``) is not sealed: it is reported as not
    # retained instead of handing out a reference that cannot send.
    candidates += [(str(int(number)), str(value)) for number, value in sorted(values.items())
                   if str(int(number)) not in prior_values and _resolvable(str(value))]
    entries = _knowledge_entries(tables, seeded, prior_tables)
    payload, kept_count, table_count = _fit_private_payload(base, candidates, entries)
    kept_numbers = set(payload.get(WITHHELD_SCHEMA_KEY) or {})
    sealed_new = sum(1 for number in values if str(int(number)) in kept_numbers)
    serialized = _serialized(payload)
    payload.clear()
    try:
        sealed = encrypt_secret(serialized)
    except Exception:
        sealed = None  # no encryption key: the values stay withheld and unreferenceable
    finally:
        serialized = ""
    if not str(sealed or "").startswith("enc:fernet:"):
        return {"sealed": 0, "status": "encryption_unavailable"}  # never stored in clear
    if len(sealed) > MAX_PRIVATE_RESULT_CHARS:
        return {"sealed": 0, "status": "no_room", "not_retained": {"values": len(values)}}
    await conn.execute("UPDATE hunt_actions SET private_http_result=$3 WHERE id=$1 AND hunt_run_id=$2",
        uuid.UUID(source_id), uuid.UUID(run_id), sealed)
    result: dict[str, Any] = {
        "sealed": sealed_new,
        "status": ("sealed" if sealed_new == len(values) else "partially_sealed") if values else "knowledge_only",
    }
    unresolvable = sum(1 for value in values.values() if not _resolvable(str(value)))
    dropped_values, dropped_tables = len(candidates) - kept_count + unresolvable, len(entries) - table_count
    if dropped_values or dropped_tables:
        result["not_retained"] = {"values": dropped_values, "sql_tables": dropped_tables}
    return result


async def settle_private_results(
    conn: Any, *, run: Mapping[str, Any], status: str, exchange: HttpWorkflowExchange | None,
    withheld: Any, action_id: Any, target: TargetBinding, observations: Any,
    receipt_result: dict[str, Any],
) -> None:
    """Inside the action's settlement: persist its response captures and seal its withheld values."""
    if exchange is not None:
        await exchange.persist(conn, run=run, status=status)
        receipt_result["captures"] = exchange.public_result()
    sealing = await persist_withheld_values(conn, run=run, action_id=action_id, target=target,
        values=withheld, status=status, observations=observations)
    if sealing["status"] != "none":
        receipt_result["withheld_values_sealing"] = sealing


async def _withheld_value(
    conn: Any, *, run: Mapping[str, Any], target: TargetBinding, reference: str,
) -> str:
    from .archive_body_masking import WITHHELD_REF_RE
    match = WITHHELD_REF_RE.fullmatch(str(reference))
    if match is None:
        raise ValueError("withheld value reference is invalid")
    if not _hunt_is_live(run):
        raise ValueError("withheld value reference belongs to a Hunt that is no longer live")
    run_id = str(run["id"])
    source_id, number = match.group(1), int(match.group(2))
    row = await conn.fetchrow("""SELECT private_http_result FROM hunt_actions
        WHERE id=$1 AND hunt_run_id=$2 AND status='completed'""", uuid.UUID(source_id), uuid.UUID(run_id))
    ciphertext = str(row["private_http_result"] or "") if row else ""
    if len(ciphertext) > MAX_PRIVATE_RESULT_CHARS or not ciphertext.startswith("enc:fernet:"):
        raise ValueError("withheld value reference is unavailable in this Hunt")
    try:
        private = json.loads(decrypt_secret(ciphertext))
        expires_at = datetime.fromisoformat(private.get(WITHHELD_EXPIRES_KEY) or private["expires_at"])
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
            value = await _withheld_value(conn, run=run, target=target, reference=binding["withheld_ref"])
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

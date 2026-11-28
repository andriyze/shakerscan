"""The object a Hunt planted for ``authz.verify`` mode ``planted_object``, from the server's records.

A planner that created an object as one of the two principals (an ordinary ``http.request`` POST,
PUT or PATCH of this Hunt) names that create request (``create_action_id``) and one field of its
body (``planted_field``). The value and the creating principal come from what the server holds,
never from the planner: the create action's archived request body (decrypted here, in the worker)
and its recorded input (``as_principal``, ``session_ref`` or the captured login it bound).

The field must be named for something private (a secret, a password, a note, an address...), and
its value long and varied enough that nothing else on the page can hold it by chance; the proof
in ``capabilities/authz_planted`` then shows the other principal reading it.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any
import urllib.parse
import uuid

# A field name is read as its words (snake_case, kebab-case, dotted and camelCase all split) and
# one whole word must be private: ``note`` is, ``footnote`` is not; ``card`` is, ``discard`` is not.
_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_PRIVATE_WORDS = frozenset({
    "secret", "secrets", "password", "passwd", "pwd", "token", "tokens", "apikey", "private", "note", "notes",
    "ssn", "card", "cvv", "iban", "address", "phone", "mobile", "birth", "birthday", "birthdate", "dob",
    "salary", "medical", "diagnosis", "diagnoses", "email", "personal",
})
# Two words that are private only together.
_PRIVATE_PAIRS = frozenset({("api", "key"), ("social", "security"), ("account", "number"), ("account", "no"),
                            ("account", "num"), ("pass", "word")})
# ``address`` after one of these is where a machine is, not where a person lives.
_NETWORK_ADDRESS = frozenset({"ip", "ipv4", "ipv6", "mac", "host", "server", "web", "url", "site", "remote",
                              "bind", "listen", "contract", "memory"})
MIN_VALUE_CHARS = 12
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


class PlantedObjectRefused(ValueError):
    """The named create request cannot anchor the proof; nothing is sent."""


def private_field(name: str) -> bool:
    words = [word.lower() for word in _WORD.findall(str(name or ""))]
    for index, word in enumerate(words):
        before = words[index - 1] if index else ""
        if word in _PRIVATE_WORDS and not (word == "address" and before in _NETWORK_ADDRESS):
            return True
        if (before, word) in _PRIVATE_PAIRS:
            return True
    return False


def distinctive(value: str) -> bool:
    """Long and varied enough that its presence on a page is this value, not a coincidence."""
    text = str(value or "")
    return len(text) >= MIN_VALUE_CHARS and len(set(text)) >= 8 and not text.isdigit()


def _body_value(body: bytes, content_type: str, field: str) -> str | None:
    text = bytes(body or b"").decode("utf-8", "replace")
    found: list[str] = []
    if "json" in content_type or text.lstrip()[:1] in {"{", "["}:
        try:
            document = json.loads(text)
        except ValueError:
            document = None

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(node, Mapping):
                for key, child in node.items():
                    if key == field and isinstance(child, str):
                        found.append(child)
                    walk(child, depth + 1)
            elif isinstance(node, list):
                for child in node[:50]:
                    walk(child, depth + 1)

        walk(document)
    else:
        found = [value for name, value in urllib.parse.parse_qsl(text, keep_blank_values=True) if name == field]
    return found[0] if len(found) == 1 else None


def _archived_text(stored: Any) -> str:
    """An archived body as text. The archive keeps text bodies as a JSON string (the body's text
    quoted), so one layer of JSON is undone when the stored value is one."""
    if isinstance(stored, (bytes, bytearray)):
        stored = bytes(stored).decode("utf-8", "replace")
    text = str(stored or "")
    if text.startswith('"'):
        try:
            inner = json.loads(text)
        except ValueError:
            return text
        if isinstance(inner, str):
            return inner
    return text


def creator_slot(action_input: Mapping[str, Any], values: Mapping[str, Any]) -> str | None:
    """Which of the proof's two principals sent the create request, or None."""
    principal = str(action_input.get("as_principal") or "").lower()
    if values.get("primary_principal") and principal in {"primary", "secondary"}:
        return principal
    session = str(action_input.get("session_ref") or "")
    if session:
        for slot in ("primary", "secondary"):
            if session == str(values.get(f"{slot}_session_ref") or ""):
                return slot
    sources = {str(item.get("source_action_id")) for item in action_input.get("request_bindings") or ()
               if isinstance(item, Mapping) and item.get("source_action_id")}
    if sources:
        for slot in ("primary", "secondary"):
            login = {str(item.get("source_action_id")) for item in values.get(f"{slot}_bindings") or ()
                     if isinstance(item, Mapping) and item.get("source_action_id")}
            if login and sources == login:
                return slot
    return None


async def planted_source(conn: Any, *, hunt_id: Any, values: Mapping[str, Any]) -> tuple[str, str]:
    """``(creator slot, planted value)`` of the create request ``values`` name."""
    from runtime.http_archive_reader import read_transaction_payloads
    field = str(values.get("planted_field") or "")
    if not private_field(field):
        raise PlantedObjectRefused(
            "planted_field must name a private field (a secret, password, token, note, address, ...): "
            "a public field another user may read by design proves nothing")
    try:
        action_id = uuid.UUID(str(values.get("create_action_id") or ""))
    except ValueError:
        raise PlantedObjectRefused("create_action_id names the http.request that created the object") from None
    row = await conn.fetchrow(
        """SELECT input_summary, status FROM hunt_actions
           WHERE id=$1 AND hunt_run_id=$2 AND capability_name='http.request'""",
        action_id, uuid.UUID(str(hunt_id)))
    if row is None or row["status"] not in {"completed", "partial"}:
        raise PlantedObjectRefused("create_action_id is not a completed http.request of this Hunt")
    summary = row["input_summary"]
    summary = json.loads(summary) if isinstance(summary, str) else dict(summary or {})
    action_input = summary.get("input") if isinstance(summary.get("input"), Mapping) else {}
    if str(action_input.get("method") or "").upper() not in _WRITE_METHODS:
        raise PlantedObjectRefused("the create request is a POST, PUT or PATCH")
    slot = creator_slot(action_input, values)
    if slot is None:
        raise PlantedObjectRefused(
            "the create request was not sent as one of the two principals this proof compares")
    transactions = await conn.fetch(
        """SELECT id, status_code, request_headers_object_id FROM http_transactions
           WHERE hunt_run_id=$1 AND hunt_action_id=$2 AND method IN ('POST','PUT','PATCH')
           ORDER BY sequence DESC LIMIT 1""",
        uuid.UUID(str(hunt_id)), action_id)
    if not transactions or not (200 <= int(transactions[0]["status_code"] or 0) < 300):
        raise PlantedObjectRefused("the create request has no archived 2xx answer")
    payloads, _used = await read_transaction_payloads(
        conn, [transactions[0]["id"]], external_payload_budget=1 << 20, hunt_run_id=str(hunt_id))
    payload = payloads.get(str(transactions[0]["id"])) or {}
    body = _archived_text(payload.get("request_body"))
    headers = payload.get("request_headers") or {}
    if isinstance(headers, (bytes, str)):
        try:
            headers = json.loads(headers)
        except ValueError:
            headers = {}
    content_type = str({str(k).lower(): v for k, v in dict(headers or {}).items()}.get("content-type") or "")
    value = _body_value(body.encode(), content_type.lower(), field)
    if value is None or not distinctive(value):
        raise PlantedObjectRefused(
            f"the create request's body holds no single distinctive value in {field} "
            f"(at least {MIN_VALUE_CHARS} varied characters)")
    return slot, value

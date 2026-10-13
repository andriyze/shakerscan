"""Secrets in Scan findings: keep them in the target's discovered-secrets store, never in evidence.

A defence in depth for every finding the worker writes: checks mask their own evidence, and before
a Scan's result is written anywhere (the result artifact, a scan's stored result, the findings
table, a fleet node's posted result), every self-evident provider secret still in a finding's
evidence is kept, encrypted, in ``discovered_secrets`` for the Scan's target and replaced by its
``secret://`` reference, or by ``[REDACTED:<kind>]`` when it cannot be kept (no target row, no
encryption key, no database). A value handed over in ``_discovered_secret_values`` is masked and
the key removed; it is not kept. The replacement is idempotent: scrubbed text no longer matches.
"""
from __future__ import annotations

from typing import Any, Mapping

try:
    from capabilities.secret_material import SELF_EVIDENT_SECRET_PATTERNS, is_placeholder_secret
except ModuleNotFoundError:  # package import layout
    from ..capabilities.secret_material import SELF_EVIDENT_SECRET_PATTERNS, is_placeholder_secret

PRIVATE_VALUES_KEY = "_discovered_secret_values"
MAX_STRING_CHARS = 200_000
MAX_VALUES_PER_REPORT = 256


def _matches(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if not text:
        return found
    text = text[:MAX_STRING_CHARS]  # a longer string is searched in its first part
    for label, pattern in SELF_EVIDENT_SECRET_PATTERNS:
        if not pattern.groups:
            continue  # a structural marker (PEM header), not a value
        for match in pattern.finditer(text):
            value = match.group(1)
            if value and not is_placeholder_secret(value):
                found.append((label, value))
    return found


def _collect(value: Any, sink: dict[str, str]) -> None:
    if isinstance(value, str):
        for label, found in _matches(value):
            sink.setdefault(found, label)
    elif isinstance(value, Mapping):
        for nested in value.values():
            _collect(nested, sink)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _collect(nested, sink)


def _replace(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        for raw in sorted(replacements, key=len, reverse=True):
            if raw in value:
                value = value.replace(raw, replacements[raw])
        return value
    if isinstance(value, dict):
        return {key: _replace(nested, replacements) for key, nested in value.items()}
    if isinstance(value, list):
        return [_replace(nested, replacements) for nested in value]
    if isinstance(value, tuple):
        return tuple(_replace(nested, replacements) for nested in value)
    return value


async def scrub_findings(
    conn: Any, *, target_id: Any, scan_id: Any, findings: list[Any],
) -> dict[str, int]:
    """Keep and mask the secrets in ``findings`` (dicts, changed in place). ``conn`` may be None:
    the values are then masked and not kept. Returns counts, never values."""
    values: dict[str, str] = {}
    handed: dict[str, str] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for holder in (finding, finding.get("evidence")):
            if isinstance(holder, Mapping):
                for item in holder.get(PRIVATE_VALUES_KEY) or ():
                    if isinstance(item, Mapping) and isinstance(item.get("value"), str) and item["value"]:
                        handed.setdefault(item["value"], str(item.get("label") or "other"))
        for key, nested in finding.items():
            if key not in {"id", PRIVATE_VALUES_KEY}:
                _collect(nested, values)
    if not values and not handed:
        return {"found": 0, "kept": 0}
    pairs = list(values.items())[:MAX_VALUES_PER_REPORT]
    references: dict[str, str] = {}
    if conn is not None and target_id and pairs:
        try:
            try:
                from hunt.discovered_secrets import record_discovered, reference_for
            except ModuleNotFoundError:
                from ..hunt.discovered_secrets import record_discovered, reference_for
            await record_discovered(
                conn, target_id=target_id, values=[(value, label) for value, label in pairs],
                source={"kind": "scan_finding", "id": str(scan_id or "")})
            for value, _label in pairs:
                reference = await reference_for(conn, target_id=target_id, value=value)
                if reference:
                    references[value] = reference
        except Exception:
            references = {}  # nothing kept: every value is masked below
    for value, label in handed.items():
        values.setdefault(value, label)
    replacements = {
        value: (f"[{references[value]}]" if value in references else f"[REDACTED:{label}]")
        for value, label in values.items()
    }
    for finding in findings:
        if isinstance(finding, dict):
            finding.pop(PRIVATE_VALUES_KEY, None)
            if isinstance(finding.get("evidence"), dict):
                finding["evidence"].pop(PRIVATE_VALUES_KEY, None)
            for key in list(finding):
                if key != "id":
                    finding[key] = _replace(finding[key], replacements)
    return {"found": len(values), "kept": len(references)}


def mask_payload(value: Any) -> Any:
    """Mask (never keep) every self-evident provider secret anywhere in ``value``: for a payload
    stored before the worker scrubs it, such as a fleet node's posted result."""
    found: dict[str, str] = {}
    _collect(value, found)
    if not found:
        return value
    return _replace(value, {raw: f"[REDACTED:{label}]" for raw, label in found.items()})


async def scrub_report_secrets(pool: Any, *, scan_id: Any, result: Any) -> dict[str, int]:
    """The worker's pass over a Scan result before it is written: its ``findings`` (and each
    module's ``findings`` lists) are scrubbed in place. A failure to keep values still masks."""
    if not isinstance(result, dict):
        return {"found": 0, "kept": 0}
    lists = [result.get("findings")]
    for module in (result.get("modules") or {}).values() if isinstance(result.get("modules"), dict) else ():
        if isinstance(module, dict):
            lists.append(module.get("findings"))
    findings = [f for items in lists if isinstance(items, list) for f in items if isinstance(f, dict)]
    if not findings:
        return {"found": 0, "kept": 0}
    target_id = None
    try:
        if pool is not None and scan_id:
            async with pool.acquire() as conn:
                target_id = await conn.fetchval("SELECT target_id FROM scans WHERE id=$1::uuid", str(scan_id))
                return await scrub_findings(conn, target_id=target_id, scan_id=scan_id, findings=findings)
    except Exception:
        pass
    return await scrub_findings(None, target_id=None, scan_id=scan_id, findings=findings)

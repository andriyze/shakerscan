"""Carry a finding's row across a finding identity change instead of duplicating it.

Two changes moved rows to new keys: 2.3.8 gave CWE-less endpoint findings their own check (they
had shared the tool name), and later the check joined the CWE as the class of findings that name
one (distinct checks sharing a CWE on one URL had shared a row).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def legacy_finding_fingerprint(legacy_identity: str | None, fingerprint: str) -> str | None:
    """The fingerprint a pre-2.3.8 installation stored for this identity, if it differs."""
    if not legacy_identity:
        return None
    candidate = "t:" + hashlib.sha256(legacy_identity.encode()).hexdigest()[:16]
    return candidate if candidate != fingerprint else None


def _legacy_identities(finding: dict) -> list[str]:
    """The earlier templated keys this finding may still be stored under, oldest change first."""
    try:
        from findings import legacy_templated_finding_identity, pre_check_templated_finding_identity, pre_service_templated_finding_identity, template_path
    except ImportError:  # package layout
        from scanner.findings import legacy_templated_finding_identity, pre_check_templated_finding_identity, pre_service_templated_finding_identity, template_path
    identities = []
    pre_service = None
    for previous in (legacy_templated_finding_identity, pre_check_templated_finding_identity, pre_service_templated_finding_identity):
        try:
            identity = previous(finding)
        except Exception:  # noqa: BLE001 - an unreadable finding simply has no legacy row
            identity = None
        if identity:
            identities.append(identity)
            if previous is pre_service_templated_finding_identity:
                pre_service = identity
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = {}
    if finding.get("cwe") == "CWE-79" and isinstance(evidence, dict) and evidence.get("client_route"):
        from urllib.parse import urlsplit, parse_qsl
        route = urlsplit(str(evidence["client_route"]).lstrip("!"))
        params = {key for key, _ in parse_qsl(route.query, keep_blank_values=True)}
        if evidence.get("param"):
            params.add(str(evidence["param"]))
        identities.append(f"CWE-79|{evidence.get('method') or 'GET'}|"
                          f"{template_path(evidence.get('path') or '/')}#"
                          f"{template_path(route.path or '/')}|{','.join(sorted(params))}")
    # Hunt qualified findings on a service other than its target with its own suffix, which
    # wrote IPv6 hosts without brackets (https://::1:443). Reproduce that spelling so those
    # rows are adopted rather than split.
    suffix = _historical_hunt_service_suffix(finding.get("url"))
    if suffix:
        bases = [pre_service] if pre_service else []
        if finding.get("cwe") == "CWE-79" and isinstance(evidence, dict) and evidence.get("client_route"):
            bases.append(identities[-1])
        identities.extend(base + suffix for base in bases)
    return list(dict.fromkeys(identities))


def _historical_hunt_service_suffix(url: Any) -> str:
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(str(url or ""))
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    except ValueError:
        return ""
    # Only IPv6 hosts were spelled differently; every other historical suffix equals today's.
    if scheme not in {"http", "https"} or not parsed.hostname or ":" not in parsed.hostname:
        return ""
    return f"|service={scheme}://{parsed.hostname}:{port}"


async def reconcile_legacy_finding_row(
    conn: Any,
    *,
    target_uuid: Any,
    fingerprint: str,
    finding: dict,
    target_kind: str = "web",
) -> Any | None:
    """Move the row an older installation holds for this finding to its new key.

    Under an older key several checks shared one row (before 2.3.8 every CWE-less
    match on a route; before checks joined the CWE, every check sharing a CWE on
    a URL), so that row carries the title of whichever was written last. It is
    the same finding only when the title agrees; then its triage and history
    move to the new fingerprint and the caller updates it as existing. Any other
    legacy row is left alone: it belongs to a different check, goes stale on its
    own, and never has one disposition copied onto every split. A row moves
    once, so only one of the split findings can adopt it.
    """
    target_column = "device_target_id" if target_kind == "device" else "target_id"
    for identity in _legacy_identities(finding):
        legacy_fingerprint = legacy_finding_fingerprint(identity, fingerprint)
        if not legacy_fingerprint:
            continue
        legacy_row = await conn.fetchrow(
            f"""
            SELECT id, status, resurfaced_count, title, tool, cwe, url, evidence
            FROM findings
            WHERE {target_column} = $1 AND fingerprint = $2
            FOR UPDATE
            """,
            target_uuid, legacy_fingerprint,
        )
        if not legacy_row or str(legacy_row.get("title") or "") != str(finding.get("title") or ""):
            continue
        try:
            from finding_service_identity import same_finding_service
        except ModuleNotFoundError:
            from scanner.finding_service_identity import same_finding_service
        if not same_finding_service(legacy_row, finding):
            continue
        current = await conn.fetchrow(
            f"SELECT id FROM findings WHERE {target_column}=$1 AND fingerprint=$2 FOR UPDATE",
            target_uuid, fingerprint,
        )
        if current:
            return None
        try:
            # A concurrent run can insert the canonical key after our absence check.
            # Roll back only this re-key, retaining the legacy row and its history.
            async with conn.transaction():
                await conn.execute(
                    """WITH prior AS MATERIALIZED (
                        SELECT id, target_id, fingerprint FROM findings WHERE id=$2 FOR UPDATE
                    ), moved AS (
                        UPDATE findings SET fingerprint=$1 WHERE id=$2 RETURNING id
                    )
                    UPDATE finding_exceptions AS exception
                    SET finding_id=prior.id::text, fingerprint=$1, updated_at=NOW(),
                        edit_history=COALESCE(exception.edit_history, '[]'::jsonb) || jsonb_build_array(
                            jsonb_build_object('transition', 'finding_identity_rekey',
                                              'fingerprint', exception.fingerprint,
                                              'finding_id', exception.finding_id,
                                              'replaced_at', NOW()))
                    FROM prior, moved
                    WHERE moved.id=prior.id AND exception.target_id=prior.target_id
                      AND exception.fingerprint=prior.fingerprint
                      AND (NULLIF(exception.finding_id, '') IS NULL OR exception.finding_id=prior.id::text)
                    """,
                    fingerprint, legacy_row["id"],
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) != "23505":
                raise
            return await conn.fetchrow(
                f"SELECT id, status, resurfaced_count, title, tool, cwe, url, evidence "
                f"FROM findings WHERE {target_column}=$1 AND fingerprint=$2 FOR UPDATE",
                target_uuid, fingerprint,
            )
        return legacy_row
    return None

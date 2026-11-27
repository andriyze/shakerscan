"""Persist the settled evidence of a cancelled parallel parent through the shared report path.

Dependencies are supplied by the worker; this module never imports the worker composition root.
"""
from __future__ import annotations

import json
from typing import Any
import urllib.parse
import uuid

from .cancelled_report import cancelled_parallel_parent_report

async def fold_cancelled_parent(pool: Any, parent_id: str | None, log_prefix: str, *,
                                redis_provider: Any, finding_merge_key: Any, fingerprint: Any,
                                save_findings: Any) -> int | None:
    """Keep a cancelled parallel Scan's findings: the union of what its shards kept.

    A cancelled parent is never merged; this stores the union of its completed shards and of
    its cancelled shards' kept reports under the parent, which stays cancelled. It runs again
    each time a shard of a cancelled parent settles (a shard that was running when the
    parent was cancelled settles later), so it is idempotent: the parent row is locked and
    the union is rebuilt from every shard. Returns the kept count, or None when the parent is
    not cancelled.
    """
    if not parent_id:
        return None
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                parent = await conn.fetchrow(
                    "SELECT status, scan_role, target_id, target_url FROM scans WHERE id=$1 FOR UPDATE",
                    uuid.UUID(str(parent_id)),
                )
                if not parent or parent['status'] != 'cancelled' or parent['scan_role'] != 'parent':
                    return None
                children = await conn.fetch(
                    """SELECT id, status, shard_index, result FROM scans
                       WHERE parent_scan_id=$1 AND scan_role='shard'
                       ORDER BY shard_index NULLS LAST, id""",
                    uuid.UUID(str(parent_id)),
                )
                recon: list[Any] = []
                try:
                    raw = redis_provider().get(f"coverage:recon_findings:{parent_id}")
                    recon = json.loads(raw) if raw else []
                except Exception:
                    recon = []

                def merge_key(finding: dict[str, Any]) -> str:
                    key = finding_merge_key(finding)
                    if key:
                        return key
                    try:
                        return fingerprint(finding)
                    except Exception:
                        return json.dumps(finding, sort_keys=True, default=str)[:256]

                report = cancelled_parallel_parent_report(
                    target_url=parent['target_url'], children=[dict(row) for row in children],
                    merge_key=merge_key, extra_findings=recon if isinstance(recon, list) else (),
                )
                findings = report['findings']
                try:
                    from findings import apply_dast_precision_policy
                    host = urllib.parse.urlparse(str(parent['target_url'] or "")).hostname
                    report['findings'] = findings = apply_dast_precision_policy(findings, target_host=host or None)
                except Exception:
                    pass
                await conn.execute(
                    """UPDATE scans SET result=$2, findings_count=$3, coverage_status='cancelled',
                              coverage_json=$4, score=NULL, grade=NULL
                       WHERE id=$1 AND status='cancelled'""",
                    uuid.UUID(str(parent_id)), json.dumps(report), len(findings),
                    json.dumps(report['coverage']),
                )
        target_id = str(parent['target_id']) if parent['target_id'] else None
        if target_id and findings:
            await save_findings(str(parent_id), target_id, findings)
        print(f"[{log_prefix}] cancelled parent {str(parent_id)[:8]} keeps {len(findings)} finding(s)", flush=True)
        return len(findings)
    except Exception as e:
        print(f"[{log_prefix}] cancelled parent fold error: {type(e).__name__}", flush=True)
        return None



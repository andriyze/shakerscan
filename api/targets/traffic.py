"""Which runs sent requests to an asset, and when: the engine's side of traffic attribution.

Every request a Scan, retest or Hunt sends carries ``X-ShakerScan-Run: scan:<id>`` or
``hunt:<id>`` (``scanner_tools.traffic_attribution``). A security team that sees that header, or
just a burst of requests, asks the operator "was this you?"; ``GET /targets/{id}/traffic``
answers from the request archive the engine already keeps (``http_transactions``): each run that
touched the target, its first and last request, how many requests, how many answers were 5xx or
429, and the target addresses connected to. Nothing new is stored.
"""
from __future__ import annotations

from typing import Any

TRAFFIC_LIMIT = 200

_TRAFFIC_SQL = """
SELECT CASE WHEN t.scan_id IS NOT NULL THEN 'scan' ELSE 'hunt' END AS kind,
       COALESCE(t.scan_id, t.hunt_run_id) AS run_id,
       MIN(t.started_at) AS first_request_at, MAX(t.started_at) AS last_request_at,
       COUNT(*) AS requests,
       COUNT(*) FILTER (WHERE t.status_code >= 500 OR t.status_code = 429 OR t.error IS NOT NULL)
           AS degraded_answers,
       ARRAY_REMOVE(ARRAY_AGG(DISTINCT t.remote_ip), NULL) AS target_addresses,
       MAX(s.run_kind) AS run_kind, MAX(s.status) AS scan_status, MAX(h.status) AS hunt_status
  FROM http_transactions t
  LEFT JOIN scans s ON s.id = t.scan_id
  LEFT JOIN hunt_runs h ON h.id = t.hunt_run_id
 WHERE t.target_id = $1 AND ($2::timestamptz IS NULL OR t.started_at >= $2)
 GROUP BY 1, 2
 ORDER BY MAX(t.started_at) DESC NULLS LAST
 LIMIT $3"""


async def target_traffic(conn: Any, target_id: Any, *, since: Any = None) -> list[dict[str, Any]]:
    rows = await conn.fetch(_TRAFFIC_SQL, target_id, since, TRAFFIC_LIMIT)
    out = []
    for row in rows:
        item = dict(row)
        kind, run_id = item["kind"], str(item["run_id"])
        out.append({
            "run": f"{kind}:{run_id}", "kind": "retest" if item.get("run_kind") == "retest" else kind,
            "id": run_id,
            "status": item.get("scan_status") if kind == "scan" else item.get("hunt_status"),
            "first_request_at": item["first_request_at"].isoformat() if item["first_request_at"] else None,
            "last_request_at": item["last_request_at"].isoformat() if item["last_request_at"] else None,
            "requests": int(item["requests"]),
            "degraded_answers": int(item["degraded_answers"]),
            "target_addresses": sorted(item.get("target_addresses") or []),
        })
    return out

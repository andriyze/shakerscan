"""Operations routes.

Extracted verbatim from the api.py monolith. Groups the small operational read
and control surfaces that share no domain of their own: subdomain discovery runs,
Gungnir certificate-transparency monitoring, queue statistics and the emergency
clear, stored result listings, the cross-product mission timeline, host resource
reporting, and the compatibility CLI v1 reads.

/health, /metrics/v2, and /workers deliberately stay in the composition root:
they report on the application and its container fleet rather than on a product
domain, and other routers are wired to the health probe.

Collaborators that are still hubs inside api.py are injected by the composition
root as lazily-resolved callables.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
import re
import shutil
from typing import Any, Callable, Literal, Mapping, Optional
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

try:
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _direct_query_value, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_iso_datetime, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    import asm_inventory
    import parallel_scan
    from finding_routes import router as _finding_routes
    from fleet_routes.router import BROKER_INGEST_QUEUE_NAME
    from job_queue import clear_unleased, pending_depth, queue_payloads
    from scan.compatibility import record_compatibility_call
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _direct_query_value, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_iso_datetime, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from .. import asm_inventory, parallel_scan
    from ..finding_routes import router as _finding_routes
    from ..fleet_routes.router import BROKER_INGEST_QUEUE_NAME
    from ..job_queue import clear_unleased, pending_depth, queue_payloads
    from ..scan.compatibility import record_compatibility_call
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_operations_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call

# Cross-domain call through the owning module, not a frozen binding.
async def list_findings(*a: Any, **k: Any) -> Any:
    return await _finding_routes.list_findings(*a, **k)


# Hub collaborators that still live in api.py, injected and resolved lazily.
def get_redis(*a: Any, **k: Any) -> Any:
    return _dep("get_redis")(*a, **k)


def enqueue_job(*a: Any, **k: Any) -> Any:
    return _dep("enqueue_job")(*a, **k)


def docker_socket_request(*a: Any, **k: Any) -> Any:
    return _dep("docker_socket_request")(*a, **k)


def _results_dir() -> Any:
    return _dep("results_dir")()


async def get_scan(*a: Any, **k: Any) -> Any:
    return await _dep("get_scan")(*a, **k)


import logging

logger = logging.getLogger("shakerscan.api.operations")
QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")
DEVICE_QUEUE_NAME = os.environ.get("DEVICE_QUEUE_NAME", "device_scan_jobs")
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")
HEARTBEAT_TIMEOUT_MINUTES = int(os.environ.get("FLEET_HEARTBEAT_TIMEOUT_MINUTES", "10"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

@router.get("/api/v1/scan", deprecated=True)
async def get_cli_v1_scan(
    response: Response,
    id: str = Query(..., min_length=1),
):
    """Compatibility bridge for CLI status and wait commands."""
    _set_cli_v1_deprecation_headers(response)
    record_compatibility_call(get_redis(), "cli_v1_status")
    result = await get_scan(id)
    result.setdefault("scan_id", str(result.get("id") or id))
    scan_type = str(result.get("scan_type") or "") or None
    result.setdefault("requested_scan_type", scan_type)
    result.setdefault("effective_scan_type", scan_type)
    return result


@router.get("/timeline")
async def mission_timeline(
    limit: int = Query(50, ge=1, le=200),
    target_id: Optional[str] = Query(None, description="Filter events to one target."),
    include_campaign_actions: bool = Query(True, description="Include campaign/action records not already represented by a command result."),
    include_scans: bool = Query(True, description="Include recent scans not tied to a command result."),
    include_schedules: bool = Query(True, description="Include upcoming recurring schedules."),
    include_evidence: bool = Query(True, description="Include evidence-instance binding events."),
    include_refuters: bool = Query(True, description="Include refuter review/signal events."),
    include_exports: bool = Query(True, description="Include durable content-free export events."),
):
    """Read-only cross-product mission timeline.

    Merges command-result audit rows (with live scan status joined in), recent
    user-facing scans not tied to a command result, and upcoming schedules into
    one normalized event feed with explicit, API-backed statuses. Read-only: it
    computes nothing the browser would otherwise have to infer from scan JSON.
    """
    try:
        target_uuid = _optional_uuid(target_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="target_id must be a UUID") from exc
    include_campaign_actions = bool(_direct_query_value(include_campaign_actions))
    include_scans = bool(_direct_query_value(include_scans))
    include_schedules = bool(_direct_query_value(include_schedules))
    include_evidence = bool(_direct_query_value(include_evidence))
    include_refuters = bool(_direct_query_value(include_refuters))
    include_exports = bool(_direct_query_value(include_exports))
    hidden_roles = _hidden_scan_roles_for_list()

    async with _pool().acquire() as conn:
        cr_rows = await conn.fetch(
            """
            SELECT cr.*,
                   s.status AS scan_status,
                   s.target_url AS scan_target_url,
                   s.target_id AS scan_target_id,
                   ca.id AS campaign_action_id,
                   ca.mission_campaign_id AS mission_campaign_id
            FROM command_results cr
            LEFT JOIN scans s ON cr.scan_id = s.id
            LEFT JOIN LATERAL (
                SELECT id, mission_campaign_id
                FROM campaign_actions
                WHERE command_result_id = cr.id
                ORDER BY updated_at DESC NULLS LAST, created_at DESC
                LIMIT 1
            ) ca ON true
            WHERE ($2::uuid IS NULL OR s.target_id = $2)
            ORDER BY cr.created_at DESC
            LIMIT $1
            """,
            limit,
            target_uuid,
        )
        events = [_command_result_timeline_event(row) for row in cr_rows]

        if include_campaign_actions:
            action_rows = await conn.fetch(
                """
                SELECT ca.*,
                       s.status AS scan_status,
                       s.target_url AS scan_target_url,
                       s.target_id AS scan_target_id
                FROM campaign_actions ca
                LEFT JOIN scans s ON ca.scan_id = s.id
                WHERE ca.command_result_id IS NULL
                  AND ($2::uuid IS NULL OR ca.target_id = $2 OR s.target_id = $2)
                ORDER BY ca.created_at DESC
                LIMIT $1
                """,
                limit,
                target_uuid,
            )
            events.extend(_campaign_action_timeline_event(row) for row in action_rows)

        if include_scans:
            scan_rows = await conn.fetch(
                """
                SELECT s.id, s.status, s.target_url, s.target_id, s.scan_type,
                       s.run_kind, s.grade, s.findings_count, s.created_at
                FROM scans s
                WHERE (s.scan_role IS NULL OR s.scan_role <> ALL($3::text[]))
                  AND NOT EXISTS (SELECT 1 FROM command_results cr WHERE cr.scan_id = s.id)
                  AND ($2::uuid IS NULL OR s.target_id = $2)
                ORDER BY s.created_at DESC
                LIMIT $1
                """,
                limit,
                target_uuid,
                hidden_roles,
            )
            events.extend(_scan_timeline_event(row) for row in scan_rows)

        if include_evidence:
            evidence_rows = await conn.fetch(
                """
                SELECT ei.*,
                       ca.campaign_id AS campaign_id,
                       s.target_id AS scan_target_id,
                       s.target_url AS scan_target_url,
                       f.target_id AS finding_target_id
                FROM evidence_instances ei
                LEFT JOIN campaign_actions ca ON ei.campaign_action_id = ca.id
                LEFT JOIN scans s ON ei.scan_id = s.id
                LEFT JOIN findings f ON ei.finding_id = f.id
                WHERE ($2::uuid IS NULL OR ei.target_id = $2 OR s.target_id = $2 OR f.target_id = $2)
                ORDER BY ei.created_at DESC
                LIMIT $1
                """,
                limit,
                target_uuid,
            )
            events.extend(_evidence_instance_timeline_event(row) for row in evidence_rows)

        if include_refuters:
            refuter_rows = await conn.fetch(
                """
                SELECT rr.*,
                       f.target_id AS finding_target_id,
                       h.target_id AS hypothesis_target_id
                FROM refuter_reviews rr
                LEFT JOIN findings f ON rr.finding_id = f.id
                LEFT JOIN hypotheses h ON rr.hypothesis_id = h.id
                WHERE ($2::uuid IS NULL OR rr.target_id = $2 OR f.target_id = $2 OR h.target_id = $2)
                ORDER BY rr.created_at DESC
                LIMIT $1
                """,
                limit,
                target_uuid,
            )
            events.extend(_refuter_review_timeline_event(row) for row in refuter_rows)

        if include_exports:
            export_rows = await conn.fetch(
                """
                SELECT ee.*,
                       s.target_id AS scan_target_id,
                       s.target_url AS scan_target_url,
                       f.target_id AS finding_target_id
                FROM export_events ee
                LEFT JOIN scans s ON ee.scan_id = s.id
                LEFT JOIN findings f ON ee.finding_id = f.id
                WHERE ($2::uuid IS NULL OR ee.target_id = $2 OR s.target_id = $2 OR f.target_id = $2)
                ORDER BY ee.created_at DESC
                LIMIT $1
                """,
                limit,
                target_uuid,
            )
            events.extend(_export_event_timeline_event(row) for row in export_rows)

        upcoming: list[dict[str, Any]] = []
        if include_schedules:
            schedule_rows = await conn.fetch(
                """
                SELECT sc.id, sc.name, sc.target_id, t.url AS target_url,
                       sc.frequency, sc.schedule_kind, sc.scan_type,
                       sc.next_run_at, sc.last_run_at
                FROM schedules sc
                LEFT JOIN targets t ON sc.target_id = t.id
                WHERE sc.is_active = true AND sc.next_run_at IS NOT NULL
                  AND ($2::uuid IS NULL OR sc.target_id = $2)
                ORDER BY sc.next_run_at ASC
                LIMIT $1
                """,
                limit,
                target_uuid,
            )
            upcoming = [_schedule_timeline_event(row) for row in schedule_rows]

    events.sort(key=_timeline_sort_key, reverse=True)
    events = events[:limit]
    return {
        "events": events,
        "upcoming": upcoming,
        "count": len(events),
        "statuses": list(TIMELINE_STATUSES),
        "execution_enabled": False,
    }


@router.get("/api/v1/findings", deprecated=True)
async def list_cli_v1_findings(
    request: Request,
    response: Response,
    scan_id: str = Query(..., min_length=1),
    severity: Optional[str] = None,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Compatibility bridge for the installed CLI findings command."""
    _set_cli_v1_deprecation_headers(response)
    return await list_findings(
        request=request,
        severity=severity,
        status=None,
        source_type=None,
        target_id=None,
        ai_target_id=None,
        device_target_id=None,
        scan_id=scan_id,
        root_domain=None,
        verification_verdict=None,
        verification_mode=None,
        verified_only=False,
        driven_by=None,
        research_campaign_id=None,
        search=None,
        seen_within_days=None,
        first_seen_within_days=None,
        resolved_within_days=None,
        sort_by=None,
        sort_order="desc",
        include_candidates=False,
        limit=limit,
        offset=offset,
        include_details=True,
    )


@router.post("/discovery")
async def start_discovery(root_domain: str):
    """Start subdomain discovery for a domain."""
    r = get_redis()
    job_id = str(uuid.uuid4())
    discovery_id = str(uuid.uuid4())

    async with _pool().acquire() as conn:
        await conn.execute("""
            INSERT INTO discovery_runs (id, root_domain, status)
            VALUES ($1, $2, 'pending')
        """, uuid.UUID(discovery_id), root_domain)

    # Queue the discovery job
    job_data = {
        'job_id': job_id,
        'discovery_id': discovery_id,
        'type': 'discovery',
        'root_domain': root_domain,
        'submitted_at': utc_now_iso()
    }
    enqueue_job(r, QUEUE_NAME, job_data)

    return {
        'discovery_id': discovery_id,
        'job_id': job_id,
        'root_domain': root_domain,
        'status': 'queued'
    }


@router.get("/discovery")
async def list_discovery_runs(limit: int = Query(20, ge=1, le=200)):
    """List discovery runs."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch("""
            SELECT * FROM discovery_runs
            ORDER BY created_at DESC LIMIT $1
        """, limit)

    return {'discovery_runs': [dict(r) for r in rows]}


@router.get("/discovery/{discovery_id}")
async def get_discovery(discovery_id: str):
    """Get discovery run details."""
    async with _pool().acquire() as conn:
        discovery = await conn.fetchrow(
            "SELECT * FROM discovery_runs WHERE id = $1", uuid.UUID(discovery_id)
        )
        if not discovery:
            raise HTTPException(status_code=404, detail="Discovery run not found")

    return dict(discovery)


@router.get("/system/resources")
async def get_system_resources():
    """CPU/RAM the Docker engine can give containers (i.e. the worker fleet).

    IMPORTANT platform nuance: on macOS/Windows Docker runs inside a Linux VM
    (Docker Desktop), so these numbers are the **VM allocation you set in Docker
    Desktop**, not the physical machine. On native Linux they are the real host.
    Either way this is the correct capacity ceiling for workers — read it from the
    Docker engine (/info), never from os/psutil inside the API container (that
    reports the cgroup/VM view and is misleading)."""
    try:
        status_code, info = docker_socket_request("GET", "/info")
        if status_code != 200 or not isinstance(info, dict):
            return {"available": False, "error": f"docker /info status {status_code}"}
        os_name = str(info.get("OperatingSystem") or "")
        return {
            "available": True,
            "cpus": info.get("NCPU"),
            "mem_total_bytes": info.get("MemTotal"),
            "operating_system": os_name,
            "os_type": info.get("OSType"),
            "server_version": info.get("ServerVersion"),
            # Docker Desktop (mac/win) reports a tunable VM allocation, not host HW.
            "is_desktop_vm": "desktop" in os_name.lower(),
        }
    except Exception:  # pragma: no cover - docker socket optional
        return {"available": False, "error": "Docker resource query failed"}


@router.get("/gungnir/status")
async def gungnir_status():
    """Get Gungnir CT monitor status."""
    r = get_redis()
    status = r.hgetall("gungnir:status")

    # Decode bytes if needed
    if status and isinstance(next(iter(status.values()), None), bytes):
        status = {k.decode() if isinstance(k, bytes) else k:
                  v.decode() if isinstance(v, bytes) else v
                  for k, v in status.items()}

    return {
        "running": status.get("running") == "true" if status else False,
        "domains_monitored": int(status.get("domains_monitored", 0)) if status else 0,
        "subdomains_found": int(status.get("subdomains_found", 0)) if status else 0,
        "session_found": int(status.get("session_found", 0)) if status else 0,
        "last_discovery": status.get("last_discovery") if status else None,
        "started_at": status.get("started_at") if status else None,
        "uptime_seconds": int(status.get("uptime_seconds", 0)) if status else 0,
    }


@router.post("/gungnir/start")
async def gungnir_start():
    """Start Gungnir CT monitor worker using Docker socket API."""
    import urllib.parse

    r = get_redis()

    try:
        def ensure_gungnir_container() -> dict:
            """Find or create a gungnir container from current compose context."""
            status_code, all_containers = docker_socket_request("GET", "/containers/json?all=true")
            if status_code != 200:
                raise HTTPException(500, f"Failed to query containers: status {status_code}")

            project, network, image = get_compose_context(all_containers if isinstance(all_containers, list) else [])
            if not image or not network:
                raise HTTPException(
                    status_code=404,
                    detail="Gungnir container not found and auto-create failed. Start the stack with ./scanner.sh start first."
                )

            # Look for gungnir-worker image specifically, fall back to worker image.
            gungnir_image = None
            if project:
                img_status, images = docker_socket_request("GET", "/images/json")
                if img_status == 200 and isinstance(images, list):
                    gungnir_image_name = f"{project}-gungnir-worker"
                    for img in images:
                        repo_tags = img.get("RepoTags") or []
                        for tag in repo_tags:
                            if gungnir_image_name in tag:
                                gungnir_image = tag
                                break
                        if gungnir_image:
                            break

            image = gungnir_image or image
            name = f"{project}-gungnir-worker-1" if project else "gungnir-worker"
            labels = {}
            if project:
                labels = {
                    "com.docker.compose.project": project,
                    "com.docker.compose.service": "gungnir-worker",
                    "com.docker.compose.oneoff": "False"
                }

            create_body = {
                "Image": image,
                "Cmd": ["python3", "/app/gungnir_worker.py"],
                "Env": [f"REDIS_URL={REDIS_URL}", f"DATABASE_URL={DATABASE_URL}"],
                "Labels": labels,
                "HostConfig": {
                    "NetworkMode": network,
                    "RestartPolicy": {"Name": "unless-stopped"}
                }
            }

            create_path = f"/containers/create?name={urllib.parse.quote(name)}"
            create_status, create_data = docker_socket_request("POST", create_path, create_body)
            if create_status not in (201, 409):
                raise HTTPException(500, f"Failed to create Gungnir container: status {create_status}")

            container_id = create_data.get("Id") if isinstance(create_data, dict) else None
            if not container_id and create_status == 409:
                inspect_status, inspect_data = docker_socket_request("GET", f"/containers/{urllib.parse.quote(name)}/json")
                if inspect_status == 200 and isinstance(inspect_data, dict):
                    container_id = inspect_data.get("Id")

            if not container_id:
                raise HTTPException(500, "Failed to resolve Gungnir container ID after creation.")

            return {"Id": container_id, "State": "created"}

        # Find gungnir container via socket API
        filters = urllib.parse.quote('{"name":["gungnir"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Find the gungnir-worker container
        gungnir = None
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'gungnir' in name.lower():
                gungnir = c
                break

        if not gungnir:
            gungnir = ensure_gungnir_container()

        if gungnir.get('State') == 'running':
            return {
                "status": "already_running",
                "message": "Gungnir is already running"
            }

        # Start the container
        container_id = gungnir.get('Id')
        start_status, start_data = docker_socket_request("POST", f"/containers/{container_id}/start")

        if start_status in [204, 304]:  # 204 = started, 304 = already started
            # Update Redis status
            r.hset("gungnir:status", "running", "true")
            return {
                "status": "started",
                "message": "Gungnir CT monitor started successfully"
            }

        # Self-heal stale containers (e.g., old network ID no longer exists).
        if start_status == 404 and container_id:
            docker_socket_request("DELETE", f"/containers/{container_id}?force=true")
            gungnir = ensure_gungnir_container()
            container_id = gungnir.get('Id')
            start_status, start_data = docker_socket_request("POST", f"/containers/{container_id}/start")
            if start_status in [204, 304]:
                r.hset("gungnir:status", "running", "true")
                return {
                    "status": "started",
                    "message": "Gungnir CT monitor started successfully"
                }

        docker_message = ""
        if isinstance(start_data, dict) and start_data.get("message"):
            docker_message = f" ({start_data.get('message')})"
        raise HTTPException(500, f"Failed to start Gungnir: Docker returned status {start_status}{docker_message}")

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh gungnir start"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Gungnir: {str(e)}")


@router.post("/gungnir/stop")
async def gungnir_stop():
    """Stop Gungnir CT monitor worker using Docker socket API."""
    import urllib.parse

    r = get_redis()

    try:
        # Find gungnir container via socket API
        filters = urllib.parse.quote('{"name":["gungnir"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Find the gungnir-worker container
        gungnir = None
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'gungnir' in name.lower():
                gungnir = c
                break

        if not gungnir:
            # Update Redis status anyway
            r.hset("gungnir:status", "running", "false")
            return {
                "status": "not_found",
                "message": "Gungnir container not found"
            }

        if gungnir.get('State') != 'running':
            # Update Redis status
            r.hset("gungnir:status", "running", "false")
            return {
                "status": "already_stopped",
                "message": "Gungnir is not running"
            }

        # Stop the container
        container_id = gungnir.get('Id')
        stop_status, _ = docker_socket_request("POST", f"/containers/{container_id}/stop")

        # Update Redis status
        r.hset("gungnir:status", "running", "false")

        if stop_status in [204, 304]:  # 204 = stopped, 304 = already stopped
            return {
                "status": "stopped",
                "message": "Gungnir CT monitor stopped"
            }
        else:
            raise HTTPException(500, f"Failed to stop Gungnir: Docker returned status {stop_status}")

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh gungnir stop"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop Gungnir: {str(e)}")


@router.get("/queue/stats")
async def queue_stats():
    """Get queue statistics."""
    r = get_redis()
    cached = r.get("queue:stats_cache")
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass
    now = utc_now()

    completed = 0
    running = 0
    queued = 0
    failed = 0
    retest_completed = 0
    retest_running = 0
    retest_queued = 0
    retest_failed = 0

    queue_entries = queue_payloads(r, QUEUE_NAME, include_leased=False)
    queued_job_ids: set[str] = set()
    malformed_queue_entries = 0
    for raw in queue_entries:
        try:
            job_id = str((json.loads(raw) if isinstance(raw, str) else {}).get("job_id") or "").strip()
        except (TypeError, ValueError, json.JSONDecodeError):
            job_id = ""
        if job_id:
            queued_job_ids.add(job_id)
        else:
            malformed_queue_entries += 1
    async with _pool().acquire() as conn:
        active_rows = await conn.fetch(
            """
            SELECT job_id, status, scan_role FROM scans
            WHERE status IN ('pending','queued','running') AND job_id IS NOT NULL
            """
        )
    active_scan_job_ids = {
        str(row["job_id"])
        for row in active_rows
        if row["status"] in {"pending", "queued"}
    }
    active_running_job_ids = {
        str(row["job_id"])
        for row in active_rows
        if row["status"] == "running"
    }
    # A worker may claim the Redis handoff before the planner moves the durable
    # scan row from pending/queued to running.  That is a valid in-flight
    # transition, not an orphan.  Reconcile running hashes against every active
    # durable handoff; the logical headline still comes from the DB status.
    active_job_ids = active_scan_job_ids | active_running_job_ids
    hidden_roles = set(_hidden_scan_roles_for_list())
    logical_pending = sum(
        1 for row in active_rows
        if row["status"] in {"pending", "queued"} and str(row.get("scan_role") or "") not in hidden_roles
    )
    logical_running = sum(
        1 for row in active_rows
        if row["status"] == "running" and str(row.get("scan_role") or "") not in hidden_roles
    )
    reconciled_queued_job_ids = queued_job_ids & active_scan_job_ids
    stale_queued_job_hashes = 0
    stale_running_job_hashes = 0

    for key in r.scan_iter("job:*"):
        job_data = r.hgetall(key)
        if not job_data:
            continue

        # Redis client uses decode_responses=True, so values are already strings
        status_str = job_data.get('status', '')

        if status_str == 'running':
            job_id = str(key).split("job:", 1)[-1]
            if job_id not in active_job_ids:
                stale_running_job_hashes += 1
                r.hset(key, mapping={
                    "status": "orphaned",
                    "error": "Running job hash has no matching running scan",
                })
                r.expire(key, 86400)
                continue
            heartbeat = job_data.get('heartbeat', '')
            if heartbeat:
                try:
                    last_beat = datetime.fromisoformat(heartbeat)
                    if now - last_beat > timedelta(minutes=HEARTBEAT_TIMEOUT_MINUTES):
                        r.hset(key, 'status', 'failed')
                        r.hset(key, 'error', 'Worker stopped responding')
                        failed += 1
                        continue
                except ValueError:
                    pass
            running += 1
        elif status_str == 'completed':
            completed += 1
        elif status_str == 'queued':
            job_id = str(key).split("job:", 1)[-1]
            if job_id in reconciled_queued_job_ids:
                queued += 1
            else:
                stale_queued_job_hashes += 1
                r.hset(key, mapping={
                    "status": "orphaned",
                    "error": "Queued job hash has no matching queued scan",
                })
                r.expire(key, 86400)
        elif status_str == 'failed':
            failed += 1

    for key in r.scan_iter("retest_job:*"):
        job_data = r.hgetall(key)
        if not job_data:
            continue

        status_str = job_data.get('status', '')

        if status_str == 'running':
            started_at = job_data.get('started_at', '')
            if started_at:
                try:
                    started = datetime.fromisoformat(started_at)
                    if now - started > timedelta(minutes=RETEST_RUNNING_TIMEOUT_MINUTES):
                        r.hset(key, mapping={
                            'status': 'failed',
                            'error': 'Retest worker did not complete in time',
                        })
                        retest_failed += 1
                        continue
                except ValueError:
                    pass
            retest_running += 1
        elif status_str == 'completed':
            retest_completed += 1
        elif status_str == 'queued':
            retest_queued += 1
        elif status_str == 'failed':
            retest_failed += 1

    result = {
        # Dashboard/CLI headline counts are logical user-visible scans. Parallel
        # discovery, shards, and ASM implementation rows are work units, not
        # extra scans. Keep both views explicit for operations and diagnostics.
        'pending': logical_pending,
        'queued': queued,
        'running': logical_running,
        'work_pending': pending_depth(r, QUEUE_NAME),
        'work_running': running,
        'completed': completed,
        'failed': failed,
        'retest_pending': pending_depth(r, RETEST_QUEUE_NAME),
        'broker_ingest_pending': pending_depth(r, BROKER_INGEST_QUEUE_NAME),
        'retest_queued': retest_queued,
        'retest_running': retest_running,
        'retest_completed': retest_completed,
        'retest_failed': retest_failed,
        'queue_consistency': {
            'reconciled': not malformed_queue_entries and not (queued_job_ids - active_scan_job_ids) and not (active_scan_job_ids - queued_job_ids) and not stale_queued_job_hashes and not stale_running_job_hashes,
            'malformed_entries': malformed_queue_entries,
            'queue_without_active_scan': len(queued_job_ids - active_scan_job_ids),
            'active_scan_without_queue_entry': len(active_scan_job_ids - queued_job_ids),
            'stale_queued_job_hashes': stale_queued_job_hashes,
            'stale_running_job_hashes': stale_running_job_hashes,
        },
    }
    try:
        r.set("queue:stats_cache", json.dumps(result), ex=5)
    except Exception:
        pass
    return result


@router.delete("/queue/clear")
async def clear_queue(include_retests: bool = False):
    """Clear all pending scan jobs. Optionally clear retest jobs too."""
    r = get_redis()
    entries = clear_unleased(r, QUEUE_NAME)
    device_entries = clear_unleased(r, DEVICE_QUEUE_NAME)
    all_entries = list(entries) + list(device_entries)
    count = len(all_entries)
    job_ids: list[str] = []
    for raw in all_entries:
        try:
            job_id = str(json.loads(raw).get("job_id") or "").strip()
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            job_id = ""
        if job_id:
            job_ids.append(job_id)
    cancelled_scans = 0
    if job_ids:
        async with _pool().acquire() as conn:
            result = await conn.execute(
                """
                UPDATE scans
                SET status='cancelled', error_message='Cleared from pending queue by operator',
                    completed_at=NOW(), progress=100, current_phase='cancelled'
                WHERE job_id=ANY($1::text[]) AND status IN ('pending','queued')
                """,
                job_ids,
            )
            cancelled_scans = int(str(result).split()[-1]) if str(result).split()[-1].isdigit() else 0
        for job_id in job_ids:
            r.hset(f"job:{job_id}", mapping={"status": "cancelled", "progress": "100", "current_phase": "cancelled"})
            r.expire(f"job:{job_id}", 86400)
    retest_cleared = 0
    if include_retests:
        retest_cleared = len(clear_unleased(r, RETEST_QUEUE_NAME))
    r.delete("queue:stats_cache")
    return {
        'cleared': count,
        'device_cleared': len(device_entries),
        'cancelled_scans': cancelled_scans,
        'retest_cleared': retest_cleared,
    }


@router.get("/results")
async def list_results(limit: int = Query(50, ge=1, le=500)):
    """List recent scan results from files."""
    if not _results_dir().exists():
        return {'results': [], 'count': 0}

    results = []
    for target_dir in _results_dir().iterdir():
        if target_dir.is_dir():
            latest = target_dir / "latest.json"
            if latest.exists():
                try:
                    with open(latest) as fp:
                        data = json.load(fp)
                        results.append({
                            'folder': target_dir.name,
                            'target': data.get('input', {}).get('target'),
                            'score': data.get('result', {}).get('score'),
                            'grade': data.get('result', {}).get('grade'),
                            'timestamp': data.get('timestamp_utc'),
                        })
                except Exception:
                    pass

    # Historical and partially written result files may have a null or
    # non-string timestamp. Normalize the key so one malformed legacy record
    # cannot take down the complete compatibility listing.
    results.sort(key=lambda item: str(item.get('timestamp') or ''), reverse=True)
    return {'results': results[:limit], 'count': len(results)}


@router.get("/results/{target_folder}/latest")
async def get_latest_result(target_folder: str):
    """Get latest scan result for a target."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", target_folder) or target_folder in {".", ".."}:
        raise HTTPException(status_code=404, detail="Result not found")
    try:
        target_dir = next(
            (
                entry for entry in _results_dir().iterdir()
                if not entry.is_symlink() and entry.is_dir() and entry.name == target_folder
            ),
            None,
        )
    except OSError:
        target_dir = None
    if target_dir is None:
        raise HTTPException(status_code=404, detail="Result not found")
    filepath = target_dir / "latest.json"
    if filepath.is_symlink() or not filepath.is_file():
        raise HTTPException(status_code=404, detail="Result not found")
    with open(filepath) as f:
        return json.load(f)
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")


RETEST_RUNNING_TIMEOUT_MINUTES = int(os.environ.get("RETEST_RUNNING_TIMEOUT_MINUTES", "30"))


def _hidden_scan_roles_for_list(*, include_shards: bool = False, include_internal: bool = False) -> list[str]:
    hidden: list[str] = []
    if not include_shards:
        hidden.append("shard")
    if not include_internal:
        hidden.extend([
            asm_inventory.ASM_BATCH_ROLE,
            asm_inventory.ASM_RECON_ROLE,
            parallel_scan.PARALLEL_DISCOVERY_ROLE,
            DEVICE_WEB_ORIGIN_ROLE,
        ])
    return hidden


def _set_cli_v1_deprecation_headers(response: Response) -> None:
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Thu, 31 Dec 2026 23:59:59 GMT"
    response.headers["Link"] = '</scans>; rel="successor-version"'


TIMELINE_STATUSES = (
    "planned", "blocked", "approval_required", "approved", "queued", "running",
    "completed", "partial", "degraded", "failed", "cancelled", "evidence_bound",
    "retest_scheduled", "refuter_requested",
)


def _timeline_sort_key(event: dict[str, Any]) -> str:
    # created_at has already passed through row_to_dict, which renders datetimes
    # as ISO-8601 strings. Postgres TIMESTAMPTZ values come back UTC-normalized,
    # so lexical order over these strings is chronological. None sorts last.
    created = event.get("created_at")
    return str(created) if created else ""


def _command_result_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    cr_status = str(r.get("status") or "")
    scan_status = r.get("scan_status")
    # A live scan status supersedes the frozen command-result status once a scan
    # exists; blocked/approval_required rows have no scan and keep their status.
    status = _timeline_scan_status(scan_status) if scan_status else cr_status
    scan_id = str(r["scan_id"]) if r.get("scan_id") else None
    return {
        "event_id": str(r.get("id")),
        "kind": "command_result",
        "command": r.get("command"),
        "action_name": r.get("command"),
        "status": status,
        "risk_tier": r.get("risk_tier"),
        "dry_run": bool(r.get("dry_run")),
        "target_id": str(r["scan_target_id"]) if r.get("scan_target_id") else None,
        "target_url": r.get("scan_target_url"),
        "scan_id": scan_id,
        "active_scan_id": scan_id if status in ("queued", "running") else None,
        "operation_plan_id": str(r["operation_plan_id"]) if r.get("operation_plan_id") else None,
        "campaign_id": str(r["campaign_id"]) if r.get("campaign_id") else None,
        "mission_campaign_id": str(r["mission_campaign_id"]) if r.get("mission_campaign_id") else None,
        "campaign_action_id": str(r["campaign_action_id"]) if r.get("campaign_action_id") else None,
        "scope_receipt_id": r.get("scope_receipt_id"),
        "approval_receipt_id": str(r["approval_receipt_id"]) if r.get("approval_receipt_id") else None,
        "finding_ids": _decode_json_value(r.get("finding_ids")) or [],
        "evidence_object_ids": _decode_json_value(r.get("evidence_object_ids")) or [],
        "tool_receipt_ids": _decode_json_value(r.get("tool_receipt_ids")) or [],
        "blocked_by": _decode_json_value(r.get("blocked_by")) or [],
        "next_action": r.get("next_action"),
        "operator_message": r.get("operator_message"),
        "created_at": r.get("created_at"),
    }


def _campaign_action_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    action_status = str(r.get("status") or "")
    scan_status = r.get("scan_status")
    status = _timeline_scan_status(scan_status) if scan_status else action_status
    scan_id = str(r["scan_id"]) if r.get("scan_id") else None
    target_id = r.get("target_id") or r.get("scan_target_id")
    return {
        "event_id": str(r.get("id")),
        "kind": "campaign_action",
        "command": r.get("command"),
        "action_name": r.get("action_name") or r.get("command"),
        "status": status,
        "risk_tier": r.get("risk_tier"),
        "dry_run": bool(r.get("dry_run")),
        "target_id": str(target_id) if target_id else None,
        "target_url": r.get("scan_target_url"),
        "scan_id": scan_id,
        "active_scan_id": scan_id if status in ("queued", "running") else None,
        "operation_plan_id": str(r["operation_plan_id"]) if r.get("operation_plan_id") else None,
        "campaign_id": str(r["campaign_id"]) if r.get("campaign_id") else None,
        "command_result_id": str(r["command_result_id"]) if r.get("command_result_id") else None,
        "scope_receipt_id": r.get("scope_receipt_id"),
        "approval_receipt_id": str(r["approval_receipt_id"]) if r.get("approval_receipt_id") else None,
        "finding_ids": _decode_json_value(r.get("finding_ids")) or [],
        "hypothesis_ids": _decode_json_value(r.get("hypothesis_ids")) or [],
        "evidence_object_ids": _decode_json_value(r.get("evidence_object_ids")) or [],
        "tool_receipt_ids": _decode_json_value(r.get("tool_receipt_ids")) or [],
        "blocked_by": _decode_json_value(r.get("blocked_by")) or [],
        "next_action": r.get("next_action"),
        "operator_message": r.get("operator_message"),
        "created_at": r.get("created_at"),
    }


def _scan_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    status = _timeline_scan_status(r.get("status"))
    scan_id = str(r.get("id"))
    return {
        "event_id": scan_id,
        "kind": "scan",
        "command": None,
        "action_name": f"scan:{r.get('run_kind') or 'web_dast'}",
        "status": status,
        "risk_tier": None,
        "target_id": str(r["target_id"]) if r.get("target_id") else None,
        "target_url": r.get("target_url"),
        "scan_id": scan_id,
        "active_scan_id": scan_id if status in ("queued", "running") else None,
        "scan_type": r.get("scan_type"),
        "grade": r.get("grade"),
        "findings_count": r.get("findings_count"),
        "blocked_by": [],
        "next_action": f"/scans/{scan_id}",
        "operator_message": None,
        "created_at": r.get("created_at"),
    }


def _schedule_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    kind = str(r.get("schedule_kind") or "normal_scan")
    return {
        "event_id": f"schedule:{r.get('id')}",
        "kind": "schedule",
        "command": "asm.improve" if kind == "asm_improve" else "scan.submit",
        "action_name": f"schedule:{kind}",
        "status": "planned",
        "risk_tier": None,
        "target_id": str(r["target_id"]) if r.get("target_id") else None,
        "target_url": r.get("target_url"),
        "next_eligible_at": r.get("next_run_at"),
        "name": r.get("name"),
        "scan_type": r.get("scan_type"),
        "blocked_by": [],
        "operator_message": (
            f"Next {kind} for {r.get('target_url') or 'target'}"
        ),
        "created_at": r.get("last_run_at"),
    }


def _evidence_instance_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    evidence_object_id = str(r["evidence_object_id"]) if r.get("evidence_object_id") else None
    tool_receipt_id = str(r["tool_receipt_id"]) if r.get("tool_receipt_id") else None
    finding_id = str(r["finding_id"]) if r.get("finding_id") else None
    scan_id = str(r["scan_id"]) if r.get("scan_id") else None
    target_id = r.get("target_id") or r.get("scan_target_id") or r.get("finding_target_id")
    concrete_url = r.get("concrete_url") or r.get("scan_target_url")
    proof_state = str(r.get("proof_state") or "unverified")
    return {
        "event_id": f"evidence_instance:{r.get('id')}",
        "kind": "evidence_instance",
        "command": "evidence.instance.record",
        "action_name": "evidence_bound",
        "status": "evidence_bound",
        "risk_tier": "read_only",
        "target_id": str(target_id) if target_id else None,
        "target_url": concrete_url,
        "scan_id": scan_id,
        "campaign_id": str(r["campaign_id"]) if r.get("campaign_id") else None,
        "campaign_action_id": str(r["campaign_action_id"]) if r.get("campaign_action_id") else None,
        "finding_ids": [finding_id] if finding_id else [],
        "evidence_object_ids": [evidence_object_id] if evidence_object_id else [],
        "tool_receipt_ids": [tool_receipt_id] if tool_receipt_id else [],
        "proof_state": proof_state,
        "object_id": r.get("object_id"),
        "retention_policy": r.get("retention_policy"),
        "blocked_by": [],
        "next_action": f"/evidence/{evidence_object_id}" if evidence_object_id else None,
        "operator_message": f"Evidence instance recorded ({proof_state})",
        "created_at": r.get("created_at"),
    }


def _refuter_review_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    evidence_ids = _decode_json_value(r.get("evidence_object_ids")) or []
    tool_ids = _decode_json_value(r.get("tool_receipt_ids")) or []
    finding_id = str(r["finding_id"]) if r.get("finding_id") else None
    hypothesis_id = str(r["hypothesis_id"]) if r.get("hypothesis_id") else None
    target_id = r.get("target_id") or r.get("finding_target_id") or r.get("hypothesis_target_id")
    signal = str(r.get("refuter_signal") or "question")
    verdict = r.get("refuter_verdict")
    return {
        "event_id": f"refuter_review:{r.get('id')}",
        "kind": "refuter_review",
        "command": "refuter_review.record",
        "action_name": "refuter_review",
        "status": "completed" if verdict else "refuter_requested",
        "risk_tier": "read_only",
        "target_id": str(target_id) if target_id else None,
        "campaign_id": str(r["campaign_id"]) if r.get("campaign_id") else None,
        "finding_ids": [finding_id] if finding_id else [],
        "hypothesis_ids": [hypothesis_id] if hypothesis_id else [],
        "evidence_object_ids": [str(item) for item in evidence_ids],
        "tool_receipt_ids": [str(item) for item in tool_ids],
        "refuter_signal": signal,
        "refuter_verdict": verdict,
        "verdict_basis": r.get("verdict_basis"),
        "blocked_by": [],
        "next_action": (
            f"/findings/{finding_id}" if finding_id else
            ("/settings/arsenal?tab=hypotheses" if hypothesis_id else "/settings/arsenal?tab=refuters")
        ),
        "operator_message": (
            f"Refuter verdict recorded: {verdict}" if verdict else
            f"Refuter signal recorded: {signal}"
        ),
        "created_at": r.get("created_at"),
    }


def _export_event_timeline_event(row: Any) -> dict[str, Any]:
    r = _public_export_event_row(row)
    target_id = r.get("target_id") or r.get("scan_target_id") or r.get("finding_target_id")
    scan_ids = [str(item) for item in (r.get("scan_ids") or []) if item]
    finding_ids = [str(item) for item in (r.get("finding_ids") or []) if item]
    evidence_ids = [str(item) for item in (r.get("evidence_object_ids") or []) if item]
    primary_scan_id = str(r["scan_id"]) if r.get("scan_id") else (scan_ids[0] if scan_ids else None)
    primary_finding_id = str(r["finding_id"]) if r.get("finding_id") else (finding_ids[0] if finding_ids else None)
    if primary_finding_id and primary_finding_id not in finding_ids:
        finding_ids = [primary_finding_id, *finding_ids]
    replay_plan = r.get("replay_plan") or {}
    return {
        "event_id": f"export_event:{r.get('id')}",
        "kind": "export_event",
        "command": r.get("command") or "evidence.export_bundle",
        "action_name": r.get("export_kind") or "export",
        "status": r.get("status") or "completed",
        "risk_tier": r.get("risk_tier") or "read_only",
        "target_id": str(target_id) if target_id else None,
        "target_url": r.get("scan_target_url"),
        "scan_id": primary_scan_id,
        "finding_ids": finding_ids,
        "evidence_object_ids": evidence_ids,
        "tool_receipt_ids": [],
        "blocked_by": [],
        "bundle_hash": r.get("bundle_hash"),
        "manifest_hash": r.get("manifest_hash"),
        "object_count": r.get("object_count") or 0,
        "content_included": False,
        "replay_paths": [
            str(item.get("api_path"))
            for item in (replay_plan.get("evidence_object_reads") or [])
            if isinstance(item, dict) and item.get("api_path")
        ],
        "next_action": "/settings/arsenal?tab=timeline",
        "operator_message": r.get("operator_message") or "Content-free export recorded",
        "created_at": r.get("created_at"),
    }


def get_compose_context(containers: list) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Infer compose project, network, and image from existing containers."""
    if not containers or not isinstance(containers, list):
        return None, None, None

    def extract_context(c: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
        labels = c.get("Labels", {}) or {}
        project = labels.get("com.docker.compose.project")
        image = c.get("Image")
        networks = (c.get("NetworkSettings") or {}).get("Networks", {})
        network = next(iter(networks.keys()), None) if networks else None
        if project and image and network:
            return project, network, image
        return None, None, None

    def find_by_service(service: str, running_only: bool) -> tuple[Optional[str], Optional[str], Optional[str]]:
        for c in containers:
            labels = c.get("Labels", {}) or {}
            if labels.get("com.docker.compose.service") != service:
                continue
            if running_only and c.get("State") != "running":
                continue
            project, network, image = extract_context(c)
            if project and network and image:
                return project, network, image
        return None, None, None

    preferred_services = ("worker", "api")
    for service in preferred_services:
        project, network, image = find_by_service(service, running_only=True)
        if project and network and image:
            return project, network, image
        project, network, image = find_by_service(service, running_only=False)
        if project and network and image:
            return project, network, image

    for c in containers:
        if c.get("State") != "running":
            continue
        project, network, image = extract_context(c)
        if project and network and image:
            return project, network, image

    for c in containers:
        project, network, image = extract_context(c)
        if project and network and image:
            return project, network, image

    return None, None, None
DEVICE_WEB_ORIGIN_ROLE = "device_web_origin"


def _public_export_event_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "filters",
        "evidence_object_ids",
        "finding_ids",
        "scan_ids",
        "replay_plan",
    ):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key.endswith("_ids") else {})
    return payload


def _timeline_scan_status(raw: Any) -> str:
    key = str(raw or "").strip().lower()
    return _SCAN_STATUS_TO_TIMELINE.get(key, key or "queued")
_SCAN_STATUS_TO_TIMELINE = {
    "pending": "queued",
    "queued": "queued",
    "running": "running",
    "in_progress": "running",
    "completed": "completed",
    "failed": "failed",
    "error": "failed",
    "cancelled": "cancelled",
    "canceled": "cancelled",
}

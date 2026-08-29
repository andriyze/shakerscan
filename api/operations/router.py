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
    from ai_control_requirements import AI_CONTROL_REQUIREMENTS
    from api_utils import (
        SEVERITY_ORDER, _clean_string_list, _record_map, _direct_query_value, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_iso_datetime, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    import asm_inventory
    import parallel_scan
    from finding_routes import router as _finding_routes
    from fleet_routes.router import BROKER_INGEST_QUEUE_NAME
    from artifact_storage import storage_health as artifact_storage_health
    from job_queue import clear_unleased, pending_depth, queue_payloads
    from schedules.router import SCHEDULE_HEALTH_LOOKBACK_DAYS, _schedule_health_map_for_schedules
    from scan.compatibility import record_compatibility_call
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_control_requirements import AI_CONTROL_REQUIREMENTS
    from ..api_utils import (
        SEVERITY_ORDER, _clean_string_list, _direct_query_value, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_iso_datetime, _row_value, _severity_sort_value, _uuid_or_400, utc_now, utc_now_iso,
    )
    from .. import asm_inventory, parallel_scan
    from ..finding_routes import router as _finding_routes
    from ..fleet_routes.router import BROKER_INGEST_QUEUE_NAME
    from ..artifact_storage import storage_health as artifact_storage_health
    from ..job_queue import clear_unleased, pending_depth, queue_payloads
    from ..schedules.router import SCHEDULE_HEALTH_LOOKBACK_DAYS, _schedule_health_map_for_schedules
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
                       sc.frequency, sc.day_of_week, sc.time_of_day, sc.timezone,
                       sc.jitter_minutes, sc.schedule_kind, sc.scan_type,
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
    "planned", "accepted", "blocked", "approval_required", "approved", "queued", "running",
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
    blocked_by = _decode_json_value(r.get("blocked_by")) or []
    # A live scan status supersedes the frozen command-result status once a scan
    # exists; blocked/approval_required rows have no scan and keep their status.
    status = _normalized_timeline_event_status(
        cr_status,
        command=r.get("command"),
        scan_status=scan_status,
        blocked_by=blocked_by,
    )
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
        "blocked_by": blocked_by,
        "next_action": r.get("next_action"),
        "operator_message": r.get("operator_message"),
        "created_at": r.get("created_at"),
    }


def _campaign_action_timeline_event(row: Any) -> dict[str, Any]:
    r = row_to_dict(row)
    action_status = str(r.get("status") or "")
    scan_status = r.get("scan_status")
    blocked_by = _decode_json_value(r.get("blocked_by")) or []
    status = _normalized_timeline_event_status(
        action_status,
        command=r.get("command"),
        scan_status=scan_status,
        blocked_by=blocked_by,
    )
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
        "blocked_by": blocked_by,
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
        "dispatch_at": r.get("next_run_at"),
        "frequency": r.get("frequency"),
        "day_of_week": r.get("day_of_week"),
        "time_of_day": r.get("time_of_day"),
        "timezone": r.get("timezone"),
        "jitter_minutes": int(r.get("jitter_minutes") or 0),
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
        "next_action": f"/evidence?object_id={evidence_object_id}" if evidence_object_id else None,
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


_SUBMISSION_COMMANDS = {
    "scan.submit", "scan.focused_family", "asm.improve", "asm.test",
    "asm.recon", "finding.retest", "ai_gate.scan", "model_intake.scan",
}


def _normalized_timeline_event_status(
    raw: Any,
    *,
    command: Any = None,
    scan_status: Any = None,
    blocked_by: Any = None,
) -> str:
    blockers = [str(item) for item in (blocked_by or []) if str(item).strip()]
    if blockers:
        return "blocked"
    if scan_status:
        return _timeline_scan_status(scan_status)
    status = str(raw or "").strip().lower()
    status = {
        "pending": "queued",
        "dispatching": "queued",
        "in_progress": "running",
        "success": "completed",
        "error": "failed",
        "canceled": "cancelled",
    }.get(status, status or "queued")
    if str(command or "").strip().lower() in _SUBMISSION_COMMANDS and status == "completed":
        return "accepted"
    return status
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
@router.get("/artifacts/storage/health")
async def get_artifact_storage_health(probe: bool = False):
    """Report artifact configuration; optionally exercise object I/O."""
    result = await asyncio.to_thread(
        artifact_storage_health,
        results_dir=_results_dir(),
        write_probe=probe,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=503, detail=result)
    return result


@router.get("/dashboard")
async def dashboard():
    """Get dashboard metrics."""
    async with _pool().acquire() as conn:
        metrics = await conn.fetchrow("SELECT * FROM dashboard_metrics")
        recent_scans = await conn.fetch("""
            SELECT id, target_id, ai_target_id, target_url, status, score, grade,
                   scan_type, run_kind, findings_count, created_at, completed_at
            FROM (
                SELECT DISTINCT ON (
                    COALESCE(
                        'target:' || target_id::text,
                        'ai:' || ai_target_id::text,
                        'url:' || target_url
                    )
                )
                    id, target_id, ai_target_id, target_url, status, score, grade,
                    scan_type, run_kind, findings_count, created_at, completed_at
                FROM scans
                WHERE (scan_role IS NULL OR scan_role <> 'shard')
                  AND COALESCE(run_kind, '') <> 'model_intake'
                  AND COALESCE(scan_type, '') <> 'model_intake'
                  AND device_target_id IS NULL
                  AND COALESCE(scan_role, '') <> 'device_web_origin'
                  AND COALESCE(run_kind, '') NOT IN ('device_posture','device_probe','device_web_dast')
                ORDER BY
                    COALESCE(
                        'target:' || target_id::text,
                        'ai:' || ai_target_id::text,
                        'url:' || target_url
                    ),
                    created_at DESC
            ) latest_per_target
            ORDER BY created_at DESC
            LIMIT 10
        """)
        recent_findings = await conn.fetch("""
            SELECT id, title, severity, status, tool, first_seen_at
            FROM findings
            WHERE status = 'active' AND severity IN ('critical', 'high')
              AND COALESCE(source, '') <> 'device'
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                first_seen_at DESC
            LIMIT 10
        """)
        worker_snapshot = _worker_freshness_snapshot()
        action_center = await _build_dashboard_action_center(conn, worker_snapshot=worker_snapshot)
        product_status = await _build_dashboard_product_status(conn, worker_snapshot=worker_snapshot)
        # Open hunt leads across both planes: not yet verified (promoted to a real
        # finding), refuted, or expired. Single COUNT, no joins.
        suspected_candidates_count = await conn.fetchval(
            """SELECT COUNT(*) FROM investigation_candidates
               WHERE status NOT IN ('verified','refuted','expired')"""
        ) or 0

    return {
        "metrics": dict(metrics) if metrics else {},
        "recent_scans": [dict(s) for s in recent_scans],
        "recent_findings": [dict(f) for f in recent_findings],
        "action_center": action_center,
        "product_status": product_status,
        "suspected_candidates_count": suspected_candidates_count,
    }
async def _build_dashboard_product_status(conn, *, worker_snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Compact cross-product status cards for dashboard navigation.

    This intentionally complements the prioritized Action Center. The Action
    Center says "what should I do first"; these cards keep each product area's
    blocker/running/stale counts visible without requiring the browser to infer
    state from several unrelated API responses.
    """
    items: list[dict[str, Any]] = []

    try:
        row = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (
                    WHERE status = 'active'
                      AND severity IN ('critical', 'high')
                      AND COALESCE(source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake', 'asm', 'manual')
                      AND ai_target_id IS NULL
                      AND COALESCE(tool, '') <> 'model_intake'
                ) AS blockers,
                COUNT(*) FILTER (
                    WHERE status = 'active'
                      AND COALESCE(source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake', 'asm', 'manual')
                      AND ai_target_id IS NULL
                      AND COALESCE(tool, '') <> 'model_intake'
                ) AS active_findings
            FROM findings
        """)
        counts = _record_map(row)
        scan_row = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE status IN ('pending', 'queued', 'running')) AS active_scans,
                COUNT(*) FILTER (WHERE status = 'failed' AND created_at >= NOW() - INTERVAL '7 days') AS recent_failed
            FROM scans
            WHERE (scan_role IS NULL OR scan_role <> 'shard')
              AND COALESCE(run_kind, 'dast') NOT IN ('ai_api', 'ai_widget', 'ai_rag', 'ai_trace', 'ai_mcp', 'model_intake')
        """)
        scan_counts = _record_map(scan_row)
        blockers = int(counts.get("blockers") or 0)
        active_findings = int(counts.get("active_findings") or 0)
        active_scans = int(scan_counts.get("active_scans") or 0)
        recent_failed = int(scan_counts.get("recent_failed") or 0)
        if blockers:
            status = "critical"
            summary = f"{blockers} critical/high active DAST finding(s) need triage."
            href = "/findings?status=active&source_type=dast"
        elif recent_failed:
            status = "warning"
            summary = f"{recent_failed} DAST scan(s) failed in the last 7 days."
            href = "/scans?status=failed"
        elif active_scans:
            status = "info"
            summary = f"{active_scans} DAST scan(s) are queued or running."
            href = "/scans?status=running"
        else:
            status = "ok"
            summary = "No active DAST blockers detected."
            href = "/scans"
        dast_actions = []
        if blockers:
            dast_actions.append({"label": "Review findings", "href": "/findings?status=active&source_type=dast", "variant": "primary"})
        elif recent_failed:
            dast_actions.append({"label": "Failed scans", "href": "/scans?status=failed", "variant": "primary"})
        elif active_scans:
            dast_actions.append({"label": "Running scans", "href": "/scans?status=running", "variant": "primary"})
        else:
            dast_actions.append({"label": "New scan", "href": "/scan/new", "variant": "primary"})
        if recent_failed and dast_actions[0]["href"] != "/scans?status=failed":
            dast_actions.append({"label": "Failed scans", "href": "/scans?status=failed", "variant": "secondary"})
        elif active_scans and dast_actions[0]["href"] != "/scans?status=running":
            dast_actions.append({"label": "Running scans", "href": "/scans?status=running", "variant": "secondary"})
        else:
            dast_actions.append({"label": "All scans", "href": "/scans", "variant": "secondary"})
        items.append(_dashboard_product_status_item(
            item_id="dast",
            label="DAST",
            status=status,
            summary=summary,
            href=href,
            primary_count=blockers,
            primary_label="crit/high",
            secondary_count=active_scans,
            secondary_label="running",
            actions=dast_actions,
            metadata={"active_findings": active_findings, "recent_failed_scans": recent_failed},
        ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="dast",
            label="DAST",
            status="info",
            summary="DAST status unavailable.",
            href="/scans",
        ))

    try:
        row = await conn.fetchrow("""
            WITH per_target AS (
                SELECT
                    t.id,
                    COUNT(te.id) FILTER (WHERE COALESCE(te.test_status, 'untested') <> 'gone') AS total,
                    COUNT(te.id) FILTER (
                        WHERE COALESCE(te.test_status, 'untested') IN ('untested', 'stale', 'partial')
                           OR COALESCE(te.last_attempt_status, '') IN ('partial', 'partial_timeout', 'auth_missing')
                    ) AS needs_work
                FROM targets t
                LEFT JOIN target_endpoints te ON te.target_id = t.id
                WHERE t.is_active = true AND t.asm_enabled = true
                GROUP BY t.id
            )
            SELECT
                COUNT(*) AS enabled_targets,
                COUNT(*) FILTER (WHERE total = 0) AS no_inventory_targets,
                COUNT(*) FILTER (WHERE needs_work > 0) AS targets_with_gaps,
                COALESCE(SUM(needs_work), 0) AS endpoints_needing_work,
                MIN(id::text) FILTER (WHERE total = 0 OR needs_work > 0) AS sample_target_id
            FROM per_target
        """)
        counts = _record_map(row)
        enabled = int(counts.get("enabled_targets") or 0)
        targets_with_gaps = int(counts.get("targets_with_gaps") or 0)
        no_inventory = int(counts.get("no_inventory_targets") or 0)
        endpoints_needing_work = int(counts.get("endpoints_needing_work") or 0)
        sample_target_id = str(counts.get("sample_target_id") or "")
        href = f"/asm?target_id={sample_target_id}" if sample_target_id else "/asm"
        if no_inventory or targets_with_gaps:
            status = "warning"
            summary = f"{no_inventory} target(s) need inventory; {targets_with_gaps} have stale/partial endpoint work."
        elif enabled:
            status = "ok"
            summary = f"{enabled} target(s) under continuous ASM policy."
        else:
            status = "info"
            summary = "No targets have Continuous ASM enabled."
        schedule_href = f"/schedules?create=true&target_id={sample_target_id}" if sample_target_id else "/schedules?create=true"
        items.append(_dashboard_product_status_item(
            item_id="asm",
            label="Continuous ASM",
            status=status,
            summary=summary,
            href=href,
            primary_count=targets_with_gaps + no_inventory,
            primary_label="needs action",
            secondary_count=endpoints_needing_work,
            secondary_label="endpoints",
            actions=[
                {"label": "Target timeline" if sample_target_id else "ASM targets", "href": href, "variant": "primary"},
                {"label": "Create ASM schedule", "href": schedule_href, "variant": "secondary"},
            ],
            metadata={"enabled_targets": enabled},
        ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="asm",
            label="Continuous ASM",
            status="info",
            summary="ASM status unavailable.",
            href="/asm",
        ))

    try:
        findings_row = await conn.fetchrow("""
            SELECT COUNT(*) AS active_findings
            FROM findings
            WHERE status = 'active'
              AND (source = 'ai_gate' OR ai_target_id IS NOT NULL)
        """)
        target_rows = await conn.fetch("""
            SELECT id, name, target_type, endpoint_url, production_mode, metadata_json
            FROM ai_targets
            WHERE is_active = true
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT 250
        """)
        active_findings = int(_record_map(findings_row).get("active_findings") or 0)
        missing_controls = 0
        for row in target_rows:
            target = row_to_dict(row)
            metadata = _decode_json_value(target.get("metadata_json")) or {}
            if not isinstance(metadata, dict):
                metadata = {}
            enforce = bool(metadata.get("enforce_ai_control_baseline"))
            risk = str(metadata.get("risk_tier") or "").lower()
            if target.get("production_mode") or enforce or risk in {"high", "critical"}:
                if _missing_ai_control_labels(target):
                    missing_controls += 1
        active_targets = len(target_rows)
        if active_findings:
            status = "critical"
            summary = f"{active_findings} active AI Gate finding(s) need triage."
        elif missing_controls:
            status = "warning"
            summary = f"{missing_controls} high-risk AI target(s) are missing control evidence."
        elif active_targets:
            status = "ok"
            summary = f"{active_targets} AI target(s) configured."
        else:
            status = "info"
            summary = "No AI Gate targets configured."
        ai_actions = [
            {
                "label": "AI findings" if active_findings else "Control gaps",
                "href": "/findings?source_type=ai&status=active" if active_findings else "/ai-gate?remediate=controls",
                "variant": "primary",
            },
            {
                "label": "Control gaps" if active_findings else "AI findings",
                "href": "/ai-gate?remediate=controls" if active_findings else "/findings?source_type=ai&status=active",
                "variant": "secondary",
            },
        ]
        items.append(_dashboard_product_status_item(
            item_id="ai_gate",
            label="AI Gate",
            status=status,
            summary=summary,
            href="/ai-gate?remediate=controls" if missing_controls and not active_findings else "/ai-gate",
            primary_count=active_findings,
            primary_label="findings",
            secondary_count=missing_controls,
            secondary_label="control gaps",
            actions=ai_actions,
            metadata={"active_targets": active_targets},
        ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="ai_gate",
            label="AI Gate",
            status="info",
            summary="AI Gate status unavailable.",
            href="/ai-gate",
        ))

    try:
        finding_row = await conn.fetchrow("""
            SELECT COUNT(*) AS active_findings
            FROM findings
            WHERE status = 'active'
              AND (source = 'model_intake' OR tool = 'model_intake')
        """)
        trust_row = await conn.fetchrow("""
            WITH latest AS (
                SELECT DISTINCT ON (COALESCE(target_id::text, target_url))
                    id, target_url, completed_at,
                    COALESCE(result #>> '{model_intake,summary,signature_verification_status}', '') AS signature_status,
                    COALESCE(result #>> '{model_intake,summary,signature_verified}', 'false') AS signature_verified
                FROM scans
                WHERE run_kind = 'model_intake' AND status = 'completed'
                ORDER BY COALESCE(target_id::text, target_url), completed_at DESC NULLS LAST, created_at DESC
            )
            SELECT COUNT(*) AS untrusted_latest
            FROM latest
            WHERE signature_status <> 'verified' OR signature_verified <> 'true'
        """)
        active_findings = int(_record_map(finding_row).get("active_findings") or 0)
        untrusted = int(_record_map(trust_row).get("untrusted_latest") or 0)
        if active_findings:
            status = "critical"
            summary = f"{active_findings} active Model Intake finding(s) need review."
        elif untrusted:
            status = "warning"
            summary = f"{untrusted} latest model artifact scan(s) lack trusted signatures."
        else:
            status = "ok"
            summary = "No active Model Intake blockers detected."
        items.append(_dashboard_product_status_item(
            item_id="model_intake",
            label="Model Intake",
            status=status,
            summary=summary,
            href="/model-intake?remediate=trust" if active_findings or untrusted else "/model-intake",
            primary_count=active_findings,
            primary_label="findings",
            secondary_count=untrusted,
            secondary_label="untrusted",
            actions=[
                {"label": "Fix trust", "href": "/model-intake?remediate=trust", "variant": "primary"},
                {"label": "Model findings", "href": "/findings?source_type=model_intake&status=active", "variant": "secondary"},
            ],
        ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="model_intake",
            label="Model Intake",
            status="info",
            summary="Model Intake status unavailable.",
            href="/model-intake",
        ))

    try:
        row = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS high
            FROM findings
        """)
        counts = _record_map(row)
        critical = int(counts.get("critical") or 0)
        high = int(counts.get("high") or 0)
        blockers = critical + high
        if critical:
            status = "critical"
            href = "/findings?status=active&severity=critical"
            summary = f"{critical} critical active finding(s) can block deployment."
        elif high:
            status = "warning"
            href = "/findings?status=active&severity=high"
            summary = f"{high} high active finding(s) may block deployment."
        else:
            status = "ok"
            href = "/settings/policy-profiles"
            summary = "No active high/critical deployment blockers detected."
        items.append(_dashboard_product_status_item(
            item_id="deployment",
            label="Deployment Gates",
            status=status,
            summary=summary,
            href=href,
            primary_count=critical,
            primary_label="critical",
            secondary_count=high,
            secondary_label="high",
            actions=[
                {"label": "Blockers", "href": href, "variant": "primary"},
                {"label": "Policies", "href": "/settings/policy-profiles", "variant": "secondary"},
            ],
            metadata={"blockers": blockers},
        ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="deployment",
            label="Deployment Gates",
            status="info",
            summary="Deployment gate status unavailable.",
            href="/settings/policy-profiles",
        ))

    snapshot = worker_snapshot if worker_snapshot is not None else _worker_freshness_snapshot()
    try:
        if snapshot.get("available"):
            stale = int(snapshot.get("stale_count") or 0)
            pending = int(snapshot.get("pending_count") or 0)
            total = int(snapshot.get("running") or snapshot.get("fleet_size") or snapshot.get("total") or 0)
            if stale:
                status = "critical"
                summary = f"{stale} stale worker(s) can invalidate benchmarks and fail-closed scans."
            elif pending:
                status = "warning"
                summary = f"{pending} pending worker(s) are not yet build-current."
            elif total:
                status = "ok"
                summary = f"{total} worker(s) are build-current."
            else:
                status = "info"
                summary = "No workers are currently reporting."
            items.append(_dashboard_product_status_item(
                item_id="workers",
                label="Workers",
                status=status,
                summary=summary,
                href="/",
                primary_count=stale,
                primary_label="stale",
                secondary_count=pending,
                secondary_label="pending",
                actions=[
                    {"label": "Worker controls", "href": "/", "variant": "primary"},
                    {"label": "Pending scans", "href": "/scans?status=pending", "variant": "secondary"},
                ],
                metadata={
                    "stale_workers": snapshot.get("stale_names") or [],
                    "pending_workers": snapshot.get("pending_names") or [],
                    "total": total,
                },
            ))
        else:
            items.append(_dashboard_product_status_item(
                item_id="workers",
                label="Workers",
                status="info",
                summary="Worker freshness is unavailable.",
                href="/",
            ))
    except Exception:
        items.append(_dashboard_product_status_item(
            item_id="workers",
            label="Workers",
            status="info",
            summary="Worker freshness is unavailable.",
            href="/",
        ))

    order = ["dast", "asm", "ai_gate", "model_intake", "exceptions", "deployment", "workers"]
    by_id = {str(item.get("id")): item for item in items}
    return [by_id[item_id] for item_id in order if item_id in by_id]


async def _build_dashboard_action_center(conn, *, worker_snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Server-derived operator action feed for the dashboard.

    Keep this best-effort: dashboard availability must not depend on every
    optional product area table having data, but when data exists the UI should
    receive clear action items instead of re-inferring state client-side.
    """
    items: list[dict[str, Any]] = []

    snapshot = worker_snapshot if worker_snapshot is not None else _worker_freshness_snapshot()
    if snapshot.get("available"):
        stale = int(snapshot.get("stale_count") or 0)
        pending = int(snapshot.get("pending_count") or 0)
        if stale or pending:
            items.append(_action_center_item(
                item_id="worker-build-freshness",
                priority="high" if stale else "medium",
                category="Workers",
                title="Worker build freshness needs attention",
                detail=(
                    f"{stale} stale and {pending} pending worker(s). "
                    "Restart or rescale workers before benchmark or fail-closed scans."
                ),
                href="/",
                action_label="Review workers",
                actions=[
                    {"label": "Adjust workers", "href": "/", "variant": "primary"},
                    {"label": "Queue state", "href": "/scans?status=pending", "variant": "secondary"},
                ],
                count=stale + pending,
                metadata={
                    "stale_workers": snapshot.get("stale_names") or [],
                    "pending_workers": snapshot.get("pending_names") or [],
                },
            ))

    try:
        blockers = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE severity = 'high') AS high
            FROM findings
            WHERE status = 'active' AND severity IN ('critical', 'high')
              AND COALESCE(source, '') <> 'device'
        """)
        blocker_map = _record_map(blockers)
        critical = int(blocker_map.get("critical") or 0)
        high = int(blocker_map.get("high") or 0)
        if critical or high:
            priority = "critical" if critical else "high"
            href = "/findings?status=active&severity=critical" if critical else "/findings?status=active&severity=high"
            items.append(_action_center_item(
                item_id="deploy-gate-blockers",
                priority=priority,
                category="Deployment gate",
                title="Active findings can block deployment",
                detail=f"{critical} critical and {high} high active finding(s) are still unresolved.",
                href=href,
                action_label="Review findings",
                actions=[
                    {"label": "Review blockers", "href": href, "variant": "primary"},
                    {"label": "Policy profiles", "href": "/settings/policy-profiles", "variant": "secondary"},
                ],
                count=critical + high,
            ))
    except Exception:
        pass

    try:
        failed_scans = await conn.fetch("""
            SELECT id, target_url, error_message, created_at
            FROM scans
            WHERE status = 'failed'
              AND (scan_role IS NULL OR scan_role <> 'shard')
              AND device_target_id IS NULL
              AND COALESCE(scan_role, '') <> 'device_web_origin'
              AND COALESCE(run_kind, '') NOT IN ('device_posture','device_probe','device_web_dast')
            ORDER BY created_at DESC
            LIMIT 5
        """)
        if failed_scans:
            samples = []
            for row in failed_scans[:3]:
                scan = row_to_dict(row)
                samples.append({
                    "label": scan.get("target_url") or scan.get("id"),
                    "detail": scan.get("error_message") or "Scan failed before producing a clean result.",
                    "href": f"/scans/{scan.get('id')}",
                })
            items.append(_action_center_item(
                item_id="recent-failed-scans",
                priority="high",
                category="Scans",
                title="Recent scans failed",
                detail="Open failed scans to review partial results, logs, and retry readiness.",
                href="/scans?status=failed",
                action_label="Review failures",
                actions=[
                    {"label": "Review failures", "href": "/scans?status=failed", "variant": "primary"},
                    {"label": "Latest failed scan", "href": samples[0]["href"] if samples else "/scans?status=failed", "variant": "secondary"},
                ],
                count=len(failed_scans),
                samples=samples,
            ))
    except Exception:
        pass

    try:
        schedule_rows = await conn.fetch("""
            SELECT s.*, t.url AS target_url, t.name AS target_name
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE s.is_active = true
              AND COALESCE(s.schedule_kind, 'normal_scan') = 'normal_scan'
            ORDER BY s.updated_at DESC
            LIMIT 200
        """)
        schedules = [row_to_dict(row) for row in schedule_rows]
        health_map = await _schedule_health_map_for_schedules(conn, schedules)
        unhealthy = []
        for schedule in schedules:
            health = health_map.get(str(schedule.get("id")))
            if health:
                unhealthy.append({**schedule, "schedule_health": health})
        if unhealthy:
            unhealthy.sort(key=lambda item: str(item.get("schedule_health", {}).get("latest_failed_at") or ""), reverse=True)
            samples = []
            for schedule in unhealthy[:3]:
                health = schedule.get("schedule_health") or {}
                scan_id = health.get("latest_failed_scan_id")
                scan_type = schedule.get("scan_type") or "scan"
                detail = (
                    f"{scan_type}: {health.get('recent_failed_count')} recent failure(s); "
                    f"{health.get('latest_error')}"
                )
                samples.append({
                    "label": schedule.get("target_url") or schedule.get("id"),
                    "detail": detail,
                    "href": f"/scans/{scan_id}" if scan_id else "/schedules?health=attention",
                })
            latest_scan_id = (unhealthy[0].get("schedule_health") or {}).get("latest_failed_scan_id")
            items.append(_action_center_item(
                item_id="schedule-health-attention",
                priority="high",
                category="Schedules",
                title="Recurring schedules are failing",
                detail=(
                    f"{len(unhealthy)} active schedule(s) have recent repeated failures or timeout signals. "
                    "Pause them or edit the schedule budget before the next run."
                ),
                href="/schedules?health=attention",
                action_label="Review schedules",
                actions=[
                    {"label": "Review schedules", "href": "/schedules?health=attention", "variant": "primary"},
                    {"label": "Latest failed scan", "href": f"/scans/{latest_scan_id}" if latest_scan_id else "/scans?status=failed", "variant": "secondary"},
                ],
                count=len(unhealthy),
                samples=samples,
                metadata={
                    "lookback_days": SCHEDULE_HEALTH_LOOKBACK_DAYS,
                    "schedule_ids": [str(schedule.get("id")) for schedule in unhealthy[:10]],
                },
            ))
    except Exception:
        pass

    try:
        asm_state = await conn.fetchrow("""
            WITH per_target AS (
                SELECT
                    t.id,
                    COUNT(te.id) FILTER (WHERE COALESCE(te.test_status, 'untested') <> 'gone') AS total,
                    COUNT(te.id) FILTER (
                        WHERE COALESCE(te.test_status, 'untested') IN ('untested', 'stale', 'partial')
                           OR COALESCE(te.last_attempt_status, '') IN ('partial', 'partial_timeout', 'auth_missing')
                    ) AS needs_work
                FROM targets t
                LEFT JOIN target_endpoints te ON te.target_id = t.id
                WHERE t.is_active = true AND t.asm_enabled = true
                GROUP BY t.id
            )
            SELECT
                COUNT(*) AS enabled_targets,
                COUNT(*) FILTER (WHERE total = 0) AS no_inventory_targets,
                COUNT(*) FILTER (WHERE needs_work > 0) AS targets_with_gaps,
                COALESCE(SUM(needs_work), 0) AS endpoints_needing_work,
                MIN(id::text) FILTER (WHERE total = 0 OR needs_work > 0) AS sample_target_id
            FROM per_target
        """)
        asm_map = _record_map(asm_state)
        enabled_targets = int(asm_map.get("enabled_targets") or 0)
        no_inventory = int(asm_map.get("no_inventory_targets") or 0)
        targets_with_gaps = int(asm_map.get("targets_with_gaps") or 0)
        endpoints_needing_work = int(asm_map.get("endpoints_needing_work") or 0)
        if enabled_targets and (no_inventory or targets_with_gaps):
            sample_target_id = str(asm_map.get("sample_target_id") or "")
            asm_href = f"/asm?target_id={sample_target_id}" if sample_target_id else "/asm"
            items.append(_action_center_item(
                item_id="asm-coverage-gaps",
                priority="medium",
                category="ASM",
                title="ASM coverage still has work queued",
                detail=(
                    f"{no_inventory} target(s) need inventory and {targets_with_gaps} target(s) "
                    f"have {endpoints_needing_work} endpoint(s) untested, stale, or partial."
                ),
                href=asm_href,
                action_label="Improve coverage",
                actions=[
                    {"label": "Improve coverage", "href": asm_href, "variant": "primary"},
                    {"label": "All ASM targets", "href": "/asm", "variant": "secondary"},
                ],
                count=no_inventory + targets_with_gaps,
            ))
    except Exception:
        pass

    try:
        auth_blocked_rows = await conn.fetch("""
            SELECT t.id AS target_id, t.url AS target_url,
                   COUNT(te.id) AS blocked_endpoint_count
            FROM targets t
            JOIN target_endpoints te ON te.target_id = t.id
            WHERE t.is_active = true
              AND t.asm_enabled = true
              AND COALESCE(te.last_attempt_status, '') IN ('auth_missing', 'auth_failed')
            GROUP BY t.id, t.url
            ORDER BY COUNT(te.id) DESC, t.url ASC
            LIMIT 5
        """)
        if auth_blocked_rows:
            samples = []
            total_blocked = sum(int(row_to_dict(row).get("blocked_endpoint_count") or 0) for row in auth_blocked_rows)
            for row in auth_blocked_rows[:3]:
                target = row_to_dict(row)
                blocked = int(target.get("blocked_endpoint_count") or 0)
                target_id = str(target.get("target_id") or "")
                samples.append({
                    "label": target.get("target_url") or target_id,
                    "detail": f"{blocked} endpoint(s) need credentials before replay.",
                    "href": f"/asm?target_id={target_id}" if target_id else "/asm",
                })
            first_target_id = str(row_to_dict(auth_blocked_rows[0]).get("target_id") or "")
            target_href = f"/asm?target_id={first_target_id}" if first_target_id else "/asm"
            schedule_href = f"/schedules?create=true&target_id={first_target_id}" if first_target_id else "/schedules?create=true"
            items.append(_action_center_item(
                item_id="asm-auth-blockers",
                priority="high",
                category="ASM",
                title="ASM endpoint replay is blocked by missing credentials",
                detail=(
                    f"{len(auth_blocked_rows)} target(s) have endpoint attempts blocked by missing or failed auth. "
                    "Open the target ASM timeline before adding credentials or scheduling a credentialed wave."
                ),
                href=target_href,
                action_label="Open ASM timeline",
                actions=[
                    {"label": "Open ASM timeline", "href": target_href, "variant": "primary"},
                    {"label": "Create ASM schedule", "href": schedule_href, "variant": "secondary"},
                ],
                count=total_blocked,
                samples=samples,
                metadata={
                    "blocked_target_count": len(auth_blocked_rows),
                    "blocked_endpoint_count": total_blocked,
                    "blocked_statuses": ["auth_missing", "auth_failed"],
                },
            ))
    except Exception:
        pass

    try:
        second_user_blockers = await conn.fetch("""
            SELECT ca.id, ca.target_id, ca.command, ca.action_name, ca.blocked_by,
                   ca.created_at, t.url AS target_url
            FROM campaign_actions ca
            LEFT JOIN targets t ON t.id = ca.target_id
            WHERE ca.status IN ('blocked', 'approval_required', 'planned', 'partial')
              AND ca.blocked_by ?| ARRAY[
                  'missing_second_user_auth',
                  'second_user_auth',
                  'second_user_credentials',
                  'second_user_auth_context'
              ]
            ORDER BY ca.created_at DESC
            LIMIT 5
        """)
        if second_user_blockers:
            samples = []
            for row in second_user_blockers[:3]:
                action = row_to_dict(row)
                target_id = str(action.get("target_id") or "")
                samples.append({
                    "label": action.get("target_url") or action.get("action_name") or action.get("command") or action.get("id"),
                    "detail": "Second-user credentials are required before this authz/BOLA action can run.",
                    "href": f"/asm?target_id={target_id}" if target_id else "/settings/arsenal",
                })
            first = row_to_dict(second_user_blockers[0])
            first_target_id = str(first.get("target_id") or "")
            target_href = f"/asm?target_id={first_target_id}" if first_target_id else "/settings/arsenal"
            items.append(_action_center_item(
                item_id="asm-second-user-blockers",
                priority="high",
                category="ASM",
                title="BOLA/authz work is blocked by missing second-user context",
                detail=(
                    f"{len(second_user_blockers)} campaign action(s) need second-user auth before "
                    "cross-principal replay can proceed."
                ),
                href=target_href,
                action_label="Open blocker",
                actions=[
                    {"label": "Open blocker", "href": target_href, "variant": "primary"},
                    {"label": "Campaign actions", "href": "/settings/arsenal", "variant": "secondary"},
                ],
                count=len(second_user_blockers),
                samples=samples,
                metadata={
                    "blocked_action_count": len(second_user_blockers),
                    "blocked_reasons": [
                        "missing_second_user_auth",
                        "second_user_auth",
                        "second_user_credentials",
                        "second_user_auth_context",
                    ],
                },
            ))
    except Exception:
        pass

    try:
        next_asm_schedule = await conn.fetchrow("""
            SELECT s.id, s.next_run_at, t.url AS target_url
            FROM schedules s
            JOIN targets t ON t.id = s.target_id
            WHERE s.is_active = true
              AND (
                COALESCE(s.schedule_kind, 'normal_scan') = 'asm_improve'
                OR COALESCE(s.scan_options->>'kind', '') = 'asm_improve'
              )
            ORDER BY s.next_run_at NULLS LAST, s.created_at DESC
            LIMIT 1
        """)
        if next_asm_schedule:
            row = row_to_dict(next_asm_schedule)
            detail = f"Next ASM wave for {row.get('target_url') or 'target'}"
            if row.get("next_run_at"):
                detail += f" at {row['next_run_at']}"
            items.append(_action_center_item(
                item_id="next-asm-schedule",
                priority="info",
                category="ASM schedule",
                title="Next scheduled ASM coverage wave",
                detail=detail,
                href="/schedules",
                action_label="View schedules",
                actions=[
                    {"label": "View schedules", "href": "/schedules", "variant": "primary"},
                    {"label": "Create schedule", "href": "/schedules?create=true", "variant": "secondary"},
                ],
                count=1,
            ))
    except Exception:
        pass

    try:
        model_rows = await conn.fetch("""
            WITH latest AS (
                SELECT DISTINCT ON (COALESCE(target_id::text, target_url))
                    id, target_url, completed_at,
                    COALESCE(result #>> '{model_intake,summary,signature_verification_status}', '') AS signature_status,
                    COALESCE(result #>> '{model_intake,summary,signature_verified}', 'false') AS signature_verified
                FROM scans
                WHERE run_kind = 'model_intake' AND status = 'completed'
                ORDER BY COALESCE(target_id::text, target_url), completed_at DESC NULLS LAST, created_at DESC
            )
            SELECT * FROM latest
            WHERE signature_status <> 'verified' OR signature_verified <> 'true'
            ORDER BY completed_at DESC NULLS LAST
            LIMIT 5
        """)
        if model_rows:
            samples = []
            for row in model_rows[:3]:
                scan = row_to_dict(row)
                samples.append({
                    "label": scan.get("target_url") or scan.get("id"),
                    "detail": f"signature status: {scan.get('signature_status') or 'unknown'}",
                    "href": f"/scans/{scan.get('id')}",
                })
            items.append(_action_center_item(
                item_id="model-intake-untrusted-signatures",
                priority="high",
                category="Model Intake",
                title="Model artifacts lack trusted signatures",
                detail="Latest model-intake scans include artifacts that are not verified against an operator trust root.",
                href="/model-intake",
                action_label="Review intake",
                actions=[
                    {"label": "Fix model trust", "href": "/model-intake?remediate=trust", "variant": "primary"},
                    {"label": "Latest scan", "href": samples[0]["href"] if samples else "/model-intake", "variant": "secondary"},
                ],
                count=len(model_rows),
                samples=samples,
            ))
    except Exception:
        pass

    try:
        ai_rows = await conn.fetch("""
            SELECT id, name, target_type, endpoint_url, production_mode, metadata_json
            FROM ai_targets
            WHERE is_active = true
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT 100
        """)
        missing_targets: list[dict[str, Any]] = []
        for row in ai_rows:
            target = row_to_dict(row)
            metadata = _decode_json_value(target.get("metadata_json")) or {}
            if not isinstance(metadata, dict):
                metadata = {}
            enforce = bool(metadata.get("enforce_ai_control_baseline"))
            risk = str(metadata.get("risk_tier") or "").lower()
            if not (target.get("production_mode") or enforce or risk in {"high", "critical"}):
                continue
            missing = _missing_ai_control_labels(target)
            if missing:
                missing_targets.append({
                    "target": target,
                    "missing": missing,
                })
        if missing_targets:
            samples = []
            for item in missing_targets[:3]:
                target = item["target"]
                samples.append({
                    "label": target.get("name") or target.get("endpoint_url") or target.get("id"),
                    "detail": ", ".join(item["missing"][:3]),
                    "href": "/ai-gate?remediate=controls",
                })
            items.append(_action_center_item(
                item_id="ai-control-baseline-gaps",
                priority="medium",
                category="AI Gate",
                title="AI targets are missing control evidence",
                detail="Production, high-risk, or baseline-enforced AI targets are missing required governance/control metadata.",
                href="/ai-gate?remediate=controls",
                action_label="Review AI targets",
                actions=[
                    {"label": "Control gaps", "href": "/ai-gate?remediate=controls", "variant": "primary"},
                    {"label": "AI findings", "href": "/findings?source_type=ai&status=active", "variant": "secondary"},
                ],
                count=len(missing_targets),
                samples=samples,
            ))
    except Exception:
        pass

    try:
        refuter = await _load_refuter_work_summary(conn, limit=5, finding_window=50)
        refuter_summary = refuter.get("summary") if isinstance(refuter.get("summary"), dict) else {}
        unreviewed = int(refuter_summary.get("unreviewed_count") or 0)
        integrity = int(refuter_summary.get("integrity_signal_count") or 0)
        if unreviewed or integrity:
            detail_parts = []
            if unreviewed:
                detail_parts.append(f"{unreviewed} weak or suspected-proof finding(s) awaiting a refuter review")
            if integrity:
                detail_parts.append(f"{integrity} integrity signal(s) to verify")
            integrity_samples = [
                {
                    "trigger_type": sig.get("trigger_type"),
                    "target_id": sig.get("target_id"),
                    "target_url": sig.get("target_url"),
                    "latest_finding_count": sig.get("latest_finding_count"),
                    "baseline_median": sig.get("baseline_median"),
                    "benchmark": sig.get("benchmark"),
                    "latest_expected_recall": sig.get("latest_expected_recall"),
                    "baseline_expected_recall_median": sig.get("baseline_expected_recall_median"),
                }
                for sig in (refuter.get("integrity_signals") or [])[:3]
            ]
            items.append(_action_center_item(
                item_id="refuter-review-backlog",
                priority="medium",
                category="Refuter",
                title="Weak or spiking claims need a refuter review",
                detail=(
                    "; ".join(detail_parts)
                    + ". Refuter reviews record signal only and never change findings or proof state."
                ),
                href="/settings/arsenal",
                action_label="Open refuter reviews",
                actions=[{"label": "Open refuter reviews", "href": "/settings/arsenal", "variant": "primary"}],
                count=unreviewed + integrity,
                samples=integrity_samples,
                metadata={
                    "unreviewed_candidate_count": unreviewed,
                    "integrity_signal_count": integrity,
                },
            ))
    except Exception:
        pass

    items.sort(key=lambda item: (
        ACTION_CENTER_PRIORITY_ORDER.get(str(item.get("priority")), 99),
        str(item.get("category") or ""),
        str(item.get("title") or ""),
    ))
    return items[:12]
ACTION_CENTER_PRIORITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _action_center_item(
    *,
    item_id: str,
    priority: str,
    category: str,
    title: str,
    detail: str,
    href: str | None = None,
    action_label: str | None = None,
    actions: list[dict[str, Any]] | None = None,
    count: int | None = None,
    samples: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_actions = actions or []
    if not normalized_actions and href:
        normalized_actions = [{
            "label": action_label or "Open",
            "href": href,
            "variant": "primary",
        }]
    return {
        "id": item_id,
        "priority": priority if priority in ACTION_CENTER_PRIORITY_ORDER else "info",
        "category": category,
        "title": title,
        "detail": detail,
        "href": href,
        "action_label": action_label,
        "actions": normalized_actions,
        "count": count,
        "samples": samples or [],
        "metadata": metadata or {},
    }


def _dashboard_product_status_item(
    *,
    item_id: str,
    label: str,
    status: str,
    summary: str,
    href: str,
    primary_count: int | None = None,
    primary_label: str | None = None,
    secondary_count: int | None = None,
    secondary_label: str | None = None,
    actions: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "label": label,
        "status": status if status in {"critical", "warning", "ok", "info"} else "info",
        "summary": summary,
        "href": href,
        "primary_count": primary_count,
        "primary_label": primary_label,
        "secondary_count": secondary_count,
        "secondary_label": secondary_label,
        "actions": actions or [{"label": "Open", "href": href, "variant": "primary"}],
        "metadata": metadata or {},
    }


def _missing_ai_control_labels(target: dict[str, Any]) -> list[str]:
    metadata = _decode_json_value(target.get("metadata_json")) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    target_type = str(target.get("target_type") or "api_chat")
    missing: list[str] = []
    for requirement in AI_CONTROL_REQUIREMENTS:
        if not _ai_requirement_applies(requirement, target_type):
            continue
        keys = requirement.get("keys") or ()
        if not _metadata_has_any(metadata, tuple(str(k) for k in keys)):
            missing.append(str(requirement.get("label") or requirement.get("id") or "control"))
    return missing
def _metadata_has_any(metadata: dict[str, Any], keys: tuple[str, ...] | list[str]) -> bool:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def _ai_requirement_applies(requirement: dict[str, Any], target_type: str) -> bool:
    applies_to = str(requirement.get("applies_to") or "all")
    if applies_to == "all":
        return True
    if applies_to == "rag":
        return target_type == "rag"
    if applies_to == "agent":
        return target_type in {"agent_trace", "mcp_trace"}
    return applies_to == target_type


def _worker_freshness_snapshot(*a: Any, **k: Any) -> Any:
    return _dep("worker_freshness_snapshot")(*a, **k)


async def _load_refuter_work_summary(*a: Any, **k: Any) -> Any:
    """Injected: importing it from arsenal_routes made operations cyclic."""
    return await _dep("load_refuter_work_summary")(*a, **k)

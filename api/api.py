#!/usr/bin/env python3
"""
Shaker Scan API - Open Source Edition
FastAPI server with PostgreSQL persistence and Redis queue.
"""

import asyncio
import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import asyncpg
import redis
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
HEARTBEAT_TIMEOUT_MINUTES = 5  # Mark scan stale if no heartbeat for this long
STALE_CHECK_INTERVAL_SECONDS = 60  # How often to check for stale scans

# Maximum allowed duration per scan type (minutes) - safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 180,
    'aggressive': 480,
    'smart': 360,
}


def row_to_dict(row) -> dict:
    """Convert asyncpg Record to JSON-serializable dict."""
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def get_redis():
    """Get Redis connection."""
    return redis.from_url(REDIS_URL, decode_responses=True)


async def cleanup_stale_scans(pool: asyncpg.Pool):
    """Check for and mark stale scans as failed.

    A scan is considered stale if:
    1. No heartbeat received for HEARTBEAT_TIMEOUT_MINUTES, OR
    2. Running longer than MAX_SCAN_DURATION for its scan type
    """
    r = get_redis()
    now = datetime.utcnow()

    async with pool.acquire() as conn:
        # Get all running scans
        running_scans = await conn.fetch("""
            SELECT id, scan_type, started_at
            FROM scans
            WHERE status = 'running' AND started_at IS NOT NULL
        """)

        for scan in running_scans:
            scan_id = str(scan['id'])
            scan_type = scan['scan_type'] or 'standard'
            started_at = scan['started_at']

            is_stale = False
            reason = ""

            # Check 1: Heartbeat timeout
            # Look for job with this scan_id
            job_keys = r.keys("job:*")
            heartbeat_found = False

            for key in job_keys:
                job_data = r.hgetall(key)
                if job_data.get('scan_id') == scan_id or key.endswith(scan_id):
                    heartbeat_str = job_data.get('heartbeat')
                    if heartbeat_str:
                        try:
                            heartbeat_time = datetime.fromisoformat(heartbeat_str.replace('Z', '+00:00').replace('+00:00', ''))
                            heartbeat_age = (now - heartbeat_time).total_seconds() / 60
                            heartbeat_found = True

                            if heartbeat_age > HEARTBEAT_TIMEOUT_MINUTES:
                                is_stale = True
                                reason = f"No heartbeat for {heartbeat_age:.1f} minutes"
                        except (ValueError, TypeError):
                            pass
                    break

            # If no heartbeat found at all and scan started > 5 min ago, it's stale
            if not heartbeat_found:
                scan_age = (now - started_at.replace(tzinfo=None)).total_seconds() / 60
                if scan_age > HEARTBEAT_TIMEOUT_MINUTES:
                    is_stale = True
                    reason = f"No heartbeat found, scan started {scan_age:.1f} minutes ago"

            # Check 2: Max duration exceeded (safety net)
            if not is_stale and started_at:
                max_duration = MAX_SCAN_DURATION.get(scan_type, 120)
                scan_duration = (now - started_at.replace(tzinfo=None)).total_seconds() / 60

                if scan_duration > max_duration:
                    is_stale = True
                    reason = f"Exceeded max duration ({scan_duration:.0f} min > {max_duration} min for {scan_type} scan)"

            # Mark stale scan as failed
            if is_stale:
                print(f"[cleanup] Marking scan {scan_id[:8]} as failed: {reason}", flush=True)
                await conn.execute("""
                    UPDATE scans
                    SET status = 'failed',
                        error_message = $1,
                        completed_at = $2
                    WHERE id = $3
                """, f"Scan terminated: {reason}", now, scan['id'])


async def stale_scan_checker(pool: asyncpg.Pool):
    """Background task to periodically check for stale scans."""
    print("[cleanup] Stale scan checker started", flush=True)
    while True:
        try:
            await asyncio.sleep(STALE_CHECK_INTERVAL_SECONDS)
            await cleanup_stale_scans(pool)
        except asyncio.CancelledError:
            print("[cleanup] Stale scan checker stopped", flush=True)
            break
        except Exception as e:
            print(f"[cleanup] Error checking stale scans: {e}", flush=True)


# Database connection pool
db_pool: Optional[asyncpg.Pool] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage database connection pool lifecycle and background tasks."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)

    # Start background stale scan checker
    cleanup_task = asyncio.create_task(stale_scan_checker(db_pool))

    yield

    # Stop background task
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    await db_pool.close()


app = FastAPI(
    title="Shaker Scan API",
    description="Open Source Dynamic Application Security Testing Scanner",
    version="1.0.0",
    lifespan=lifespan
)

# CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PYDANTIC MODELS
# ============================================================

class ScanOptions(BaseModel):
    # Scan type preset (mutually exclusive)
    # quick: DNS, TLS, headers (1-2 min)
    # standard: + tech detection, basic nuclei (5-10 min)
    # deep: + full nuclei, port scan, JS scanning (30-60 min)
    # full: + active XSS/SQLi, all security tests (1-2 hours)
    # aggressive: + aggressive exploit level, extended ports (2+ hours)
    scan_type: Optional[str] = None  # quick, standard, deep, full, aggressive, smart

    # Legacy fields (for backwards compatibility)
    quick: bool = False
    public: bool = False
    active: bool = False
    xss: bool = False
    sqli: bool = False
    thorough: bool = False

    # Additional options
    nuclei: bool = False
    enhanced_dns: bool = False
    subfinder: bool = False
    js_dependency_scanning: bool = False
    js_secret_scanning: bool = False
    grpc_discovery: bool = False
    json_link_following: bool = False
    options_method_discovery: bool = False

    # AI options
    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    model: Optional[str] = None
    ai_mask_host: Optional[str] = None

    # Authentication options (for authenticated scanning)
    # Session-based auth
    auth_cookies: Optional[str] = None           # "session=abc; token=xyz"
    auth_header: Optional[str] = None            # "Bearer eyJ..." or "Basic xxx"
    auth_headers_json: Optional[str] = None      # '{"X-API-Key": "abc", "X-Custom": "val"}'

    # Form-based login (scanner auto-detects login forms)
    login_url: Optional[str] = None              # Login page URL (auto-detected if not provided)
    login_username: Optional[str] = None
    login_password: Optional[str] = None
    login_extra_fields: Optional[str] = None     # Extra form fields as JSON: '{"remember": "true"}'
    auto_auth: bool = False                      # Attempt API login with provided credentials

    # Multi-user auth for BOLA/IDOR testing
    user2_cookies: Optional[str] = None          # Second user session cookies
    user2_header: Optional[str] = None           # Second user auth header

    # Manual endpoint specification for API-only targets
    # Format: "METHOD /path params" or just "/path"
    # Examples: "POST /api/login username,password", "/api/users", "GET /api/items?id=1"
    custom_endpoints: Optional[list[str]] = None

    # Smart scan tuning options
    no_early_stop: bool = False                    # Disable early stopping in smart scan
    thorough_params: bool = False                  # Test more parameters (50x10 vs 25x5)
    oob_callback_url: Optional[str] = None         # OOB callback URL for blind SQLi

    # Safety/performance limits
    smart_bola_max_endpoints: Optional[int] = None # Max endpoints for BOLA testing (default: 30)
    dom_xss_max_files: Optional[int] = None        # Max JS files for DOM XSS (default: 20)
    sqli_extract_max: Optional[int] = None         # Max SQLi findings for extraction (default: 3)
    oob_max_findings: Optional[int] = None         # Max findings for OOB SQLi test (default: 3)
    oob_max_payloads: Optional[int] = None         # Deprecated alias for oob_max_findings


class ScanRequest(BaseModel):
    target: str
    name: Optional[str] = None
    options: ScanOptions = Field(default_factory=ScanOptions)


class BatchRequest(BaseModel):
    targets: list[str]
    options: ScanOptions = Field(default_factory=ScanOptions)


class TargetCreate(BaseModel):
    url: str
    name: Optional[str] = None
    scan_options: Optional[dict] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    scan_options: Optional[dict] = None


class FindingUpdate(BaseModel):
    status: str  # active, resolved, false_positive, accepted_risk
    notes: Optional[str] = None


# ============================================================
# HEALTH & INFO
# ============================================================

@app.get("/")
async def root():
    """API info."""
    return {
        "name": "Shaker Scan API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "scans": "/scans",
            "targets": "/targets",
            "findings": "/findings",
            "discovery": "/discovery",
            "dashboard": "/dashboard",
            "queue": "/queue/stats"
        }
    }


@app.get("/health")
async def health():
    """Health check."""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    try:
        r = get_redis()
        r.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    return {
        "status": "healthy" if db_ok and redis_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "redis": "ok" if redis_ok else "error"
    }


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/dashboard")
async def dashboard():
    """Get dashboard metrics."""
    async with db_pool.acquire() as conn:
        metrics = await conn.fetchrow("SELECT * FROM dashboard_metrics")
        recent_scans = await conn.fetch("""
            SELECT id, target_url, status, score, grade, created_at, completed_at
            FROM scans ORDER BY created_at DESC LIMIT 10
        """)
        recent_findings = await conn.fetch("""
            SELECT id, title, severity, status, tool, first_seen_at
            FROM findings WHERE status = 'active'
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

    return {
        "metrics": dict(metrics) if metrics else {},
        "recent_scans": [dict(s) for s in recent_scans],
        "recent_findings": [dict(f) for f in recent_findings]
    }


# ============================================================
# SCANS
# ============================================================

@app.post("/scans")
async def submit_scan(request: ScanRequest):
    """Submit a new scan job."""
    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    # Determine scan type
    # Priority: explicit scan_type > legacy boolean flags > default (quick)
    if request.options.scan_type:
        # Use explicit scan_type if provided
        scan_type = request.options.scan_type
        if scan_type not in ['quick', 'standard', 'deep', 'full', 'aggressive', 'smart']:
            scan_type = 'quick'  # Fallback to quick for invalid types
    elif request.options.thorough and request.options.active:
        # Legacy: thorough + active = full
        scan_type = 'full'
        request.options.scan_type = 'full'
    elif request.options.thorough:
        # Legacy: thorough = deep
        scan_type = 'deep'
        request.options.scan_type = 'deep'
    elif request.options.active:
        # Legacy: just active = standard + active tests
        scan_type = 'full'
        request.options.scan_type = 'full'
    elif request.options.quick:
        scan_type = 'quick'
        request.options.scan_type = 'quick'
    else:
        # Default to quick scan
        scan_type = 'quick'
        request.options.scan_type = 'quick'

    # Validate: public option is incompatible with active-enforced scan types
    active_enforced_types = {'smart', 'full', 'aggressive'}
    if scan_type in active_enforced_types and request.options.public:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_options",
                "message": f"'public' option is incompatible with '{scan_type}' scan type. "
                           f"{scan_type.capitalize()} scans require active testing (XSS/SQLi probes). "
                           "Use 'deep' scan type for passive-only comprehensive scanning.",
                "hint": f"Either remove 'public: true' or change scan_type to 'deep'"
            }
        )

    # Create or find target
    async with db_pool.acquire() as conn:
        # Check if target exists
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1", request.target
        )
        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain)
                VALUES ($1, $2, $3)
                RETURNING id
            """, request.target, request.name, extract_root_domain(request.target))

        # Create scan record
        await conn.execute("""
            INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
        """, uuid.UUID(scan_id), target_id, request.target, job_id,
             json.dumps(request.options.dict()), scan_type)

    # Queue the job
    job_data = {
        'job_id': job_id,
        'scan_id': scan_id,
        'target': request.target,
        'options': request.options.dict(),
        'submitted_at': datetime.utcnow().isoformat()
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))
    r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': request.target})

    return {
        'scan_id': scan_id,
        'job_id': job_id,
        'status': 'queued',
        'target': request.target,
        'scan_type': scan_type
    }


@app.post("/scans/batch")
async def submit_batch(request: BatchRequest):
    """Submit multiple scan jobs."""
    jobs = []
    for target in request.targets:
        req = ScanRequest(target=target, options=request.options)
        result = await submit_scan(req)
        jobs.append(result)

    return {
        'jobs': jobs,
        'count': len(jobs),
        'status': 'queued'
    }


@app.get("/scans")
async def list_scans(
    status: Optional[str] = None,
    target: Optional[str] = None,
    root_domain: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List scans with optional filtering."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT s.*, t.name as target_name, t.root_domain
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            WHERE 1=1
        """
        count_query = """
            SELECT COUNT(*)
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            WHERE 1=1
        """
        params = []
        count_params = []
        param_idx = 1
        count_param_idx = 1

        if status:
            query += f" AND s.status = ${param_idx}"
            count_query += f" AND s.status = ${count_param_idx}"
            params.append(status)
            count_params.append(status)
            param_idx += 1
            count_param_idx += 1

        if target:
            query += f" AND s.target_url ILIKE ${param_idx}"
            count_query += f" AND s.target_url ILIKE ${count_param_idx}"
            params.append(f"%{target}%")
            count_params.append(f"%{target}%")
            param_idx += 1
            count_param_idx += 1

        if root_domain:
            query += f" AND t.root_domain = ${param_idx}"
            count_query += f" AND t.root_domain = ${count_param_idx}"
            params.append(root_domain)
            count_params.append(root_domain)
            param_idx += 1
            count_param_idx += 1

        query += f" ORDER BY s.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *count_params)

    return {
        'scans': [dict(r) for r in rows],
        'total': total,
        'limit': limit,
        'offset': offset
    }


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT s.*, t.name as target_name
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            WHERE s.id = $1
        """, uuid.UUID(scan_id))

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings for this scan
        findings = await conn.fetch("""
            SELECT id, title, severity, cvss_score, status, tool, url
            FROM findings WHERE scan_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id))

    result = dict(scan)
    result['findings'] = [dict(f) for f in findings]
    if result.get('result') and isinstance(result['result'], str):
        result['result'] = json.loads(result['result'])
    if result.get('options') and isinstance(result['options'], str):
        result['options'] = json.loads(result['options'])
    return result


@app.get("/scans/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get full scan result JSON."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result FROM scans WHERE id = $1", uuid.UUID(scan_id)
        )
        if not scan or not scan['result']:
            raise HTTPException(status_code=404, detail="Scan result not found")
        return scan['result']


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running or pending scan."""
    r = get_redis()

    async with db_pool.acquire() as conn:
        # Check scan exists and is cancellable
        scan = await conn.fetchrow(
            "SELECT id, status, target_url FROM scans WHERE id = $1",
            uuid.UUID(scan_id)
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan['status'] not in ('pending', 'running', 'queued'):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel scan with status '{scan['status']}'"
            )

        # Update database
        await conn.execute("""
            UPDATE scans
            SET status = 'cancelled',
                error_message = 'Cancelled by user',
                completed_at = NOW()
            WHERE id = $1
        """, uuid.UUID(scan_id))

    # Signal worker to stop via Redis (set cancel flag)
    # Workers should check this flag periodically
    r.set(f"scan:{scan_id}:cancel", "1", ex=3600)  # Expires in 1 hour

    # Also try to find and update the job in Redis
    for key in r.keys("job:*"):
        job_data = r.hgetall(key)
        if job_data.get('scan_id') == scan_id:
            r.hset(key, 'status', 'cancelled')
            break

    return {
        "status": "cancelled",
        "scan_id": scan_id,
        "target": scan['target_url'],
        "message": "Scan cancelled successfully"
    }


# ============================================================
# TARGETS
# ============================================================

@app.get("/targets")
async def list_targets(
    include_inactive: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List all targets."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT t.*, fs.total_active as active_findings
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += f" AND t.is_active = true"

        query += f" ORDER BY t.updated_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM targets" + ("" if include_inactive else " WHERE is_active = true")
        )

    return {
        'targets': [dict(r) for r in rows],
        'total': total
    }


@app.get("/targets/grouped")
async def list_targets_grouped(
    include_inactive: bool = False,
    search: Optional[str] = None,
    discovery_source: Optional[str] = Query(None, pattern="^(manual|subfinder|gungnir-monitor|import)$"),
    grade: Optional[str] = Query(None, pattern="^[A-Fa-f]$"),
    has_findings: Optional[bool] = None,
    sort_by: Optional[str] = Query("root_domain", pattern="^(root_domain|last_scanned_at|active_findings_count|last_score|created_at)$"),
    sort_order: Optional[str] = Query("asc", pattern="^(asc|desc)$")
):
    """List all targets grouped by root domain for hierarchical display."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT
                t.id, t.url, t.name, t.root_domain, t.is_root,
                t.discovery_source, t.is_active,
                t.last_scanned_at, t.last_score, t.last_grade,
                t.total_scans, t.active_findings_count,
                t.created_at
            FROM targets t
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += " AND t.is_active = true"

        if search:
            query += f" AND (t.url ILIKE '%' || ${param_idx} || '%' OR t.name ILIKE '%' || ${param_idx} || '%' OR t.root_domain ILIKE '%' || ${param_idx} || '%')"
            params.append(search)
            param_idx += 1

        if discovery_source:
            query += f" AND t.discovery_source = ${param_idx}"
            params.append(discovery_source)
            param_idx += 1

        if grade:
            query += f" AND UPPER(t.last_grade) = UPPER(${param_idx})"
            params.append(grade)
            param_idx += 1

        if has_findings is not None:
            if has_findings:
                query += " AND t.active_findings_count > 0"
            else:
                query += " AND t.active_findings_count = 0"

        query += " ORDER BY t.root_domain, t.is_root DESC, t.url"

        rows = await conn.fetch(query, *params)

    # Group by root_domain
    grouped = {}
    for row in rows:
        rd = row['root_domain'] or 'unknown'
        if rd not in grouped:
            grouped[rd] = {
                'root_domain': rd,
                'root_target': None,
                'subdomains': []
            }

        target_data = row_to_dict(row)
        if row['is_root']:
            grouped[rd]['root_target'] = target_data
        else:
            grouped[rd]['subdomains'].append(target_data)

    # Convert to list and add summary stats
    result = []
    for rd, data in grouped.items():
        data['subdomain_count'] = len(data['subdomains'])
        data['total_count'] = data['subdomain_count'] + (1 if data['root_target'] else 0)
        # Add aggregate stats for sorting
        root_findings = data['root_target']['active_findings_count'] if data['root_target'] else 0
        subdomain_findings = sum(s['active_findings_count'] for s in data['subdomains'])
        data['total_findings'] = root_findings + subdomain_findings
        data['best_score'] = data['root_target']['last_score'] if data['root_target'] and data['root_target']['last_score'] is not None else None
        data['latest_scan'] = data['root_target']['last_scanned_at'] if data['root_target'] else None
        data['earliest_created'] = data['root_target']['created_at'] if data['root_target'] else (
            min((s['created_at'] for s in data['subdomains']), default=None)
        )
        result.append(data)

    # Sort based on sort_by and sort_order
    reverse = sort_order == 'desc'

    def sort_key(x):
        if sort_by == 'root_domain':
            return x['root_domain'].lower()
        elif sort_by == 'last_scanned_at':
            return x['latest_scan'] or ''
        elif sort_by == 'active_findings_count':
            return x['total_findings']
        elif sort_by == 'last_score':
            # None values should sort last in ascending, first in descending
            score = x['best_score']
            if score is None:
                return -1 if reverse else 101
            return score
        elif sort_by == 'created_at':
            return x['earliest_created'] or ''
        return x['root_domain'].lower()

    result.sort(key=sort_key, reverse=reverse)

    return {
        'domains': result,
        'total_root_domains': len(result),
        'total_targets': sum(d['total_count'] for d in result)
    }


@app.get("/domains")
async def list_domains():
    """List unique root domains from targets."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT root_domain
            FROM targets
            WHERE root_domain IS NOT NULL AND is_active = true
            ORDER BY root_domain
        """)

    return {
        'domains': [r['root_domain'] for r in rows]
    }


@app.post("/targets")
async def create_target(request: TargetCreate):
    """Create a new target."""
    root_domain = extract_root_domain(request.url)
    is_root = is_root_domain(request.url)

    async with db_pool.acquire() as conn:
        try:
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, is_root, scan_options)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            """, request.url, request.name, root_domain, is_root,
                 json.dumps(request.scan_options or {}))

            return {
                'id': str(target_id),
                'url': request.url,
                'root_domain': root_domain,
                'is_root': is_root,
                'status': 'created'
            }
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Target already exists")


@app.get("/targets/{target_id}")
async def get_target(target_id: str):
    """Get target details."""
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("""
            SELECT t.*, fs.*
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            WHERE t.id = $1
        """, uuid.UUID(target_id))

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Get recent scans
        scans = await conn.fetch("""
            SELECT id, status, score, grade, created_at, completed_at
            FROM scans WHERE target_id = $1
            ORDER BY created_at DESC LIMIT 10
        """, uuid.UUID(target_id))

    result = dict(target)
    result['recent_scans'] = [dict(s) for s in scans]
    return result


@app.patch("/targets/{target_id}")
async def update_target(target_id: str, request: TargetUpdate):
    """Update a target."""
    async with db_pool.acquire() as conn:
        updates = []
        params = []
        param_idx = 1

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.is_active is not None:
            updates.append(f"is_active = ${param_idx}")
            params.append(request.is_active)
            param_idx += 1

        if request.scan_options is not None:
            updates.append(f"scan_options = ${param_idx}")
            params.append(json.dumps(request.scan_options))
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(target_id))

        query = f"UPDATE targets SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        result = await conn.fetchval(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'updated'}


@app.delete("/targets/{target_id}")
async def delete_target(target_id: str):
    """Delete a target (soft delete - sets inactive)."""
    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE targets SET is_active = false, updated_at = NOW()
            WHERE id = $1
        """, uuid.UUID(target_id))

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'deleted'}


@app.post("/targets/{target_id}/scan")
async def scan_target(target_id: str, options: ScanOptions = None):
    """Start a scan for a specific target."""
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow(
            "SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

    # Merge target's default options with provided options
    stored_options = target['scan_options']
    if isinstance(stored_options, str):
        merged_options = json.loads(stored_options) if stored_options else {}
    else:
        merged_options = stored_options or {}
    if options:
        merged_options.update(options.dict(exclude_unset=True))

    request = ScanRequest(target=target['url'], options=ScanOptions(**merged_options))
    return await submit_scan(request)


# ============================================================
# FINDINGS
# ============================================================

@app.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    root_domain: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = Query(None, regex="^(severity|first_seen|last_seen|cvss)$"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List findings with filtering and sorting."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT f.*, t.url as target_url, t.name as target_name, t.root_domain
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            WHERE 1=1
        """
        count_query = """
            SELECT COUNT(*)
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            WHERE 1=1
        """
        params = []
        count_params = []
        param_idx = 1
        count_param_idx = 1

        if severity:
            query += f" AND f.severity = ${param_idx}"
            count_query += f" AND f.severity = ${count_param_idx}"
            params.append(severity)
            count_params.append(severity)
            param_idx += 1
            count_param_idx += 1

        if status:
            query += f" AND f.status = ${param_idx}"
            count_query += f" AND f.status = ${count_param_idx}"
            params.append(status)
            count_params.append(status)
            param_idx += 1
            count_param_idx += 1

        if target_id:
            query += f" AND f.target_id = ${param_idx}"
            count_query += f" AND f.target_id = ${count_param_idx}"
            params.append(uuid.UUID(target_id))
            count_params.append(uuid.UUID(target_id))
            param_idx += 1
            count_param_idx += 1

        if scan_id:
            query += f" AND f.scan_id = ${param_idx}"
            count_query += f" AND f.scan_id = ${count_param_idx}"
            params.append(uuid.UUID(scan_id))
            count_params.append(uuid.UUID(scan_id))
            param_idx += 1
            count_param_idx += 1

        if root_domain:
            query += f" AND t.root_domain = ${param_idx}"
            count_query += f" AND t.root_domain = ${count_param_idx}"
            params.append(root_domain)
            count_params.append(root_domain)
            param_idx += 1
            count_param_idx += 1

        if search:
            search_pattern = f"%{search}%"
            query += f" AND (f.title ILIKE ${param_idx} OR f.url ILIKE ${param_idx})"
            count_query += f" AND (f.title ILIKE ${count_param_idx} OR f.url ILIKE ${count_param_idx})"
            params.append(search_pattern)
            count_params.append(search_pattern)
            param_idx += 1
            count_param_idx += 1

        # Build ORDER BY clause based on sort_by parameter
        order_dir = "DESC" if sort_order == "desc" else "ASC"
        if sort_by == "first_seen":
            order_clause = f"f.first_seen_at {order_dir}"
        elif sort_by == "last_seen":
            order_clause = f"f.last_seen_at {order_dir}"
        elif sort_by == "cvss":
            order_clause = f"f.cvss_score {order_dir} NULLS LAST"
        else:
            # Default: severity (always show critical first regardless of sort_order)
            order_clause = """
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END""" + (", f.first_seen_at DESC" if sort_order == "desc" else ", f.first_seen_at ASC")

        query += f"""
            ORDER BY {order_clause}
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *count_params)

    return {
        'findings': [dict(r) for r in rows],
        'total': total,
        'limit': limit,
        'offset': offset
    }


@app.get("/findings/{finding_id:path}")
async def get_finding(finding_id: str):
    """Get finding details by ID or fingerprint."""
    async with db_pool.acquire() as conn:
        finding = None

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            finding = await conn.fetchrow("""
                SELECT f.*, t.url as target_url, t.name as target_name
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE f.id = $1
            """, finding_uuid)
        except ValueError:
            pass

        # Try full scanner ID as fingerprint (new format: "tool:hash")
        if not finding:
            finding = await conn.fetchrow("""
                SELECT f.*, t.url as target_url, t.name as target_name
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE f.fingerprint = $1
                ORDER BY f.last_seen_at DESC
                LIMIT 1
            """, finding_id)

        # Backward compat: try suffix-only for old findings stored with hash-only fingerprint
        if not finding and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            finding = await conn.fetchrow("""
                SELECT f.*, t.url as target_url, t.name as target_name
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE f.fingerprint = $1
                ORDER BY f.last_seen_at DESC
                LIMIT 1
            """, suffix)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    return dict(finding)


@app.patch("/findings/{finding_id:path}")
async def update_finding(
    finding_id: str,
    request: FindingUpdate,
    scan_id: Optional[str] = Query(None, description="Scope update to specific scan")
):
    """Update a finding status by ID or fingerprint.

    Lookup order:
    1. UUID (exact match)
    2. Full scanner ID as fingerprint (new format: "tool:hash")
    3. Suffix-only fingerprint (backward compat)
    4. Legacy computed fingerprint (pre-change findings)

    Pass scan_id to scope updates to a specific scan and prevent cross-target collisions.
    """
    async with db_pool.acquire() as conn:
        updated_id = None
        scan_uuid = None
        if scan_id:
            try:
                scan_uuid = uuid.UUID(scan_id)
            except ValueError:
                pass

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            result = await conn.fetchrow("""
                UPDATE findings
                SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
                WHERE id = $3
                RETURNING id
            """, request.status, request.notes, finding_uuid)
            if result:
                updated_id = result['id']
        except ValueError:
            pass

        # Try full scanner ID as fingerprint (new format: "tool:hash")
        if not updated_id:
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
                    WHERE fingerprint = $3 AND scan_id = $4
                    RETURNING id
                """, request.status, request.notes, finding_id, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $3
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id
                """, request.status, request.notes, finding_id)
            if result:
                updated_id = result['id']

        # Backward compat: try suffix-only for old findings
        if not updated_id and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
                    WHERE fingerprint = $3 AND scan_id = $4
                    RETURNING id
                """, request.status, request.notes, suffix, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $3
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id
                """, request.status, request.notes, suffix)
            if result:
                updated_id = result['id']

        if not updated_id:
            raise HTTPException(status_code=404, detail="Finding not found")

    return {'id': str(updated_id), 'status': request.status}


@app.post("/findings/bulk")
async def bulk_update_findings(finding_ids: list[str], status: str, notes: Optional[str] = None):
    """Bulk update finding statuses."""
    async with db_pool.acquire() as conn:
        ids = [uuid.UUID(fid) for fid in finding_ids]
        result = await conn.execute("""
            UPDATE findings
            SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
            WHERE id = ANY($3)
        """, status, notes, ids)

    return {'updated': len(finding_ids), 'status': status}


# ============================================================
# DISCOVERY (Subdomain Enumeration)
# ============================================================

@app.post("/discovery")
async def start_discovery(root_domain: str):
    """Start subdomain discovery for a domain."""
    r = get_redis()
    job_id = str(uuid.uuid4())
    discovery_id = str(uuid.uuid4())

    async with db_pool.acquire() as conn:
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
        'submitted_at': datetime.utcnow().isoformat()
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))

    return {
        'discovery_id': discovery_id,
        'job_id': job_id,
        'root_domain': root_domain,
        'status': 'queued'
    }


@app.get("/discovery")
async def list_discovery_runs(limit: int = 20):
    """List discovery runs."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT * FROM discovery_runs
            ORDER BY created_at DESC LIMIT $1
        """, limit)

    return {'discovery_runs': [dict(r) for r in rows]}


@app.get("/discovery/{discovery_id}")
async def get_discovery(discovery_id: str):
    """Get discovery run details."""
    async with db_pool.acquire() as conn:
        discovery = await conn.fetchrow(
            "SELECT * FROM discovery_runs WHERE id = $1", uuid.UUID(discovery_id)
        )
        if not discovery:
            raise HTTPException(status_code=404, detail="Discovery run not found")

    return dict(discovery)


# ============================================================
# WORKER MANAGEMENT
# ============================================================

class WorkerScaleRequest(BaseModel):
    count: int = Field(..., ge=1, le=20, description="Number of workers (1-20)")


def docker_socket_request(method: str, path: str, body: dict = None) -> tuple[int, dict | list]:
    """Send HTTP request to Docker socket API.

    Args:
        method: HTTP method (GET, POST, DELETE)
        path: API path (e.g., /containers/json)
        body: Optional JSON body for POST requests

    Returns:
        Tuple of (status_code, response_data)
    """
    import socket as sock_module
    import json as json_module

    docker_socket = "/var/run/docker.sock"
    s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
    s.settimeout(30)
    s.connect(docker_socket)

    if body:
        body_str = json_module.dumps(body)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_str)}\r\n"
            f"Connection: close\r\n"
            f"\r\n{body_str}"
        )
    else:
        request = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

    s.sendall(request.encode())

    # Read response
    response = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        response += chunk
    s.close()

    # Parse HTTP response
    response_str = response.decode('utf-8', errors='ignore')
    status_code = 0
    response_body = {}

    if '\r\n' in response_str:
        status_line = response_str.split('\r\n')[0]
        parts = status_line.split(' ')
        if len(parts) >= 2:
            status_code = int(parts[1])

    if '\r\n\r\n' in response_str:
        headers, body_part = response_str.split('\r\n\r\n', 1)
        # Handle chunked transfer encoding
        if 'Transfer-Encoding: chunked' in headers:
            # Parse chunked encoding: format is "size\r\ndata\r\nsize\r\ndata\r\n...0\r\n\r\n"
            # Assemble all chunks into complete body
            assembled = []
            remaining = body_part
            while remaining:
                # Find chunk size line
                if '\r\n' not in remaining:
                    break
                size_line, remaining = remaining.split('\r\n', 1)
                try:
                    size_str = size_line.split(';', 1)[0].strip()
                    if not size_str:
                        break
                    chunk_size = int(size_str, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    break
                # Extract chunk data
                if len(remaining) < chunk_size:
                    break
                chunk_data = remaining[:chunk_size]
                assembled.append(chunk_data)
                # Skip past chunk data and trailing \r\n
                remaining = remaining[chunk_size:]
                if remaining.startswith('\r\n'):
                    remaining = remaining[2:]
            body_part = ''.join(assembled)

        if body_part.strip():
            try:
                response_body = json_module.loads(body_part)
            except json_module.JSONDecodeError:
                response_body = {}

    return status_code, response_body


def get_compose_context(containers: list) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Infer compose project, network, and image from existing containers."""
    if not containers or not isinstance(containers, list):
        return None, None, None

    preferred_services = ("worker", "api")
    for service in preferred_services:
        for c in containers:
            labels = c.get("Labels", {}) or {}
            if labels.get("com.docker.compose.service") == service:
                project = labels.get("com.docker.compose.project")
                image = c.get("Image")
                networks = (c.get("NetworkSettings") or {}).get("Networks", {})
                network = next(iter(networks.keys()), None) if networks else None
                return project, network, image

    for c in containers:
        labels = c.get("Labels", {}) or {}
        project = labels.get("com.docker.compose.project")
        if project:
            image = c.get("Image")
            networks = (c.get("NetworkSettings") or {}).get("Networks", {})
            network = next(iter(networks.keys()), None) if networks else None
            return project, network, image

    return None, None, None


@app.get("/workers")
async def get_workers():
    """Get current worker count and status via Docker socket API."""
    import socket
    import json as json_module

    docker_socket = "/var/run/docker.sock"

    try:
        # Connect to Docker socket directly
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(docker_socket)

        # Request container list filtered by name
        request = (
            "GET /containers/json?all=true&filters=%7B%22name%22%3A%5B%22worker%22%5D%7D HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        # Parse HTTP response
        response_str = response.decode('utf-8')
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
            # Handle chunked transfer encoding
            if 'Transfer-Encoding: chunked' in headers:
                # Simple chunked parsing - get content after first chunk size
                lines = body.split('\r\n')
                body = '\r\n'.join(lines[1:]) if len(lines) > 1 else ''
                # Find JSON array
                if '[' in body:
                    body = body[body.find('['):]
                    if ']' in body:
                        body = body[:body.rfind(']')+1]
        else:
            body = response_str

        containers = json_module.loads(body) if body.strip().startswith('[') else []

        # Filter and format worker containers (only shakerscan workers)
        worker_list = []
        for c in containers:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else 'unknown'
            if 'shakerscan' in name.lower() and 'worker' in name.lower():
                state = c.get('State', 'unknown')
                worker_list.append({
                    "name": name,
                    "status": state,
                    "health": c.get('Status', '')
                })

        running = len([w for w in worker_list if w.get("status") == "running"])

        return {
            "count": running,
            "workers": worker_list,
            "max_allowed": 20
        }
    except FileNotFoundError:
        return {
            "count": -1,
            "error": "Docker socket not available",
            "workers": []
        }
    except Exception as e:
        return {
            "count": -1,
            "error": f"Failed to query Docker: {str(e)}",
            "workers": []
        }


@app.post("/workers")
async def scale_workers(request: WorkerScaleRequest):
    """Scale the number of worker containers using Docker socket API."""
    import urllib.parse

    try:
        count = request.count
        if count < 1 or count > 20:
            raise HTTPException(400, "Workers must be between 1 and 20")

        # Get current workers via socket API
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Filter to shakerscan workers only (exclude gungnir-worker)
        workers = []
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'shakerscan' in name.lower() and 'worker' in name.lower() and 'gungnir' not in name.lower():
                workers.append(c)

        running = [c for c in workers if c.get('State') == 'running']
        stopped = [c for c in workers if c.get('State') != 'running']
        current_count = len(running)

        if count == current_count:
            return {
                "status": "success",
                "target_count": current_count,
                "message": f"Already at {count} worker(s)"
            }

        if count > current_count:
            # Scale up - start stopped workers first
            started = 0
            for container in stopped[:count - current_count]:
                container_id = container.get('Id')
                start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")
                if start_status in [204, 304]:  # 204 = started, 304 = already running
                    started += 1

            new_count = current_count + started

            # If we still need more workers, create new containers
            needed = count - new_count
            if needed > 0:
                # Get compose context from existing workers
                project, network, image = get_compose_context(workers)
                if project and network and image:
                    # Find the highest worker number
                    existing_numbers = []
                    for w in workers:
                        names = w.get('Names', [])
                        name = names[0].lstrip('/') if names else ''
                        # Extract number from name like "shakerscan-oss-worker-3"
                        if '-worker-' in name:
                            try:
                                num = int(name.split('-worker-')[-1])
                                existing_numbers.append(num)
                            except ValueError:
                                pass

                    next_num = max(existing_numbers) + 1 if existing_numbers else 1
                    created = 0

                    # Get env vars and bind mounts from an existing worker (via inspect)
                    existing_env = [f"REDIS_URL={REDIS_URL}", f"DATABASE_URL={DATABASE_URL}"]
                    existing_binds = [f"{os.environ.get('HOST_RESULTS_PATH', '/tmp/scanner-results')}:/results:rw"]

                    if workers:
                        # Inspect first running worker to get full config
                        ref_worker = workers[0]
                        ref_id = ref_worker.get("Id", "")
                        if ref_id:
                            inspect_status, inspect_data = docker_socket_request("GET", f"/containers/{ref_id}/json")
                            if inspect_status == 200 and isinstance(inspect_data, dict):
                                # Copy env vars from existing worker
                                config_env = inspect_data.get("Config", {}).get("Env", [])
                                if config_env:
                                    existing_env = config_env

                                # Copy bind mounts from existing worker
                                mounts = inspect_data.get("Mounts", [])
                                binds = []
                                for mount in mounts:
                                    if mount.get("Type") == "bind":
                                        src = mount.get("Source", "")
                                        dst = mount.get("Destination", "")
                                        mode = "ro" if not mount.get("RW", True) else "rw"
                                        if src and dst:
                                            binds.append(f"{src}:{dst}:{mode}")
                                if binds:
                                    existing_binds = binds

                    for i in range(needed):
                        worker_num = next_num + i
                        name = f"{project}-worker-{worker_num}"

                        labels = {
                            "com.docker.compose.project": project,
                            "com.docker.compose.service": "worker",
                            "com.docker.compose.oneoff": "False",
                            "com.docker.compose.container-number": str(worker_num)
                        }

                        create_body = {
                            "Image": image,
                            "Cmd": ["python3", "/app/worker.py"],
                            "Env": existing_env,
                            "Labels": labels,
                            "HostConfig": {
                                "NetworkMode": network,
                                "RestartPolicy": {"Name": "unless-stopped"},
                                "Binds": existing_binds
                            }
                        }

                        create_path = f"/containers/create?name={urllib.parse.quote(name)}"
                        create_status, create_data = docker_socket_request("POST", create_path, create_body)

                        if create_status == 201:
                            container_id = create_data.get("Id")
                            # Start the new container
                            start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")
                            if start_status in [204, 304]:
                                created += 1
                                new_count += 1

                    if created > 0:
                        # Return success only if we reached the target, otherwise partial
                        status = "success" if new_count >= count else "partial"
                        return {
                            "status": status,
                            "target_count": new_count,
                            "message": f"Scaled to {new_count} worker(s) (started {started}, created {created})"
                        }

            if new_count < count:
                return {
                    "status": "partial",
                    "target_count": new_count,
                    "message": f"Could only scale to {new_count} workers"
                }

            return {
                "status": "success",
                "target_count": new_count,
                "message": f"Scaled to {new_count} worker(s)"
            }

        else:
            # Scale down - stop excess workers
            to_stop = running[count:]
            stopped_count = 0
            for container in to_stop:
                container_id = container.get('Id')
                stop_status, _ = docker_socket_request("POST", f"/containers/{container_id}/stop")
                if stop_status in [204, 304]:  # 204 = stopped, 304 = already stopped
                    stopped_count += 1

            return {
                "status": "success",
                "target_count": count,
                "message": f"Scaled down to {count} worker(s) (stopped {stopped_count})"
            }

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh scale <N>"
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to scale workers: {str(e)}")


# ============================================================
# GUNGNIR CT MONITOR
# ============================================================

@app.get("/gungnir/status")
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


@app.post("/gungnir/start")
async def gungnir_start():
    """Start Gungnir CT monitor worker using Docker socket API."""
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
            status_code, all_containers = docker_socket_request("GET", "/containers/json?all=true")
            if status_code != 200:
                raise HTTPException(500, f"Failed to query containers: status {status_code}")

            project, network, image = get_compose_context(all_containers if isinstance(all_containers, list) else [])
            if not image or not network:
                raise HTTPException(
                    status_code=404,
                    detail="Gungnir container not found and auto-create failed. Start the stack with ./scanner.sh start first."
                )

            # Look for gungnir-worker image specifically, fall back to worker image
            gungnir_image = None
            if project:
                # Check if gungnir-worker image exists
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

            # Use gungnir-worker image if found, otherwise fall back to worker image
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

            gungnir = {"Id": container_id, "State": "created"}

        if gungnir.get('State') == 'running':
            return {
                "status": "already_running",
                "message": "Gungnir is already running"
            }

        # Start the container
        container_id = gungnir.get('Id')
        start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")

        if start_status in [204, 304]:  # 204 = started, 304 = already started
            # Update Redis status
            r.hset("gungnir:status", "running", "true")
            return {
                "status": "started",
                "message": "Gungnir CT monitor started successfully"
            }
        else:
            raise HTTPException(500, f"Failed to start Gungnir: Docker returned status {start_status}")

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh gungnir start"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Gungnir: {str(e)}")


@app.post("/gungnir/stop")
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


# ============================================================
# QUEUE MANAGEMENT
# ============================================================

@app.get("/queue/stats")
async def queue_stats():
    """Get queue statistics."""
    r = get_redis()
    cached = r.get("queue:stats_cache")
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass
    now = datetime.utcnow()

    completed = 0
    running = 0
    queued = 0
    failed = 0

    for key in r.scan_iter("job:*"):
        job_data = r.hgetall(key)
        if not job_data:
            continue

        # Redis client uses decode_responses=True, so values are already strings
        status_str = job_data.get('status', '')

        if status_str == 'running':
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
            queued += 1
        elif status_str == 'failed':
            failed += 1

    result = {
        'pending': r.llen(QUEUE_NAME),
        'queued': queued,
        'running': running,
        'completed': completed,
        'failed': failed
    }
    try:
        r.setex("queue:stats_cache", 5, json.dumps(result))
    except Exception:
        pass
    return result


@app.delete("/queue/clear")
async def clear_queue():
    """Clear all pending jobs."""
    r = get_redis()
    count = r.llen(QUEUE_NAME)
    r.delete(QUEUE_NAME)
    return {'cleared': count}


# ============================================================
# RESULTS (File-based)
# ============================================================

@app.get("/results")
async def list_results(limit: int = 50):
    """List recent scan results from files."""
    if not RESULTS_DIR.exists():
        return {'results': [], 'count': 0}

    results = []
    for target_dir in RESULTS_DIR.iterdir():
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

    results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return {'results': results[:limit], 'count': len(results)}


@app.get("/results/{target_folder}/latest")
async def get_latest_result(target_folder: str):
    """Get latest scan result for a target."""
    filepath = RESULTS_DIR / target_folder / "latest.json"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Result not found")
    with open(filepath) as f:
        return json.load(f)


# ============================================================
# UTILITIES
# ============================================================

def extract_root_domain(url: str) -> str:
    """Extract root domain from URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.netloc or parsed.path.split('/')[0]
        # Remove port
        host = host.split(':')[0]
        # Get root domain (last 2 parts)
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return url


def is_root_domain(url: str) -> bool:
    """Check if URL is a root domain (not a subdomain)."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.netloc or parsed.path.split('/')[0]
        host = host.split(':')[0].lower()  # Remove port
        root = extract_root_domain(url).lower()
        # It's a root if host equals root_domain or www.root_domain
        return host == root or host == f'www.{root}'
    except Exception:
        return False


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8080)

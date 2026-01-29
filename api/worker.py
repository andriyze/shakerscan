#!/usr/bin/env python3
"""
Shaker Scan Worker - Open Source Edition
Redis-based job worker with PostgreSQL persistence.
"""

import asyncio
import hashlib
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path

import asyncpg
import redis

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
SCANNER_PATH = '/app/scanner.py'
SCAN_LOG_TAIL = int(os.environ.get('SCAN_LOG_TAIL', '200'))
SCAN_LOG_TTL_SECONDS = int(os.environ.get('SCAN_LOG_TTL_SECONDS', '86400'))

# Maximum allowed duration per scan type (minutes) - worker-side safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 600,        # 10 hours
    'aggressive': 600,  # 10 hours
    'smart': 360,
}
DEFAULT_MAX_DURATION_MINUTES = int(os.environ.get('SCAN_MAX_DURATION_DEFAULT_MINUTES', '120'))
SCAN_KILL_GRACE_SECONDS = int(os.environ.get('SCAN_KILL_GRACE_SECONDS', '10'))

# Database pool (initialized in main)
db_pool = None


def get_redis():
    return redis.from_url(REDIS_URL)


async def init_db():
    """Initialize database connection pool."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)


async def run_scan(target: str, options: dict, scan_id: str | None = None, job_id: str | None = None) -> dict:
    """Execute scanner and return results."""
    cmd = ['python3', SCANNER_PATH, target]

    # Map scan_type to CLI flags (mutually exclusive presets)
    # Scan types: quick, standard, deep, full, aggressive, smart
    scan_type = (options.get('scan_type') or '').lower()

    # Scan types that require active testing (XSS/SQLi probes)
    active_enforced_types = {'smart', 'full', 'aggressive'}

    # Validate: public mode is incompatible with active-enforced scan types
    if scan_type in active_enforced_types and options.get('public'):
        raise ValueError(
            f"public option is incompatible with '{scan_type}' scan type. "
            f"{scan_type.capitalize()} scans require active testing. "
            "Use 'deep' scan type for passive-only comprehensive scanning."
        )

    if scan_type == 'smart':
        cmd.append('--smart')
    elif scan_type == 'aggressive':
        cmd.append('--aggressive')
    elif scan_type == 'full':
        cmd.append('--full')
    elif scan_type == 'deep' or options.get('thorough'):
        cmd.append('--deep')
    elif scan_type == 'standard':
        cmd.append('--standard')
    elif scan_type == 'quick' or options.get('quick'):
        cmd.append('--quick')
    # If no scan_type, run standard scan (no flag needed)

    # Additional flags (can be combined with scan types)
    # Pass --active when explicitly requested (even with explicit scan_type)
    # Note: full/aggressive/smart already include active tests, so skip for those
    if options.get('active') and scan_type not in ['full', 'aggressive', 'smart']:
        cmd.append('--active')

    # Note: public is not allowed for smart/full/aggressive (validated above)
    if options.get('public'):
        cmd.append('--public')
    if options.get('xss'):
        cmd.append('--xss')
    if options.get('sqli'):
        cmd.append('--sqli')
    if options.get('nuclei') and scan_type not in ['full', 'aggressive', 'deep']:
        cmd.append('--nuclei')
    if options.get('enhanced_dns'):
        cmd.append('--enhanced-dns')
    if options.get('subfinder'):
        cmd.append('--subfinder')

    # Client-Side Security
    if options.get('js_dependency_scanning'):
        cmd.append('--js-dependency-scanning')
    if options.get('js_secret_scanning'):
        cmd.append('--js-secret-scanning')
    if options.get('grpc_discovery'):
        cmd.append('--grpc-discovery')
    if options.get('json_link_following'):
        cmd.append('--json-link-following')
    if options.get('options_method_discovery'):
        cmd.append('--options-method-discovery')
    if options.get('include_partial_attack_chains'):
        cmd.append('--include-partial-attack-chains')

    # Smart scan tuning options
    if options.get('no_early_stop'):
        cmd.append('--no-early-stop')
    if options.get('thorough_params'):
        cmd.append('--thorough-params')
    if options.get('oob_callback_url'):
        cmd.extend(['--oob-callback-url', options['oob_callback_url']])

    # Safety/performance limits
    if options.get('smart_bola_max_endpoints'):
        cmd.extend(['--smart-bola-max-endpoints', str(options['smart_bola_max_endpoints'])])
    if options.get('dom_xss_max_files'):
        cmd.extend(['--dom-xss-max-files', str(options['dom_xss_max_files'])])
    if options.get('sqli_extract_max'):
        cmd.extend(['--sqli-extract-max', str(options['sqli_extract_max'])])
    # oob_max_findings (prefer new name, fall back to deprecated oob_max_payloads)
    oob_max = options.get('oob_max_findings')
    if oob_max is None:
        oob_max = options.get('oob_max_payloads')
    if oob_max is not None:
        cmd.extend(['--oob-max-findings', str(oob_max)])

    # AI options
    ai_url = options.get('ai_url') or os.environ.get('AI_URL')
    ai_api_key = options.get('ai_api_key') or os.environ.get('AI_API_KEY')
    model = options.get('model') or os.environ.get('AI_MODEL')
    ai_mask_host = options.get('ai_mask_host') or os.environ.get('AI_MASK_HOST', 'example.com')

    if ai_url and ai_api_key and model:
        cmd.append('--ai')
        cmd.extend(['--ai-url', ai_url])
        cmd.extend(['--ai-api-key', ai_api_key])
        cmd.extend(['--model', model])
        cmd.extend(['--ai-mask-host', ai_mask_host])

    # Authentication options
    # Session-based auth (cookies, headers)
    if options.get('auth_cookies'):
        cmd.extend(['--auth-cookies', options['auth_cookies']])
    if options.get('auth_header'):
        cmd.extend(['--auth-header', options['auth_header']])
    if options.get('auth_headers_json'):
        cmd.extend(['--auth-headers-json', options['auth_headers_json']])

    # Form-based login
    if options.get('login_username') and options.get('login_password'):
        cmd.extend(['--login-username', options['login_username']])
        cmd.extend(['--login-password', options['login_password']])
    if options.get('login_url'):
        cmd.extend(['--login-url', options['login_url']])
    if options.get('login_extra_fields'):
        cmd.extend(['--login-extra-fields', options['login_extra_fields']])
    if options.get('auto_auth'):
        cmd.append('--auto-auth')

    # Multi-user auth (for BOLA/IDOR testing)
    if options.get('user2_cookies'):
        cmd.extend(['--user2-cookies', options['user2_cookies']])
    if options.get('user2_header'):
        cmd.extend(['--user2-header', options['user2_header']])

    # Manual endpoints for API-only targets
    custom_endpoints = options.get('custom_endpoints')
    if custom_endpoints and isinstance(custom_endpoints, list):
        for endpoint in custom_endpoints:
            if endpoint and isinstance(endpoint, str):
                cmd.extend(['--endpoints', endpoint.strip()])

    # Log command (mask API key and sensitive auth data)
    sensitive_flags = ['--ai-api-key', '--auth-cookies', '--auth-header', '--auth-headers-json',
                       '--login-password', '--user2-cookies', '--user2-header']
    cmd_masked = []
    for i, c in enumerate(cmd):
        if i > 0 and cmd[i-1] in sensitive_flags:
            cmd_masked.append('***')
        else:
            cmd_masked.append(c)
    print(f"  Command: {' '.join(cmd_masked)}", flush=True)

    # Set up checkpoint file for partial result recovery
    checkpoint_file = None
    scan_env = os.environ.copy()
    if scan_id:
        checkpoint_file = RESULTS_DIR / f"{scan_id}_checkpoint.json"
        scan_env["SCAN_CHECKPOINT_FILE"] = str(checkpoint_file)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=scan_env
    )

    timeout_reason: str | None = None
    max_duration_minutes = DEFAULT_MAX_DURATION_MINUTES
    override_minutes = os.environ.get("SCAN_MAX_DURATION_MINUTES")
    if override_minutes:
        try:
            max_duration_minutes = int(override_minutes)
        except Exception:
            max_duration_minutes = DEFAULT_MAX_DURATION_MINUTES
    else:
        if scan_type:
            max_duration_minutes = MAX_SCAN_DURATION.get(scan_type, DEFAULT_MAX_DURATION_MINUTES)

    async def _watchdog_timeout() -> None:
        nonlocal timeout_reason
        if max_duration_minutes <= 0:
            return
        await asyncio.sleep(max_duration_minutes * 60)
        if proc.returncode is None:
            timeout_reason = (
                f"Exceeded max duration ({max_duration_minutes} min for {scan_type or 'standard'} scan)"
            )
            try:
                proc.terminate()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(proc.wait(), timeout=SCAN_KILL_GRACE_SECONDS)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

    watchdog_task = asyncio.create_task(_watchdog_timeout())

    stdout_chunks: list[bytes] = []
    stderr_lines: list[str] = []
    last_progress: tuple[str | None, int | None] = (None, None)
    log_key = f"scan:{scan_id}:logs" if scan_id else None

    def _parse_progress(line: str) -> tuple[str, int] | None:
        if not line.startswith("[progress]"):
            return None
        phase_match = re.search(r"\bphase=([^\s]+)", line)
        pct_match = re.search(r"\bpct=(\d{1,3})", line)
        if not phase_match or not pct_match:
            return None
        phase = phase_match.group(1)
        try:
            pct = int(pct_match.group(1))
        except ValueError:
            return None
        pct = max(0, min(100, pct))
        return phase, pct

    async def _handle_stdout(line: bytes) -> None:
        stdout_chunks.append(line)

    async def _handle_stderr(line: bytes) -> None:
        nonlocal last_progress
        text = line.decode(errors="replace").rstrip("\n")
        if not text:
            return
        stderr_lines.append(text)
        # Limit in-memory stderr to avoid bloat
        if len(stderr_lines) > 2000:
            stderr_lines.pop(0)

        if log_key:
            try:
                r = get_redis()
                r.rpush(log_key, text)
                r.ltrim(log_key, -SCAN_LOG_TAIL, -1)
                r.expire(log_key, SCAN_LOG_TTL_SECONDS)
            except Exception:
                pass

        progress = _parse_progress(text)
        if progress and scan_id:
            phase, pct = progress
            last_phase, last_pct = last_progress
            if phase != last_phase or pct != last_pct:
                await update_scan_progress(scan_id, phase, pct, job_id=job_id)
                last_progress = (phase, pct)

    async def _read_stream(stream: asyncio.StreamReader, handler) -> None:
        while True:
            line = await stream.readline()
            if not line:
                break
            await handler(line)

    stdout_task = asyncio.create_task(_read_stream(proc.stdout, _handle_stdout))
    stderr_task = asyncio.create_task(_read_stream(proc.stderr, _handle_stderr))

    await proc.wait()
    if watchdog_task:
        watchdog_task.cancel()
        try:
            await watchdog_task
        except Exception:
            pass
    await stdout_task
    await stderr_task

    stdout_text = b"".join(stdout_chunks).decode(errors="replace") if stdout_chunks else ""
    stderr_text = "\n".join(stderr_lines)

    try:
        result = json.loads(stdout_text)
    except json.JSONDecodeError:
        if timeout_reason and checkpoint_file and checkpoint_file.exists():
            try:
                with open(checkpoint_file) as f:
                    checkpoint_data = json.load(f)
                partial = checkpoint_data.get("report")
                if partial:
                    partial["error"] = timeout_reason
                    return partial
            except Exception:
                pass
        return {
            'error': timeout_reason or stderr_text,
            'target': target,
            'exit_code': proc.returncode
        }

    if stderr_text:
        print(stderr_text, flush=True)
        # Preserve a trimmed copy in scan metadata for troubleshooting.
        if isinstance(result, dict):
            scan_metadata = result.get("scan_metadata")
            if isinstance(scan_metadata, dict):
                scan_metadata.setdefault("scanner_stderr", stderr_text[-20000:])
            else:
                result["scan_metadata"] = {"scanner_stderr": stderr_text[-20000:]}

    # Clean up checkpoint file on successful completion
    if checkpoint_file and checkpoint_file.exists():
        try:
            checkpoint_file.unlink()
        except Exception:
            pass

    return result


async def run_discovery(root_domain: str) -> dict:
    """Execute subdomain discovery."""
    cmd = ['python3', SCANNER_PATH, root_domain, '--subfinder', '--quick']

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    try:
        result = json.loads(stdout.decode())
        return {
            'subdomains': result.get('subdomains', []),
            'by_source': result.get('by_source', {}),
            'total': result.get('subdomain_count', 0)
        }
    except json.JSONDecodeError:
        return {
            'error': stderr.decode(),
            'root_domain': root_domain,
            'subdomains': []
        }


def generate_finding_fingerprint(finding: dict) -> str:
    """Generate a unique fingerprint for deduplication.

    Uses the full scanner ID (e.g., 'exposed_files:abc123') as fingerprint
    to ensure consistency with UI and avoid collisions from suffix-only matching.
    """
    # Prefer scanner's original ID if available (full format: "tool:hash")
    scanner_id = finding.get('id', '')
    if scanner_id:
        return scanner_id

    # Fallback to computed fingerprint for findings without scanner ID
    key_parts = [
        finding.get('title', ''),
        finding.get('tool', ''),
        finding.get('url', ''),
        finding.get('cwe', '')
    ]
    key_string = '|'.join(str(p) for p in key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


async def save_findings(scan_id: str, target_id: str, findings: list):
    """Save findings to database with deduplication."""
    if not findings:
        return

    async with db_pool.acquire() as conn:
        for finding in findings:
            fingerprint = generate_finding_fingerprint(finding)

            # Check if this finding already exists for this target
            existing = await conn.fetchrow("""
                SELECT id, status, resurfaced_count
                FROM findings
                WHERE target_id = $1 AND fingerprint = $2
            """, uuid.UUID(target_id), fingerprint)

            if existing:
                # Update existing finding
                if existing['status'] == 'resolved':
                    # Resurfaced!
                    await conn.execute("""
                        UPDATE findings SET
                            status = 'active',
                            last_seen_at = NOW(),
                            resurfaced_count = $1,
                            scan_id = $2,
                            updated_at = NOW()
                        WHERE id = $3
                    """, existing['resurfaced_count'] + 1, uuid.UUID(scan_id), existing['id'])
                else:
                    # Just update last_seen
                    await conn.execute("""
                        UPDATE findings SET
                            last_seen_at = NOW(),
                            scan_id = $1,
                            updated_at = NOW()
                        WHERE id = $2
                    """, uuid.UUID(scan_id), existing['id'])
            else:
                # Insert new finding
                await conn.execute("""
                    INSERT INTO findings (
                        scan_id, target_id, fingerprint, title, description,
                        severity, cvss_score, tool, cwe, cwe_name, owasp,
                        url, evidence, ai_verdict, ai_confidence, ai_rationale, ai_recommendations
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                """,
                    uuid.UUID(scan_id),
                    uuid.UUID(target_id),
                    fingerprint,
                    finding.get('title'),
                    finding.get('description'),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score'),
                    finding.get('tool'),
                    finding.get('cwe'),
                    finding.get('cwe_name'),
                    finding.get('owasp'),
                    finding.get('url'),
                    json.dumps(finding.get('evidence')) if finding.get('evidence') else None,
                    finding.get('ai_verdict'),
                    finding.get('ai_confidence'),
                    finding.get('ai_rationale'),
                    json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None
                )


def save_result_file(result: dict, job_id: str) -> str:
    """Save scan result to JSON file."""
    target = result.get('input', {}).get('normalized_host', 'unknown')
    target_safe = "".join(c if c.isalnum() or c in '.-_' else '_' for c in target)

    target_dir = RESULTS_DIR / target_safe
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{job_id[:8]}.json"
    filepath = target_dir / filename

    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)

    # Update latest.json
    latest_path = target_dir / "latest.json"
    try:
        if latest_path.exists() or latest_path.is_symlink():
            latest_path.unlink()
        with open(latest_path, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return str(filepath)


async def send_heartbeats(job_id: str, stop_event: asyncio.Event):
    """Send periodic heartbeats."""
    r = get_redis()
    while not stop_event.is_set():
        try:
            r.hset(f"job:{job_id}", 'heartbeat', datetime.utcnow().isoformat())
        except Exception as e:
            print(f"[{job_id[:8]}] Heartbeat error: {e}", flush=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass


async def update_scan_progress(scan_id: str, phase: str, progress: int, job_id: str | None = None):
    """Update scan progress in database (and Redis if job_id provided)."""
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE scans SET current_phase = $1, progress = $2
            WHERE id = $3
        """, phase, progress, uuid.UUID(scan_id))
    if job_id:
        try:
            r = get_redis()
            r.hset(f"job:{job_id}", mapping={'current_phase': phase, 'progress': str(progress)})
        except Exception:
            pass


async def process_scan_job(job_data: dict):
    """Process a scan job."""
    job_id = job_data.get('job_id', 'unknown')
    scan_id = job_data.get('scan_id')
    target = job_data.get('target')
    options = job_data.get('options', {})

    print(f"[{job_id[:8]}] Starting scan: {target}", flush=True)
    print(f"[{job_id[:8]}] Options keys: {list(options.keys())}", flush=True)
    print(f"[{job_id[:8]}] auth_header present: {bool(options.get('auth_header'))}", flush=True)
    print(f"[{job_id[:8]}] custom_endpoints: {len(options.get('custom_endpoints') or [])} endpoints", flush=True)

    r = get_redis()
    now = datetime.utcnow()

    # Update Redis status
    r.hset(f"job:{job_id}", mapping={
        'status': 'running',
        'scan_id': scan_id,
        'started_at': now.isoformat(),
        'heartbeat': now.isoformat()
    })
    r.delete(f"scan:{scan_id}:logs")

    # Update database
    target_id = None
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE scans SET status = 'running', started_at = $1
            WHERE id = $2
        """, now, uuid.UUID(scan_id))

        # Get target_id
        row = await conn.fetchrow("SELECT target_id FROM scans WHERE id = $1", uuid.UUID(scan_id))
        if row:
            target_id = str(row['target_id'])

    # Initial progress
    await update_scan_progress(scan_id, "starting", 5, job_id=job_id)

    # Start heartbeat
    stop_heartbeat = asyncio.Event()
    heartbeat_task = asyncio.create_task(send_heartbeats(job_id, stop_heartbeat))

    try:
        result = await run_scan(target, options, scan_id=scan_id, job_id=job_id)
    except ValueError as e:
        # Validation errors (e.g., incompatible options like public+smart)
        result = {
            'target': target,
            'error': str(e),
            'result': {'score': None, 'grade': None},
            'findings': []
        }
        print(f"[{job_id[:8]}] Validation error: {e}", flush=True)
    finally:
        stop_heartbeat.set()
        try:
            await heartbeat_task
        except Exception:
            pass

    result['job_id'] = job_id
    result['scan_id'] = scan_id

    # Extract results
    score = result.get('result', {}).get('score')
    grade = result.get('result', {}).get('grade')
    findings = result.get('findings', [])
    error = result.get('error')

    # Save to file
    filepath = save_result_file(result, job_id)

    # Calculate duration
    completed_at = datetime.utcnow()
    duration = int((completed_at - now).total_seconds())

    # Update database - but check if scan was already marked failed by stale checker
    async with db_pool.acquire() as conn:
        # Check current status - don't overwrite if already failed (e.g., by stale scan checker)
        current = await conn.fetchrow(
            "SELECT status FROM scans WHERE id = $1",
            uuid.UUID(scan_id)
        )
        if current and current['status'] == 'failed':
            print(f"[{job_id[:8]}] Scan already marked failed (stale?), not overwriting scan row", flush=True)
            # Don't save findings - stale checker already saved partial findings from checkpoint.
            # Saving late-completing findings would cause inconsistency between scan report and /findings.
            # Update Redis to mark job as done so it doesn't stay "running"
            # Don't set result_path - the late-completing output doesn't match the official partial results
            job_key = f"job:{job_id}"
            r.hset(job_key, mapping={
                'status': 'failed',
                'score': str(score) if score else 'N/A',
                'grade': str(grade) if grade else 'N/A',
                'completed_at': completed_at.isoformat(),
                'progress': '100',
                'current_phase': 'terminated'
            })
            r.expire(job_key, 86400)
            return

        if error:
            await conn.execute("""
                UPDATE scans SET
                    status = 'failed',
                    error_message = $1,
                    completed_at = $2,
                    duration_seconds = $3,
                    progress = 100,
                    current_phase = 'failed'
                WHERE id = $4
            """, error, completed_at, duration, uuid.UUID(scan_id))
        else:
            await conn.execute("""
                UPDATE scans SET
                    status = 'completed',
                    result = $1,
                    score = $2,
                    grade = $3,
                    findings_count = $4,
                    completed_at = $5,
                    duration_seconds = $6,
                    progress = 100
                WHERE id = $7
            """, json.dumps(result), score, grade, len(findings),
                 completed_at, duration, uuid.UUID(scan_id))

    # Save findings
    if target_id and findings:
        await save_findings(scan_id, target_id, findings)

    # Update Redis
    status = 'failed' if error else 'completed'
    job_key = f"job:{job_id}"
    r.hset(job_key, mapping={
        'status': status,
        'result_path': filepath,
        'score': str(score) if score else 'N/A',
        'grade': str(grade) if grade else 'N/A',
        'completed_at': completed_at.isoformat(),
        'progress': '100',
        'current_phase': status
    })
    # Expire completed/failed job keys after 24 hours
    r.expire(job_key, 86400)

    print(f"[{job_id[:8]}] Completed: {target} | Score: {score} | Grade: {grade} | Findings: {len(findings)}", flush=True)


async def process_discovery_job(job_data: dict):
    """Process a discovery job."""
    job_id = job_data.get('job_id', 'unknown')
    discovery_id = job_data.get('discovery_id')
    root_domain = job_data.get('root_domain')

    print(f"[{job_id[:8]}] Starting discovery: {root_domain}", flush=True)

    r = get_redis()
    now = datetime.utcnow()

    # Update status
    r.hset(f"job:{job_id}", mapping={'status': 'running', 'started_at': now.isoformat()})

    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE discovery_runs SET status = 'running', started_at = $1
            WHERE id = $2
        """, now, uuid.UUID(discovery_id))

    # Run discovery
    result = await run_discovery(root_domain)

    completed_at = datetime.utcnow()
    error = result.get('error')

    # Update database
    async with db_pool.acquire() as conn:
        if error:
            await conn.execute("""
                UPDATE discovery_runs SET
                    status = 'failed',
                    error_message = $1,
                    completed_at = $2
                WHERE id = $3
            """, error, completed_at, uuid.UUID(discovery_id))
        else:
            await conn.execute("""
                UPDATE discovery_runs SET
                    status = 'completed',
                    subdomains_found = $1,
                    result = $2,
                    sources_used = $3,
                    completed_at = $4
                WHERE id = $5
            """, result.get('total', 0), json.dumps(result.get('subdomains', [])),
                 json.dumps(result.get('by_source', {})), completed_at, uuid.UUID(discovery_id))

            # Auto-create targets for discovered subdomains
            for subdomain in result.get('subdomains', [])[:100]:  # Limit to 100
                try:
                    await conn.execute("""
                        INSERT INTO targets (url, root_domain, is_root, discovery_source)
                        VALUES ($1, $2, false, 'subfinder')
                        ON CONFLICT (url) DO NOTHING
                    """, f"https://{subdomain}", root_domain)
                except Exception:
                    pass

    job_key = f"job:{job_id}"
    r.hset(job_key, mapping={
        'status': 'failed' if error else 'completed',
        'completed_at': completed_at.isoformat()
    })
    # Expire completed/failed job keys after 24 hours
    r.expire(job_key, 86400)

    print(f"[{job_id[:8]}] Discovery completed: {root_domain} | Found: {result.get('total', 0)} subdomains", flush=True)


async def process_job(job_data: dict):
    """Route job to appropriate handler."""
    job_type = job_data.get('type', 'scan')

    if job_type == 'discovery':
        await process_discovery_job(job_data)
    else:
        await process_scan_job(job_data)


async def async_main():
    """Async main worker loop - uses single event loop for database pool."""
    print("Initializing worker...", flush=True)

    # Initialize database pool (bound to this event loop)
    await init_db()

    r = get_redis()
    print(f"Worker started, listening on queue: {QUEUE_NAME}", flush=True)

    loop = asyncio.get_event_loop()

    while True:
        try:
            # Use run_in_executor for blocking Redis pop
            result = await loop.run_in_executor(None, lambda: r.blpop(QUEUE_NAME, timeout=30))
            if result is None:
                continue  # Timeout, continue polling

            _, job_json = result
            job_data = json.loads(job_json)
            await process_job(job_data)
        except Exception as e:
            print(f"Error processing job: {e}", flush=True)
            import traceback
            traceback.print_exc()


def main():
    """Entry point - runs async main in single event loop."""
    asyncio.run(async_main())


if __name__ == '__main__':
    main()

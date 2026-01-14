#!/usr/bin/env python3
"""
Gungnir CT Monitor Worker
Monitors Certificate Transparency logs for all root domains in the targets table.
Discovered subdomains are automatically added as targets.

Usage:
    python3 gungnir_worker.py

Control via API:
    POST /gungnir/start - Start monitoring
    POST /gungnir/stop  - Stop monitoring
    GET  /gungnir/status - Get status
"""

import asyncio
import os
import signal
import tempfile
from datetime import datetime, timezone

import asyncpg
import redis

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
GUNGNIR_BIN = '/opt/tools/gungnir'
DOMAIN_RELOAD_INTERVAL = 300  # Reload domains every 5 minutes
STATUS_UPDATE_INTERVAL = 10   # Update Redis status every 10 seconds

# Global state
db_pool = None
shutdown_event = asyncio.Event()
stats = {
    'running': False,
    'domains_count': 0,
    'found_count': 0,
    'session_found': 0,
    'last_discovery': None,
    'started_at': None,
}


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


async def init_db():
    """Initialize database connection pool."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)


async def get_monitored_domains() -> list[str]:
    """Get unique root_domains from targets table."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT root_domain FROM targets
            WHERE root_domain IS NOT NULL AND is_active = true
        """)
        return [r['root_domain'] for r in rows if r['root_domain']]


async def store_subdomain(subdomain: str, root_domain: str) -> bool:
    """Insert discovered subdomain as target. Returns True if new."""
    async with db_pool.acquire() as conn:
        try:
            result = await conn.execute("""
                INSERT INTO targets (url, root_domain, is_root, discovery_source)
                VALUES ($1, $2, false, 'gungnir-monitor')
                ON CONFLICT (url) DO NOTHING
            """, f"https://{subdomain}", root_domain)
            # Check if row was inserted (not a conflict)
            return result == 'INSERT 0 1'
        except Exception as e:
            print(f"[gungnir] Error storing subdomain {subdomain}: {e}", flush=True)
            return False


def update_redis_status(r: redis.Redis):
    """Update status in Redis for UI/API."""
    now = datetime.now(timezone.utc)
    uptime = 0
    if stats['started_at']:
        uptime = int((now - stats['started_at']).total_seconds())

    r.hset("gungnir:status", mapping={
        "running": "true" if stats['running'] else "false",
        "domains_monitored": str(stats['domains_count']),
        "subdomains_found": str(stats['found_count']),
        "session_found": str(stats['session_found']),
        "last_discovery": stats['last_discovery'] or "",
        "started_at": stats['started_at'].isoformat() if stats['started_at'] else "",
        "uptime_seconds": str(uptime),
        "updated_at": now.isoformat(),
    })


async def status_updater():
    """Periodically update Redis status."""
    r = get_redis()
    while not shutdown_event.is_set():
        try:
            update_redis_status(r)
        except Exception as e:
            print(f"[gungnir] Status update error: {e}", flush=True)
        await asyncio.sleep(STATUS_UPDATE_INTERVAL)


async def run_gungnir(domains: list[str]):
    """Run gungnir with given domains and process output."""
    if not domains:
        print("[gungnir] No domains to monitor", flush=True)
        return

    # Create temp file with domains
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for domain in domains:
            f.write(domain + '\n')
        roots_file = f.name

    try:
        print(f"[gungnir] Starting monitor for {len(domains)} domains: {', '.join(domains[:5])}{'...' if len(domains) > 5 else ''}", flush=True)

        proc = await asyncio.create_subprocess_exec(
            GUNGNIR_BIN, '-r', roots_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Track seen subdomains to avoid duplicate DB calls
        seen = set()

        async def read_stdout():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break

                subdomain = line.decode().strip().lower()
                if not subdomain or subdomain in seen:
                    continue

                # Remove wildcard prefix
                subdomain = subdomain.replace('*.', '')

                # Find matching root domain
                for domain in domains:
                    if subdomain.endswith(domain) and subdomain != domain:
                        seen.add(subdomain)
                        is_new = await store_subdomain(subdomain, domain)
                        if is_new:
                            stats['found_count'] += 1
                            stats['session_found'] += 1
                            stats['last_discovery'] = subdomain
                            print(f"[gungnir] NEW: {subdomain} (root: {domain})", flush=True)
                        break

        async def read_stderr():
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                # Log errors but don't crash
                err = line.decode().strip()
                if err and 'error' in err.lower():
                    print(f"[gungnir] stderr: {err}", flush=True)

        # Run readers until shutdown or process ends
        stdout_task = asyncio.create_task(read_stdout())
        stderr_task = asyncio.create_task(read_stderr())

        # Wait for shutdown signal or process to end
        while not shutdown_event.is_set():
            if proc.returncode is not None:
                print(f"[gungnir] Process exited with code {proc.returncode}", flush=True)
                break
            await asyncio.sleep(1)

        # Cleanup
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

        stdout_task.cancel()
        stderr_task.cancel()

    finally:
        try:
            os.unlink(roots_file)
        except Exception:
            pass


async def monitor_loop():
    """Main monitoring loop with periodic domain reload."""
    stats['running'] = True
    stats['started_at'] = datetime.now(timezone.utc)
    stats['session_found'] = 0

    print("[gungnir] Monitor started", flush=True)

    while not shutdown_event.is_set():
        # Load current domains
        domains = await get_monitored_domains()
        stats['domains_count'] = len(domains)

        if not domains:
            print("[gungnir] No domains to monitor, waiting...", flush=True)
            await asyncio.sleep(60)
            continue

        # Run gungnir with timeout for domain reload
        try:
            await asyncio.wait_for(
                run_gungnir(domains),
                timeout=DOMAIN_RELOAD_INTERVAL
            )
        except asyncio.TimeoutError:
            # Normal - restart to reload domains
            print("[gungnir] Reloading domains...", flush=True)
        except Exception as e:
            print(f"[gungnir] Error: {e}", flush=True)
            await asyncio.sleep(10)

    stats['running'] = False
    print("[gungnir] Monitor stopped", flush=True)


def handle_shutdown(signum, frame):
    """Handle shutdown signals."""
    print(f"[gungnir] Received signal {signum}, shutting down...", flush=True)
    shutdown_event.set()


async def async_main():
    """Async entry point."""
    # Initialize database
    await init_db()

    # Get initial subdomain count from DB
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT COUNT(*) as count FROM targets
            WHERE discovery_source = 'gungnir-monitor'
        """)
        stats['found_count'] = row['count'] if row else 0

    print(f"[gungnir] Initialized. Previously found: {stats['found_count']} subdomains", flush=True)

    # Start status updater
    status_task = asyncio.create_task(status_updater())

    # Run monitor
    try:
        await monitor_loop()
    finally:
        status_task.cancel()
        # Final status update
        r = get_redis()
        stats['running'] = False
        update_redis_status(r)
        await db_pool.close()


def main():
    """Entry point."""
    # Check gungnir binary
    if not os.path.isfile(GUNGNIR_BIN):
        print(f"[gungnir] ERROR: Gungnir binary not found at {GUNGNIR_BIN}", flush=True)
        return 1

    # Setup signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    print("[gungnir] Gungnir CT Monitor Worker starting...", flush=True)

    # Run async main
    asyncio.run(async_main())

    print("[gungnir] Worker exited", flush=True)
    return 0


if __name__ == '__main__':
    exit(main())

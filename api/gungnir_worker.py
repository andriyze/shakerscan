#!/usr/bin/env python3
"""
Gungnir CT Monitor Worker
Monitors Certificate Transparency logs for all root domains in the targets table.
Discovered subdomains are automatically added as targets, bounded:

- a root that is a public suffix (``co.uk`` stored by an older engine) is never monitored;
- a CT name is used only when it is a valid host name on a label boundary under a monitored
  root; a leading ``*.`` names its parent, any other wildcard is dropped;
- each apex (eTLD+1) gains at most ``SHAKERSCAN_CT_MONITOR_DAILY_CAP`` new targets per UTC day
  (default 100, as the scan-path discovery cap); the names over the cap are counted per apex and
  day in Redis ``gungnir:suppressed`` and in the status, not inserted.

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

try:
    from scanner_tools.discovered_names import canonical_name, subdomain_of
except ModuleNotFoundError:  # source checkout / package import
    from scanner.scanner_tools.discovered_names import canonical_name, subdomain_of
try:
    from scope.psl import registrable_domain, spans_public_suffix
    from scope.roots import monitored_root
except ModuleNotFoundError:  # package import (api.gungnir_worker)
    from .scope.psl import registrable_domain, spans_public_suffix
    from .scope.roots import monitored_root

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
GUNGNIR_BIN = '/opt/tools/gungnir'
DOMAIN_RELOAD_INTERVAL = 300  # Reload domains every 5 minutes
STATUS_UPDATE_INTERVAL = 10   # Update Redis status every 10 seconds
DEFAULT_DAILY_CAP = 100       # new targets per apex per UTC day, as DISCOVERY_TARGET_LIMIT
SUPPRESSED_KEY = "gungnir:suppressed"  # field "<YYYY-MM-DD>:<apex>" -> names over the cap

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
    'suppressed_count': 0,
}


def daily_cap() -> int:
    """New CT-monitor targets allowed per apex per UTC day (SHAKERSCAN_CT_MONITOR_DAILY_CAP)."""
    try:
        value = int(os.environ.get("SHAKERSCAN_CT_MONITOR_DAILY_CAP", "") or DEFAULT_DAILY_CAP)
    except ValueError:
        value = DEFAULT_DAILY_CAP
    return max(0, min(value, 10_000))


def ct_name(raw: str) -> str | None:
    """The host a CT log line names, or None. ``*.a.example.com`` names ``a.example.com``; a
    wildcard anywhere else, an address or an invalid name drops the line. A non-ASCII name is
    spelled as its IDNA 2008/UTS #46 ASCII form (``discovered_names.canonical_name``)."""
    name = str(raw or "").strip()
    if name.startswith("*."):
        name = name[2:]
    if not name or "*" in name:
        return None
    return canonical_name(name)


def monitored_roots(roots: list[str]) -> list[str]:
    """Distinct roots to watch: a public suffix (co.uk, github.io) would add every site under it."""
    kept: list[str] = []
    for root in roots:
        name = str(root or "").strip().lower().rstrip(".")
        if not name or name in kept:
            continue
        if spans_public_suffix(name):
            print(f"[gungnir] Not monitoring {name}: it is or covers a public suffix", flush=True)
            continue
        kept.append(name)
    return kept


class ApexDailyCap:
    """At most ``cap`` new targets per apex per UTC day, seeded from the database so a restart
    does not reset it; names over the cap are counted, not inserted."""

    def __init__(self, cap: int, *, today=None):
        self.cap = cap
        self._today = today or (lambda: datetime.now(timezone.utc).date())
        self.day = None
        self.added: dict[str, int] = {}
        self.suppressed: dict[str, int] = {}

    def _roll(self) -> None:
        day = self._today()
        if day != self.day:
            self.day, self.added, self.suppressed = day, {}, {}

    async def allows(self, apex: str, count_today) -> bool:
        self._roll()
        if apex not in self.added:
            self.added[apex] = int(await count_today(apex, self.day))
        return self.added[apex] < self.cap

    def record_added(self, apex: str) -> None:
        self.added[apex] = self.added.get(apex, 0) + 1

    def record_suppressed(self, apex: str) -> str:
        self.suppressed[apex] = self.suppressed.get(apex, 0) + 1
        return f"{self.day.isoformat()}:{apex}"


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


async def init_db():
    """Initialize database connection pool."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)


async def get_monitored_domains() -> list[str]:
    """Unique roots to watch. A legacy spanning root (co.uk, stored before 2.8.1 and not yet
    recomputed by the startup migration) is replaced by the root each of its targets has now
    (example.co.uk), so monitoring continues for the customer and never covers the suffix."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT root_domain FROM targets
            WHERE root_domain IS NOT NULL AND is_active = true
        """)
        stored = [r['root_domain'] for r in rows if r['root_domain']]
        legacy = [root for root in stored if spans_public_suffix(root)]
        roots = [root for root in stored if root not in legacy]
        if legacy:
            for row in await conn.fetch("""
                SELECT root_domain, url FROM targets
                WHERE root_domain = ANY($1::text[]) AND is_active = true
            """, legacy):
                root = monitored_root(row['root_domain'], row['url'])
                if root:
                    roots.append(root)
        return list(dict.fromkeys(roots))


async def count_added_today(apex: str, day) -> int:
    """New CT-monitor targets already recorded under ``apex`` since the start of ``day`` (UTC)."""
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    async with db_pool.acquire() as conn:
        return int(await conn.fetchval("""
            SELECT COUNT(*) FROM targets
            WHERE discovery_source = 'gungnir-monitor' AND created_at >= $2
              AND (root_domain = $1 OR root_domain LIKE '%.' || $1)
        """, apex, start) or 0)


def match_root_domain(subdomain: str, domains: list[str]) -> str | None:
    """Return the most specific monitored root that ``subdomain`` sits under, if any.

    Matching is on label boundaries: ``a.example.com`` belongs to ``example.com`` and never
    to a shorter string suffix such as ``le.com``, whose ASM policy it would otherwise inherit.
    """
    matches = [domain for domain in domains if subdomain_of(subdomain, domain)]
    return max(matches, key=lambda domain: len(canonical_name(domain) or "")) if matches else None


async def store_subdomain(subdomain: str, root_domain: str) -> bool:
    """Insert discovered subdomain as target. Returns True if new.

    Continuous ASM (docs §16 Phase 4): if the root domain already has ASM
    enabled on any target, inherit that policy onto the newly discovered
    surface. The background dispatcher then auto-recons it (last_recon_at is
    NULL -> recon fires) and subsequently tests it — new attack surface flows
    straight into continuous testing, mirroring how Gungnir alerts on new certs.
    """
    async with db_pool.acquire() as conn:
        try:
            row = await conn.fetchrow("""
                INSERT INTO targets (url, root_domain, is_root, discovery_source)
                VALUES ($1, $2, false, 'gungnir-monitor')
                ON CONFLICT (canonical_key) DO NOTHING
                RETURNING id
            """, f"https://{subdomain}", root_domain)
            if not row:
                return False  # already existed

            # Inherit ASM policy from the root domain (copied entirely in SQL so
            # there's no JSONB round-trip); only updates if some target under
            # this root has ASM enabled.
            tag = await conn.execute("""
                UPDATE targets t
                SET asm_enabled = true, asm_config = src.asm_config, updated_at = NOW()
                FROM (
                    SELECT asm_config FROM targets
                    WHERE root_domain = $2 AND asm_enabled = true
                    ORDER BY is_root DESC, created_at ASC
                    LIMIT 1
                ) src
                WHERE t.id = $1
            """, row['id'], root_domain)
            if tag.endswith('1'):
                print(f"[gungnir] ASM auto-enabled on new surface {subdomain} "
                      f"(inherited policy from {root_domain})", flush=True)
            return True
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
        "suppressed_over_daily_cap": str(stats['suppressed_count']),
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


async def handle_ct_name(raw: str, domains: list[str], seen: set[str], cap: ApexDailyCap,
                         *, store=None, count_today=None, redis_client=None) -> str:
    """Store one CT name as a target when it is new, valid, in scope and under its apex's cap.

    Returns what happened: ``invalid``, ``duplicate``, ``out_of_scope``, ``suppressed``,
    ``existing`` or ``added``.
    """
    subdomain = ct_name(raw)
    if subdomain is None:
        return "invalid"
    if subdomain in seen:
        return "duplicate"
    seen.add(subdomain)
    # Find the monitored root this name belongs to (dot boundary, most specific root)
    domain = match_root_domain(subdomain, domains)
    if not domain:
        return "out_of_scope"
    apex = registrable_domain(domain) or domain
    if not await cap.allows(apex, count_today or count_added_today):
        field = cap.record_suppressed(apex)
        stats['suppressed_count'] += 1
        try:
            client = redis_client or get_redis()
            client.hincrby(SUPPRESSED_KEY, field, 1)
        except Exception as exc:  # the count is diagnostic; the cap itself already held
            print(f"[gungnir] Could not record a suppressed name: {type(exc).__name__}", flush=True)
        if cap.suppressed[apex] == 1:
            print(f"[gungnir] Daily cap of {cap.cap} new targets reached for {apex}; "
                  "further names are counted, not added", flush=True)
        return "suppressed"
    if not await (store or store_subdomain)(subdomain, domain):
        return "existing"
    cap.record_added(apex)
    stats['found_count'] += 1
    stats['session_found'] += 1
    stats['last_discovery'] = subdomain
    print(f"[gungnir] NEW: {subdomain} (root: {domain})", flush=True)
    return "added"


async def run_gungnir(domains: list[str], cap: "ApexDailyCap | None" = None):
    """Run gungnir with given domains and process output."""
    cap = cap or ApexDailyCap(daily_cap())
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
                await handle_ct_name(line.decode(errors="replace"), domains, seen, cap)

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
    cap = ApexDailyCap(daily_cap())

    while not shutdown_event.is_set():
        # Load current domains
        domains = monitored_roots(await get_monitored_domains())
        stats['domains_count'] = len(domains)

        if not domains:
            print("[gungnir] No domains to monitor, waiting...", flush=True)
            await asyncio.sleep(60)
            continue

        # Run gungnir with timeout for domain reload
        try:
            await asyncio.wait_for(
                run_gungnir(domains, cap),
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
    try:
        import deployment_policy
    except ModuleNotFoundError:  # package import (api.gungnir_worker)
        from . import deployment_policy
    # A malformed destination setting stops this worker as it stops the API and scan workers.
    deployment_policy.require_valid_destination_settings()
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

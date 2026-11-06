"""Target liveness: does a target's name resolve, does a port open, does the service answer.

One row per Targets-list asset (``target_liveness``), written by a bounded check and read by the
inventory (column, filter, facets) and the target page. docs/target-liveness.md describes the
product behaviour; this module is its implementation:

* ``plan_check`` reads what a check may touch: the asset's host, its web apps' ports, its port
  hints and the ports a network scan found open (at most ``MAX_PORTS``), and whether the target's
  scope is blocked or archived.
* ``run_check`` resolves the name once, keeps the addresses the destination policy admits for the
  target's environment, and connects to those addresses only, by address. A web port is asked
  ``GET /`` (TLS where the scheme or port says so); another port is only read for a banner. Only
  the HTTP status code of an answer is kept; headers, bodies, banners and certificates never are.
* ``liveness_tick`` checks the due assets (never checked, asked for, a new web app since the last
  check, or the schedule) a bounded batch at a time, in the API process that leads the loop.

Scan submissions ask for a fresh check through a trigger on ``scans``, so every way a Scan is
submitted (Targets page, API, client, schedules, Hunt) counts as "before a Scan".
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import ipaddress
import json
import re
import ssl
import time
from typing import Any, Awaitable, Callable, Mapping, Sequence
import urllib.parse
import uuid

try:
    import target_authorization
    import target_resolution
    from target_address_policy import normalize_frozen_addresses
except ModuleNotFoundError:  # package-native import layout
    from .. import target_authorization, target_resolution
    from ..target_address_policy import normalize_frozen_addresses

SCHEMA_VERSION = "target-liveness/v1"

LIVE = "live"
REACHABLE = "reachable"
UNREACHABLE = "unreachable"
NO_DNS = "no_dns"
DNS_ERROR = "dns_error"
BLOCKED = "blocked"
UNCHECKED = "unchecked"
STATUSES = (LIVE, REACHABLE, UNREACHABLE, NO_DNS, DNS_ERROR, BLOCKED, UNCHECKED)

DNS_RESOLVES = "resolves"
DNS_NO_RECORD = "no_record"
DNS_ERROR_STATE = "error"

TRIGGERS = ("add", "pre_scan", "schedule", "manual")

# Budgets (docs/target-liveness.md "Limits").
MAX_PORTS = 4
MAX_ADDRESSES_PER_PORT = 2
MAX_STORED_ADDRESSES = 8
DNS_TIMEOUT_SECONDS = 3.0
CONNECT_TIMEOUT_SECONDS = 3.0
ANSWER_TIMEOUT_SECONDS = 5.0
CHECK_TIMEOUT_SECONDS = 15.0
READ_LIMIT_BYTES = 1024
# Scheduling.
RECHECK_SECONDS = 12 * 3600
DNS_ERROR_RECHECK_SECONDS = 3600
PRE_SCAN_FRESH_SECONDS = 600
MANUAL_FRESH_SECONDS = 30
TICK_INTERVAL_SECONDS = 20.0
TICK_BATCH = 64
TICK_CONCURRENCY = 16
TICK_TIMEOUT_SECONDS = 120.0
CLAIM_SECONDS = 300
MANUAL_CONCURRENCY = 4

WEB_PORTS = {80: "http", 8080: "http", 443: "https", 8443: "https"}
USER_AGENT = "ShakerScan-Liveness/1"
_STATUS_LINE = re.compile(rb"^HTTP/\d(?:\.\d)? (\d{3})(?: |\r|\n|$)")

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS target_liveness (
    target_id UUID PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'unchecked'
        CHECK (status IN ({", ".join(f"'{status}'" for status in STATUSES)})),
    dns TEXT CHECK (dns IN ('resolves', 'no_record', 'error')),
    reachable BOOLEAN,
    live BOOLEAN,
    addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
    ports JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason TEXT CHECK (char_length(reason) <= 1000),
    trigger TEXT CHECK (trigger IN ({", ".join(f"'{name}'" for name in TRIGGERS)})),
    checked_at TIMESTAMPTZ,
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_at TIMESTAMPTZ,
    requested_by TEXT CHECK (requested_by IN ({", ".join(f"'{name}'" for name in TRIGGERS)})),
    claimed_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_target_liveness_status ON target_liveness(status);
CREATE INDEX IF NOT EXISTS idx_target_liveness_next_check ON target_liveness(next_check_at);

-- Before a Scan: a submitted Scan asks for a fresh check of its target's asset when the last
-- one is older than {PRE_SCAN_FRESH_SECONDS} s. Statement-level, from the inserted rows only.
CREATE OR REPLACE FUNCTION target_liveness_scan_requested() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO target_liveness(target_id, requested_at, requested_by)
    SELECT DISTINCT COALESCE(t.asset_owner_id, t.id), now(), 'pre_scan'
    FROM new_scans s JOIN targets t ON t.id = s.target_id
    WHERE COALESCE(s.scan_role, '') <> 'shard'
    ON CONFLICT (target_id) DO UPDATE SET requested_at = now(), requested_by = 'pre_scan', updated_at = now()
    WHERE target_liveness.requested_at IS NULL
      AND (target_liveness.checked_at IS NULL
           OR target_liveness.checked_at < now() - interval '{PRE_SCAN_FRESH_SECONDS} seconds');
    RETURN NULL;
END $$;
"""
_SCAN_TRIGGER = ("target_liveness_scan_requested",
                 """CREATE TRIGGER target_liveness_scan_requested AFTER INSERT ON scans
                    REFERENCING NEW TABLE AS new_scans FOR EACH STATEMENT
                    EXECUTE FUNCTION target_liveness_scan_requested()""")


async def install_target_liveness(conn: Any) -> None:
    """Create the table, its function and the scans trigger (only when missing: a restart takes
    no lock on ``scans``). Runs inside the startup transaction."""
    await conn.execute(SCHEMA_SQL)
    name, ddl = _SCAN_TRIGGER
    exists = await conn.fetchval(
        "SELECT 1 FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'scans'::regclass AND tgname = $1", name)
    if not exists:
        await conn.execute(ddl)


# --- What a check may touch ---------------------------------------------------------------------


@dataclass(frozen=True)
class PortPlan:
    port: int
    mode: str  # "https", "http" or "tcp"


@dataclass
class CheckPlan:
    target_id: uuid.UUID
    host: str
    environment: str
    ports: list[PortPlan] = field(default_factory=list)
    blocked_reason: str | None = None
    inactive: bool = False


def _mode_for(port: int, service_name: Any = None) -> str:
    name = str(service_name or "").lower()
    if "https" in name or "ssl/http" in name or name == "ssl":
        return "https"
    if "http" in name:
        return "http"
    return WEB_PORTS.get(port, "tcp")


def _origin_port(url: str) -> PortPlan | None:
    try:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
        port = parsed.port
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return None
    return PortPlan(port or (443 if scheme == "https" else 80), scheme)


def choose_ports(origin_urls: Sequence[str], hints: Sequence[Any],
                 services: Sequence[Mapping[str, Any]]) -> list[PortPlan]:
    """Web apps first, then port hints, then ports a network scan found open; 443 and 80 when
    nothing is known. At most ``MAX_PORTS``, one entry per port (a web app's scheme wins)."""
    chosen: dict[int, PortPlan] = {}

    def add(plan: PortPlan | None) -> None:
        if plan is not None and plan.port not in chosen and len(chosen) < MAX_PORTS:
            chosen[plan.port] = plan
    for url in origin_urls:
        add(_origin_port(url))
    for hint in hints if isinstance(hints, (list, tuple)) else ():
        if type(hint) is int and 1 <= hint <= 65535:
            add(PortPlan(hint, _mode_for(hint)))
    for service in services:
        port = service.get("port")
        if type(port) is int and 1 <= port <= 65535:
            add(PortPlan(port, _mode_for(port, service.get("service_name"))))
    if not chosen:
        add(PortPlan(443, "https"))
        add(PortPlan(80, "http"))
    return list(chosen.values())


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


async def asset_id_for(conn: Any, target_id: Any) -> uuid.UUID | None:
    """The Targets-list asset a target belongs to (itself, or its owning host)."""
    try:
        identifier = uuid.UUID(str(target_id))
    except (TypeError, ValueError):
        return None
    row = await conn.fetchrow("SELECT id, asset_owner_id FROM targets WHERE id=$1", identifier)
    if row is None:
        return None
    return row["asset_owner_id"] or row["id"]


async def plan_check(conn: Any, asset_id: uuid.UUID) -> CheckPlan | None:
    row = await conn.fetchrow("""SELECT t.id, t.url, t.is_active, t.metadata_json,
            target_asset_locator(t.url) AS locator
        FROM targets t WHERE t.id=$1""", asset_id)
    if row is None:
        return None
    metadata = _json(row["metadata_json"]) or {}
    metadata = metadata if isinstance(metadata, Mapping) else {}
    environment = target_authorization.effective_target_environment(metadata)
    host = str(row["locator"] or "").strip().lower().strip("[]").rstrip(".")
    members = await conn.fetch("""SELECT url FROM targets WHERE asset_owner_id=$1 AND is_active
        AND url ~* '^https?://' ORDER BY created_at, id LIMIT 16""", asset_id)
    origins = [str(row["url"])] + [str(member["url"]) for member in members]
    services = await conn.fetch("""SELECT port, service_name FROM device_services
        WHERE target_id=$1 AND state='open' AND COALESCE(transport,'tcp')='tcp'
        ORDER BY last_seen_at DESC NULLS LAST, port LIMIT 16""", asset_id)
    plan = CheckPlan(target_id=asset_id, host=host, environment=environment,
                     ports=choose_ports(origins, metadata.get("port_hints") or [], [dict(s) for s in services]),
                     inactive=not row["is_active"])
    if not host:
        plan.blocked_reason = "the target has no host name or address to check"
        return plan
    refusal = await target_authorization.target_scope_refusal(conn, asset_id)
    if refusal:
        plan.blocked_reason = str(refusal.get("message") or "the target's scope is blocked")[:500]
    return plan


# --- The check ----------------------------------------------------------------------------------

Lookup = Callable[[str], Awaitable[list[str]]]


@dataclass
class _Port:
    port: int
    mode: str
    address: str | None = None
    tcp: str = "not_tried"  # open, refused, timeout, unreachable, error
    service: str | None = None  # "http" or "banner" when the service answered
    http_status: int | None = None
    note: str | None = None  # tls_failed, no_answer, not_http

    def public(self) -> dict[str, Any]:
        item: dict[str, Any] = {"port": self.port, "mode": self.mode, "address": self.address,
                                "tcp": self.tcp, "answered": self.service is not None}
        if self.http_status is not None:
            item["http_status"] = self.http_status
        if self.note:
            item["note"] = self.note
        return item


def _tcp_outcome(exc: BaseException) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError) and exc.errno in (101, 113, 51, 65):  # ENETUNREACH/EHOSTUNREACH (Linux, BSD)
        return "unreachable"
    return "error"


_TLS_CONTEXT: ssl.SSLContext | None = None


def _tls_context() -> ssl.SSLContext:
    """One client context for every check. Liveness asks whether a service answers, not whether
    its certificate is trusted, so nothing is verified and no trust store is loaded."""
    global _TLS_CONTEXT
    if _TLS_CONTEXT is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _TLS_CONTEXT = context
    return _TLS_CONTEXT


def _host_header(host: str, port: int, mode: str) -> str:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    shown = f"[{host}]" if literal is not None and literal.version == 6 else host
    default = 443 if mode == "https" else 80
    return shown if port == default else f"{shown}:{port}"


async def _read_some(reader: asyncio.StreamReader, timeout: float) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < READ_LIMIT_BYTES and b"\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(READ_LIMIT_BYTES - len(data)), remaining)
        except (asyncio.TimeoutError, TimeoutError):
            break
        if not chunk:
            break
        data += chunk
    return data[:READ_LIMIT_BYTES]


async def _probe_port(plan: PortPlan, host: str, addresses: Sequence[str]) -> _Port:
    result = _Port(plan.port, plan.mode)
    for address in addresses[:MAX_ADDRESSES_PER_PORT]:
        result.address = address
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, plan.port, limit=READ_LIMIT_BYTES * 4), CONNECT_TIMEOUT_SECONDS)
        except (OSError, asyncio.TimeoutError, TimeoutError) as exc:
            result.tcp = _tcp_outcome(exc)
            continue
        result.tcp = "open"
        try:
            await _ask_service(result, plan, host, reader, writer)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except Exception:  # noqa: BLE001 -- a peer that never closes is not our problem
                pass
        return result
    return result


async def _ask_service(result: _Port, plan: PortPlan, host: str,
                       reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    if plan.mode == "tcp":
        data = await _read_some(reader, ANSWER_TIMEOUT_SECONDS)
        if data:
            result.service = "banner"
        else:
            result.note = "no_answer"
        return
    if plan.mode == "https":
        try:
            server_name = None if _is_address(host) else host
            await asyncio.wait_for(writer.start_tls(_tls_context(), server_hostname=server_name),
                                   ANSWER_TIMEOUT_SECONDS)
        except (OSError, ssl.SSLError, asyncio.TimeoutError, TimeoutError, ValueError):
            result.note = "tls_failed"
            return
    request = (f"GET / HTTP/1.1\r\nHost: {_host_header(host, plan.port, plan.mode)}\r\n"
               f"User-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    try:
        writer.write(request.encode("ascii", "ignore"))
        await asyncio.wait_for(writer.drain(), ANSWER_TIMEOUT_SECONDS)
        data = await _read_some(reader, ANSWER_TIMEOUT_SECONDS)
    except (OSError, ssl.SSLError, asyncio.TimeoutError, TimeoutError):
        data = b""
    match = _STATUS_LINE.match(data)
    if match and 100 <= int(match.group(1)) <= 599:
        result.service = "http"
        result.http_status = int(match.group(1))
    else:
        result.note = "not_http" if data else "no_answer"


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


_TCP_WORDS = {"refused": "connection refused", "timeout": f"no connection within {CONNECT_TIMEOUT_SECONDS:g} s",
              "unreachable": "no route to the address", "error": "connection failed"}


def _port_reason(item: _Port) -> str:
    if item.tcp != "open":
        return f"port {item.port}: {_TCP_WORDS.get(item.tcp, 'not tried')}"
    if item.note == "tls_failed":
        return f"port {item.port}: connected, TLS handshake failed"
    if item.note == "not_http":
        return f"port {item.port}: connected, the answer was not HTTP"
    what = "HTTP" if item.mode in ("http", "https") else "a banner"
    return f"port {item.port}: connected, no {what} answer within {ANSWER_TIMEOUT_SECONDS:g} s"


def _result(status: str, *, dns: str | None, addresses: Sequence[str] = (), ports: Sequence[_Port] = (),
            reason: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION, "status": status, "dns": dns,
        "reachable": None if status in (NO_DNS, DNS_ERROR, BLOCKED) else any(p.tcp == "open" for p in ports),
        "live": None if status in (NO_DNS, DNS_ERROR, BLOCKED) else any(p.service for p in ports),
        "addresses": list(addresses)[:MAX_STORED_ADDRESSES],
        "ports": [port.public() for port in ports],
        "reason": (reason or None) and str(reason)[:1000],
    }


async def run_check(plan: CheckPlan, *, lookup: Lookup | None = None) -> dict[str, Any]:
    """Check one asset within its budgets; never raises for anything the target does."""
    if plan.inactive:
        return _result(BLOCKED, dns=None, reason="the target is archived")
    if plan.blocked_reason:
        return _result(BLOCKED, dns=None, reason=plan.blocked_reason)
    status, addresses = await target_resolution.lookup_host(plan.host, lookup=lookup, timeout=DNS_TIMEOUT_SECONDS)
    if status == target_resolution.NO_ADDRESS:
        return _result(NO_DNS, dns=DNS_NO_RECORD, reason=f"{plan.host[:253]} has no address record")
    if status != target_resolution.RESOLVES:
        return _result(DNS_ERROR, dns=DNS_ERROR_STATE,
                       reason=f"the resolver did not answer for {plan.host[:253]} within {DNS_TIMEOUT_SECONDS:g} s")
    try:
        ordered = list(normalize_frozen_addresses(addresses[:64]))
    except ValueError:
        ordered = []
    admit = target_resolution.policy_admits(plan.environment)
    admitted = [address for address in ordered if admit(address)]
    if not admitted:
        return _result(BLOCKED, dns=DNS_RESOLVES, addresses=ordered,
                       reason=f"every address of {plan.host[:253]} is outside the destination policy for "
                              f"the {plan.environment} environment; nothing was sent")
    probed = list(await asyncio.gather(*(_probe_port(port, plan.host, admitted) for port in plan.ports)))
    if any(item.service for item in probed):
        return _result(LIVE, dns=DNS_RESOLVES, addresses=ordered, ports=probed)
    state = REACHABLE if any(item.tcp == "open" for item in probed) else UNREACHABLE
    return _result(state, dns=DNS_RESOLVES, addresses=ordered, ports=probed,
                   reason="; ".join(_port_reason(item) for item in probed))


async def check_with_deadline(plan: CheckPlan, *, lookup: Lookup | None = None) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(run_check(plan, lookup=lookup), CHECK_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, TimeoutError):
        return _result(UNREACHABLE, dns=None,
                       reason=f"the check did not finish within {CHECK_TIMEOUT_SECONDS:g} s")


# --- Storage ------------------------------------------------------------------------------------


async def store_result(conn: Any, asset_id: uuid.UUID, result: Mapping[str, Any], trigger: str) -> None:
    recheck = DNS_ERROR_RECHECK_SECONDS if result["status"] == DNS_ERROR else RECHECK_SECONDS
    await conn.execute("""INSERT INTO target_liveness(target_id, status, dns, reachable, live, addresses, ports,
            reason, trigger, checked_at, next_check_at, requested_at, requested_by, claimed_until, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, now(), now() + make_interval(secs => $10),
                NULL, NULL, NULL, now())
        ON CONFLICT (target_id) DO UPDATE SET status=EXCLUDED.status, dns=EXCLUDED.dns,
            reachable=EXCLUDED.reachable, live=EXCLUDED.live, addresses=EXCLUDED.addresses,
            ports=EXCLUDED.ports, reason=EXCLUDED.reason, trigger=EXCLUDED.trigger,
            checked_at=EXCLUDED.checked_at, next_check_at=EXCLUDED.next_check_at,
            requested_at=NULL, requested_by=NULL, claimed_until=NULL, updated_at=now()""",
                       asset_id, result["status"], result.get("dns"), result.get("reachable"), result.get("live"),
                       json.dumps(result.get("addresses") or []), json.dumps(result.get("ports") or []),
                       result.get("reason"), trigger if trigger in TRIGGERS else "schedule", float(recheck))


def public_liveness(row: Mapping[str, Any] | None) -> dict[str, Any]:
    """The ``liveness`` object of an inventory row or asset detail (``liveness_*`` columns)."""
    row = row or {}
    status = row.get("liveness_status") or UNCHECKED
    checked_at = row.get("liveness_checked_at")
    return {
        "status": status if status in STATUSES else UNCHECKED,
        "dns": row.get("liveness_dns"),
        "reachable": row.get("liveness_reachable"),
        "live": row.get("liveness_live"),
        "reason": row.get("liveness_reason"),
        "checked_at": checked_at.isoformat() if hasattr(checked_at, "isoformat") else checked_at,
        "trigger": row.get("liveness_trigger"),
        "addresses": _json(row.get("liveness_addresses")) or [],
        "ports": _json(row.get("liveness_ports")) or [],
    }


LIVENESS_COLUMNS = """lv.status AS liveness_status,lv.dns AS liveness_dns,lv.reachable AS liveness_reachable,
    lv.live AS liveness_live,lv.reason AS liveness_reason,lv.checked_at AS liveness_checked_at,
    lv.trigger AS liveness_trigger,lv.addresses AS liveness_addresses,lv.ports AS liveness_ports"""
LIVENESS_JOIN = "LEFT JOIN target_liveness lv ON lv.target_id=t.id"
LIVENESS_STATUS = "COALESCE(lv.status,'unchecked')"


# --- The loop -----------------------------------------------------------------------------------

_ASSET_WHERE = ("t.asset_owner_id IS NULL AND t.is_active "
                "AND COALESCE(t.discovery_source,'manual') <> 'model-intake'")
CLAIM_SQL = f"""WITH due AS (
    SELECT t.id, lv.requested_by, lv.checked_at
    FROM targets t LEFT JOIN target_liveness lv ON lv.target_id=t.id
    WHERE {_ASSET_WHERE}
      AND (lv.claimed_until IS NULL OR lv.claimed_until < now())
      AND (lv.target_id IS NULL OR lv.checked_at IS NULL OR lv.requested_at IS NOT NULL
           OR lv.next_check_at <= now()
           OR EXISTS (SELECT 1 FROM targets m WHERE m.asset_owner_id=t.id AND m.is_active
                      AND m.created_at > lv.checked_at))
    ORDER BY (lv.requested_at IS NULL), lv.checked_at NULLS FIRST, lv.next_check_at, t.id
    LIMIT $1
)
INSERT INTO target_liveness(target_id, claimed_until)
SELECT id, now() + make_interval(secs => $2) FROM due
ON CONFLICT (target_id) DO UPDATE SET claimed_until = EXCLUDED.claimed_until
RETURNING target_id, requested_by, checked_at"""


async def claim_due(conn: Any, limit: int = TICK_BATCH) -> list[tuple[uuid.UUID, str]]:
    rows = await conn.fetch(CLAIM_SQL, limit, float(CLAIM_SECONDS))
    claimed = []
    for row in rows:
        trigger = row["requested_by"] or ("add" if row["checked_at"] is None else "schedule")
        claimed.append((row["target_id"], trigger))
    return claimed


async def check_asset(pool: Any, asset_id: uuid.UUID, trigger: str, *,
                      lookup: Lookup | None = None) -> dict[str, Any] | None:
    async with pool.acquire() as conn:
        plan = await plan_check(conn, asset_id)
    if plan is None:
        return None
    result = await check_with_deadline(plan, lookup=lookup)
    async with pool.acquire() as conn:
        if await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", asset_id):
            await store_result(conn, asset_id, result, trigger)
    return result


async def liveness_tick(pool: Any, *, lookup: Lookup | None = None, batch: int = TICK_BATCH,
                        concurrency: int = TICK_CONCURRENCY) -> int:
    async with pool.acquire() as conn:
        claimed = await claim_due(conn, batch)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(asset_id: uuid.UUID, trigger: str) -> None:
        async with semaphore:
            try:
                await check_asset(pool, asset_id, trigger, lookup=lookup)
            except Exception as exc:  # noqa: BLE001 -- one target never stops the round
                print(f"[liveness] {asset_id} check failed: {type(exc).__name__}", flush=True)
    await asyncio.gather(*(one(asset_id, trigger) for asset_id, trigger in claimed))
    return len(claimed)


async def target_liveness_runner(pool: Any) -> None:
    """The API's led loop: one process checks the due targets every interval."""
    try:
        from loop_leader import run_led_loop
    except ModuleNotFoundError:
        from ..loop_leader import run_led_loop
    await run_led_loop(pool, "target_liveness_runner", lambda: liveness_tick(pool),
                       interval=TICK_INTERVAL_SECONDS, timeout=TICK_TIMEOUT_SECONDS)


# --- Check now ----------------------------------------------------------------------------------

_manual = asyncio.Semaphore(MANUAL_CONCURRENCY)


async def check_now(pool: Any, target_id: Any) -> dict[str, Any] | None:
    """Run the check for ``target_id``'s asset now; a check younger than ``MANUAL_FRESH_SECONDS``
    is returned instead. None when the target does not exist."""
    async with pool.acquire() as conn:
        asset_id = await asset_id_for(conn, target_id)
        if asset_id is None:
            return None
        recent = await conn.fetchval("""SELECT 1 FROM target_liveness WHERE target_id=$1
            AND checked_at > now() - make_interval(secs => $2)""", asset_id, float(MANUAL_FRESH_SECONDS))
    checked = False
    if not recent:
        async with _manual:
            await check_asset(pool, asset_id, "manual")
        checked = True
    async with pool.acquire() as conn:
        row = await conn.fetchrow(f"SELECT {LIVENESS_COLUMNS} FROM targets t {LIVENESS_JOIN} WHERE t.id=$1", asset_id)
    return {"target_id": str(asset_id), "checked": checked, "liveness": public_liveness(row)}


# --- Reach of one origin (retest) ---------------------------------------------------------------


async def origin_reach(url: str, *, environment: str = "production",
                       lookup: Lookup | None = None) -> tuple[bool, str]:
    """Whether this process reaches ``url``'s origin now: one TCP connection and an HTTP answer
    (any status) to ``GET /``, with the liveness budgets and the destination policy of
    ``environment``. Returns ``(reached, reason)``; the reason says what was seen either way.

    A retest uses it before it reads a non-reproduction on a private address as "fixed": nothing
    reproduced proves nothing when the request never reached the application."""
    target = _origin_port(url)
    try:
        host = (urllib.parse.urlsplit(str(url or "").strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if target is None or not host:
        return False, "the finding has no HTTP origin to reach"
    plan = CheckPlan(target_id=uuid.uuid4(), host=host, environment=environment, ports=[target])
    try:
        result = await asyncio.wait_for(run_check(plan, lookup=lookup), CHECK_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, TimeoutError):
        return False, f"the reach check of {host[:253]} did not finish within {CHECK_TIMEOUT_SECONDS:g} s"
    origin = f"{target.mode}://{host[:253]}:{target.port}"
    if result["status"] == LIVE:
        status = (result["ports"][0] or {}).get("http_status")
        return True, f"{origin} answered HTTP {status}"
    return False, f"{origin} was not reached: {result.get('reason') or result['status']}"

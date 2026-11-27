"""Pacing reads the Scan's own request archive; the target's traffic record lists every run (PostgreSQL).

A host that answers 503 on every path pauses the Scan's tools instead of being hit at full rate,
only that origin's answers count, the decision is kept in ``execution_context.target_pacing``,
and ``GET /targets/{id}/traffic`` lists each Scan and Hunt that sent it requests. Lab addresses
only; nothing is contacted. Requires ``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from runtime import target_pacing  # noqa: E402
from targets.traffic import target_traffic  # noqa: E402
from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
ORIGIN = "http://10.10.10.150:8081"


async def _answers(conn, *, scan=None, hunt=None, target, url, status, count, error=None, ago=10):
    for index in range(count):
        await conn.execute(
            """INSERT INTO http_transactions(plane, sequence, scan_id, hunt_run_id, target_id, method,
                   url, status_code, elapsed_ms, error, remote_ip, started_at)
               VALUES ($1, $2, $3, $4, $5, 'GET', $6, $7, 40, $8, '10.10.10.150',
                       NOW() - make_interval(secs => $9))""",
            "scan" if scan else "hunt", index, scan, hunt, target, url, status, error, float(ago + index))


def test_a_host_answering_503_everywhere_pauses_only_its_own_origin(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
                scan = await conn.fetchval(
                    "INSERT INTO scans(target_id, target_url, status) VALUES($1, $2, 'running') RETURNING id",
                    target, ORIGIN)
                await _answers(conn, scan=scan, target=target, url=f"{ORIGIN}/", status=200, count=3, ago=900)
                await _answers(conn, scan=scan, target=target, url=f"{ORIGIN}/a?x=1", status=503, count=20)
                # Another origin of the same Scan answers well; it does not dilute the window.
                await _answers(conn, scan=scan, target=target, url="http://10.10.10.150:9000/",
                               status=200, count=30)

                decision = await target_pacing.origin_pacing(conn, scan, f"{ORIGIN}/search?q=1")
                assert decision.state == "paused" and decision.samples == 20
                healthy = await target_pacing.origin_pacing(conn, scan, "http://10.10.10.150:9000/")
                assert healthy.state == "normal"

                await target_pacing.record(conn, scan, ORIGIN, decision, outcome="paused")
                await target_pacing.record(conn, scan, ORIGIN, decision, outcome="stopped")
                context = json.loads(await conn.fetchval("SELECT execution_context::text FROM scans WHERE id=$1", scan))
                origin = context["target_pacing"][ORIGIN]
                assert origin["state"] == "paused" and origin["attempts_paused"] == 1
                assert origin["attempts_stopped"] == 1 and "of the last 20 answers" in origin["reason"]

                # The answers age out of the five-minute window: the origin is judged afresh.
                await conn.execute("UPDATE http_transactions SET started_at = started_at - interval '10 minutes'")
                assert (await target_pacing.origin_pacing(conn, scan, ORIGIN)).state == "normal"

                hunt = await conn.fetchval(
                    "INSERT INTO hunt_runs(target_kind, target_id) VALUES('web', $1) RETURNING id", target)
                await _answers(conn, hunt=hunt, target=target, url=f"{ORIGIN}/", status=429, count=2)
                runs = {item["run"]: item for item in await target_traffic(conn, target)}
                assert runs[f"scan:{scan}"]["requests"] == 53
                assert runs[f"scan:{scan}"]["degraded_answers"] == 20
                assert runs[f"hunt:{hunt}"]["degraded_answers"] == 2
                assert runs[f"hunt:{hunt}"]["target_addresses"] == ["10.10.10.150"]
    asyncio.run(run())

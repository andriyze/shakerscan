"""``query(kind="receipts")`` names the action behind each receipt and why a failed one failed (PostgreSQL).

The actual FastAPI app, startup migrations, Hunt admission and the Hunt query route. The receipt and
action rows are fixture rows (identified where they are written) standing in for what the Hunt
capability route records when a request succeeds and when it never gets a response.

A failed receipt row used to carry only its own id, tool, status and arguments, so a planner could
not tell which of its calls it was or whether the target refused, timed out or never answered.
"""
import asyncio
import json
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database

SECRET = 'sk_live_' + 'Q' * 32


async def _settled(conn, hunt_id, target, *, status, result, receipt_status, metadata_action=True,
                   parser_errors=None):
    """Fixture: one settled Hunt action and the tool receipt the capability route records for it."""
    action, receipt = uuid4(), uuid4()
    metadata = {'durable_budget_reservation_id': 'fixture'}
    if metadata_action:
        metadata['hunt_action_id'] = str(action)
    if parser_errors is not None:
        metadata['parser_errors'] = parser_errors
    await conn.execute(
        """INSERT INTO tool_receipts(id, tool_name, adapter_version, command_hash, redacted_argv,
               target_scope, status, metadata_json, hunt_id)
           VALUES($1,'http_request','1',$2,'[{"method":"GET","path":"/health"}]'::jsonb,$3::jsonb,$4,$5::jsonb,$6)""",
        receipt, uuid4().hex, json.dumps({'target_kind': 'web', 'target_id': str(target)}),
        receipt_status, json.dumps(metadata), UUID(hunt_id))
    await conn.execute(
        """INSERT INTO hunt_actions(id, hunt_run_id, capability_name, status, result_summary, receipt_id, completed_at)
           VALUES($1,$2,'http.request',$3,$4::jsonb,$5,NOW())""",
        action, UUID(hunt_id), status, json.dumps(result), receipt)
    return str(action), str(receipt)


def test_receipt_rows_carry_the_action_and_the_bounded_error_of_a_failed_call(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.receipts.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                ok_action, ok_receipt = await _settled(
                    conn, hunt.id, target, status='completed', receipt_status='success',
                    result={'ok': True, 'response': {'status': 200, 'body_sample': 'fine'}})
                refused_action, refused_receipt = await _settled(
                    conn, hunt.id, target, status='failed', receipt_status='failed',
                    result={'ok': False, 'error': 'request_error:ConnectError',
                            'request': {'method': 'GET', 'path': '/health'}})
                # A receipt recorded without the action id in its metadata is still linked by the
                # action's receipt_id; its error, long and carrying a secret, comes back bounded.
                linked_action, linked_receipt = await _settled(
                    conn, hunt.id, target, status='failed', receipt_status='failed', metadata_action=False,
                    result={'ok': False, 'error': f'scope: refused with key {SECRET} ' + 'x' * 600})
                parser_action, parser_receipt = await _settled(
                    conn, hunt.id, target, status='failed', receipt_status='parser_error',
                    result={'ok': False}, parser_errors=['unexpected end of JSON input'])
                response = await operator.post(f'/hunts/{hunt.id}/query', json={'kind': 'receipts', 'limit': 50})
                assert response.status_code == 200, response.text
                rows = {row['id']: row for row in response.json()['rows']}

        assert set(rows) >= {ok_receipt, refused_receipt, linked_receipt, parser_receipt}
        assert rows[ok_receipt]['action_id'] == ok_action and 'error' not in rows[ok_receipt]
        assert rows[refused_receipt]['action_id'] == refused_action
        assert rows[refused_receipt]['error'] == 'request_error:ConnectError'
        assert rows[linked_receipt]['action_id'] == linked_action
        linked_error = rows[linked_receipt]['error']
        assert linked_error.startswith('scope: refused with key') and SECRET not in linked_error
        assert len(linked_error) <= 240
        assert rows[parser_receipt]['action_id'] == parser_action
        assert rows[parser_receipt]['error'] == 'unexpected end of JSON input'
        for row in rows.values():
            # The raw receipt metadata and any response content stay out of the page.
            assert 'metadata_json' not in row and 'body_sample' not in json.dumps(row)
    asyncio.run(run())


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))

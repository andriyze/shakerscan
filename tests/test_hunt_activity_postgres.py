"""query kind=activity against real PostgreSQL: a planner waits for a change instead of polling.

The actual app, startup migrations, Hunt admission, the capability route and the Hunt query route.
Actions inserted directly are fixture rows: the ledger record of something that settled.
"""
import asyncio
import json
import time
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from api.hunt.activity import ActivityQueryError, decode_cursor, encode_cursor, parse_filters
from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _settle(conn, hunt, status='completed', capability='http.request'):
    """Fixture: an action of this Hunt settling now, as the action ledger records it."""
    action = uuid4()
    await conn.execute("""INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,completed_at)
        VALUES($1,$2,$3,$4,clock_timestamp())""", action, UUID(hunt.id), capability, status)
    return str(action)


def test_a_cursor_round_trips_and_only_the_servers_own_is_accepted():
    after, seen = decode_cursor(encode_cursor(decode_cursor(encode_cursor(
        __import__('datetime').datetime(2026, 11, 17, tzinfo=__import__('datetime').timezone.utc), ['a:1']))[0], ['a:1', 'l:2:3']))
    assert after.isoformat() == '2026-11-17T00:00:00+00:00' and seen == frozenset({'a:1', 'l:2:3'})
    for bad in ('', 'not-a-cursor', 'e30', 7, 'x' * 9000):
        with pytest.raises(ActivityQueryError):
            decode_cursor(bad)
    for filters in ({'since': 'x'}, {'wait_seconds': 16}, {'wait_seconds': True}, {'after': 'nope'}):
        with pytest.raises(ActivityQueryError):
            parse_filters(filters)
    assert parse_filters({}) == (None, 0)
    # A wait without after waits from now; agents asked for it first and were refused.
    assert parse_filters({'wait_seconds': 5}) == (None, 5)


def test_a_hunt_waits_for_its_actions_and_its_targets_leads_and_hears_each_change_once(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.activity.test')
            other = await _web_target(conn, 'https://other.activity.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                peer = (await _hunt(operator, target)).hunt
                stranger = (await _hunt(operator, other)).hunt

                async def activity(asker=hunt, **filters):
                    response = await operator.post(f'/hunts/{asker.id}/query',
                                                   json={'kind': 'activity', 'filter': filters})
                    assert response.status_code == 200, response.text
                    return response.json()

                # The first read is a baseline: a cursor, nothing reported as new.
                await _settle(conn, hunt)
                start = await activity()
                assert start['changed'] is False and start['actions'] == [] and start['waited'] is False
                cursor = start['cursor']

                # Nothing happens: the wait is honoured and returns unchanged.
                began = time.monotonic()
                quiet = await activity(after=cursor, wait_seconds=1)
                assert quiet['changed'] is False and quiet['waited'] is True and time.monotonic() - began >= 0.9

                # This Hunt's action settles, a peer moves a lead on the shared target, and unrelated
                # things happen elsewhere. Only the first two reach this Hunt.
                mine = await _settle(conn, hunt, status='failed', capability='xss.verify')
                await _settle(conn, peer)
                await _settle(conn, stranger)
                lead = (await peer.ok('hypothesis.propose', {
                    'family': 'bola', 'title': 'A title that must not travel in activity',
                    'dedupe_dimensions': {'route': '/api/orders/{id}'}}))['result']['hypothesis']
                await stranger.ok('hypothesis.propose', {
                    'family': 'sqli', 'title': 'Elsewhere', 'dedupe_dimensions': {'route': '/x'}})
                began = time.monotonic()
                woke = await activity(after=cursor, wait_seconds=15)
                assert woke['changed'] is True and time.monotonic() - began < 5
                assert [(item['action_id'], item['capability'], item['status']) for item in woke['actions']] == [
                    (mine, 'xss.verify', 'failed')]
                assert [(item['hypothesis_id'], item['status'], item['held_by_this_hunt']) for item in woke['leads']] == [
                    (lead['id'], 'open', False)]
                # Ids and states only.
                assert 'must not travel' not in json.dumps(woke) and '/api/orders' not in json.dumps(woke)

                # The same change is not reported twice, even though the cursor overlaps in time.
                again = await activity(after=woke['cursor'])
                assert again['changed'] is False and again['actions'] == [] and again['leads'] == []

                # A later move of the same lead is a new change; holding it is visible.
                await hunt.ok('hypothesis.claim', {'hypothesis_id': lead['id'], 'expected_version': lead['version']})
                moved = await activity(after=again['cursor'], wait_seconds=10)
                assert [(item['hypothesis_id'], item['status'], item['held_by_this_hunt']) for item in moved['leads']] == [
                    (lead['id'], 'claimed', True)]
                # The capability call that claimed it settled too, and is this Hunt's own action.
                assert [item['capability'] for item in moved['actions']] == ['hypothesis.claim']

                # Waiting without a cursor waits from now and hands back a cursor.
                began = time.monotonic()
                fresh = await activity(wait_seconds=1)
                assert fresh['waited'] is True and fresh['changed'] is False and fresh['cursor']
                assert time.monotonic() - began >= 0.9

                # ...and hears what happens during it: an action settling one second in.
                async def settle_later():
                    await asyncio.sleep(1)
                    return await _settle(conn, hunt, capability='sqli.verify')
                waited, later = await asyncio.gather(activity(wait_seconds=10), settle_later())
                assert waited['changed'] is True
                assert [item['action_id'] for item in waited['actions']] == [later]
                for bad in ({'after': 'not-a-cursor'}, {'since': 'release'}):
                    refused = await operator.post(f'/hunts/{hunt.id}/query', json={'kind': 'activity', 'filter': bad})
                    assert refused.status_code == 422, (bad, refused.text)
    asyncio.run(run())

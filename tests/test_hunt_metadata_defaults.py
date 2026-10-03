"""Metadata is free by default; secret trust and explicit opt-outs are independent."""
import uuid

import pytest
from fastapi import HTTPException
from targets.hunt_authority import authority_from_row, authority_row


def test_default_metadata_freedom_does_not_grant_sharing_or_ssh_trust():
    row = {'id':uuid.uuid4(), 'url':'host://tv.local', 'is_active':True, 'metadata_json':{}}
    settings = authority_from_row(row)
    assert settings['metadata_changes'] is True
    assert settings['credential_profile_ids'] == settings['collection_ids'] == settings['ssh_host_keys'] == []
    assert settings['ssh_trust_first_contact'] is False


def test_saved_metadata_opt_out_and_asset_changes_remain_authoritative():
    row = {'id':uuid.uuid4(), 'url':'host://tv.local', 'is_active':True,
           'metadata_json':{'hunt_authority':{'target_url':'host://tv.local', 'metadata_changes':False}}}
    assert authority_from_row(row)['metadata_changes'] is False
    row['metadata_json']['hunt_authority']['metadata_changes'] = True
    assert authority_from_row(row)['metadata_changes'] is True
    row['url'] = 'host://different.local'
    assert authority_from_row(row)['metadata_changes'] is False
    assert authority_from_row({**row,'metadata_json':{},'is_active':False})['metadata_changes'] is False


@pytest.mark.asyncio
async def test_runtime_rejects_invalid_and_unknown_targets_without_router_imports():
    class Connection:
        async def fetchval(self, *args): return None
        async def fetchrow(self, *args): return None
    with pytest.raises(HTTPException) as bad:
        await authority_row(Connection(), 'not-a-uuid')
    assert bad.value.status_code == 400
    with pytest.raises(HTTPException) as missing:
        await authority_row(Connection(), uuid.uuid4())
    assert missing.value.status_code == 404

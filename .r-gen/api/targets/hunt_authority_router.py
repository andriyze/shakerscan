"""Operator routes for target Hunt settings; never imported by installed executors."""
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from .asset_router import pool
from .hunt_authority import authority_from_row, authority_row, read_hunt_authority, save_authority

router = APIRouter(tags=['targets'])

class SshHostKey(BaseModel):
    model_config = ConfigDict(extra='forbid')
    port: StrictInt = Field(ge=1, le=65535)
    fingerprint: str = Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')


class HuntAuthorityWrite(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: StrictInt = Field(ge=0)
    metadata_changes: StrictBool = True
    # Off unless the operator sends true: Hunts propose instruction changes instead.
    instruction_changes: StrictBool = False
    credential_profile_ids: list[UUID] = Field(default_factory=list, max_length=64)
    collection_ids: list[UUID] = Field(default_factory=list, max_length=64)
    ssh_host_keys: list[SshHostKey] = Field(default_factory=list, max_length=32)
    ssh_trust_first_contact: StrictBool = False


@router.get('/targets/{target_id}/hunt-authority')
async def get_hunt_authority(target_id: str):
    async with pool().acquire() as conn:
        return await read_hunt_authority(conn, target_id)


@router.put('/targets/{target_id}/hunt-authority')
async def put_hunt_authority(target_id: str, values: HuntAuthorityWrite, request: Request):
    async with pool().acquire() as conn, conn.transaction():
        row = await authority_row(conn, target_id, lock=True)
        current = authority_from_row(row)
        if current['revision'] != values.expected_revision:
            raise HTTPException(409, 'Hunt permissions changed. Reload before saving.')
        if not row['is_active']:
            raise HTTPException(409, 'Reactivate this target before delegating Hunt actions')
        if request.headers.get('x-shakerscan-decision-id') and values.instruction_changes and not current['instruction_changes']:
            # The step-up binds the instruction-edit decision. Other permission changes keep
            # their normal operator route and must not be silently bundled into its inverse.
            saved_values = {key: current[key] for key in
                ('metadata_changes','instruction_changes','credential_profile_ids','collection_ids',
                 'ssh_host_keys','ssh_trust_first_contact')}
            saved_values['ssh_host_keys'] = [
                {key: entry[key] for key in ('port', 'fingerprint')}
                for entry in saved_values['ssh_host_keys']
            ]
            expected = HuntAuthorityWrite(**saved_values, expected_revision=current['revision'])
            sent = values.model_dump(exclude={'expected_revision','instruction_changes'})
            unchanged = expected.model_dump(exclude={'expected_revision','instruction_changes'})
            if sent != unchanged:
                raise HTTPException(422, 'Save other Hunt-permission edits separately before enabling instruction edits')
            from .decision_receipts import receipt_request
            return await receipt_request(conn, request, target_id, 'allow_changes',
                expected_revision=values.expected_revision,
                perform=lambda identity: save_authority(conn, row,
                    {**current, 'instruction_changes': True, 'revision': current['revision'] + 1},
                    recorded_by=identity))
        for table, identifiers in [('credential_profiles', values.credential_profile_ids),
                                   ('request_collections', values.collection_ids)]:
            count = await conn.fetchval(f'SELECT count(*) FROM {table} WHERE id=ANY($1::uuid[]) AND is_active',
                                        list(set(identifiers)))
            if count != len(set(identifiers)):
                raise HTTPException(422, 'Select existing active profiles and collections')
        ports = [item.port for item in values.ssh_host_keys]
        if len(ports) != len(set(ports)):
            raise HTTPException(422, 'Save one SSH host key per port')
        document = values.model_dump(mode='json', exclude={'expected_revision'})
        document['revision'] = current['revision'] + 1
        # A server-authenticated identity may be supplied by a managed gateway in ASGI
        # scope. Ordinary OSS operator routes identify their provenance, not a person.
        actor = str(request.scope.get('shakerscan.operator_identity') or 'operator:target-permissions-api')
        saved = await save_authority(conn, row, document, recorded_by=actor)
        return authority_from_row({**dict(row), 'metadata_json': {'hunt_authority': saved}})

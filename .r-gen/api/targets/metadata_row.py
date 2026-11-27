"""Shared exact-target metadata row lookup, independent of document routers."""
from uuid import UUID
from fastapi import HTTPException


async def target_metadata_row(conn,target_id,*,lock=False):
    try:
        identifier=UUID(str(target_id))
    except (TypeError,ValueError,AttributeError) as exc:
        raise HTTPException(400,'Invalid target id') from exc
    row=await conn.fetchrow('SELECT id,metadata_json FROM targets WHERE id=$1'+
        (' FOR UPDATE' if lock else ''),identifier)
    if row is None:
        raise HTTPException(404,'Target not found')
    return row

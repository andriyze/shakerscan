"""Foreign-key retargeting for the compatibility migration."""
from __future__ import annotations
import re
from typing import Any

async def retarget_foreign_keys(conn: Any, old_table: str, new_table: str) -> None:
    if old_table not in {"device_targets", "device_credential_profiles", "device_request_collections"} or new_table not in {"targets", "credential_profiles", "request_collections"}:
        raise ValueError("unsupported foreign-key migration")
    keys = await conn.fetch("""SELECT conrelid::regclass::text AS relation, conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE contype='f' AND confrelid=$1::regclass""", old_table)
    for key in keys:
        definition = str(key["definition"])
        updated = definition.replace(f"REFERENCES {old_table}(id)", f"REFERENCES {new_table}(id)")
        if updated == definition:
            raise RuntimeError(f"unsupported foreign key referencing {old_table}")
        relation = str(key["relation"])
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", relation):
            raise RuntimeError("unexpected foreign-key relation name")
        name = str(key["conname"]).replace('"', '""')
        await conn.execute(f'ALTER TABLE {relation} DROP CONSTRAINT "{name}"')
        await conn.execute(f'ALTER TABLE {relation} ADD CONSTRAINT "{name}" {updated}')

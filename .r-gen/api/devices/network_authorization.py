"""Freeze reused asset authorization at admission and re-check it before network execution."""
from __future__ import annotations
from typing import Any

try:
    from target_authorization import current_target_authorization
except ModuleNotFoundError:
    from ..target_authorization import current_target_authorization


async def network_authorization_snapshot(conn: Any, target_id: Any) -> dict[str, Any] | None:
    current = await current_target_authorization(conn,target_id)
    if not current or not current.get('standing') or not current.get('approval_receipt_id'):
        return None
    return {'approval_receipt_id':str(current['approval_receipt_id']),
            'approved_by':str(current.get('approved_by') or '')}


async def revalidate_network_authorization(conn: Any, target_id: Any, options: dict[str, Any]) -> None:
    expected = options.get('asset_authorization_receipt_id')
    if not expected:
        return  # Per-scan operator confirmations retain their existing contract.
    current = await network_authorization_snapshot(conn,target_id)
    if not current or current['approval_receipt_id'] != str(expected):
        raise ValueError('Standing asset authorization changed or was revoked after the scan was queued')

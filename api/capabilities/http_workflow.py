"""Worker-only HTTP workflow operation; the canonical worker owns its ledger.

Keep supplied/captured credential values out of the worker's public input and
receipt construction. Normal HTTP observations retain their existing shape.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from runtime.hunt_http_contract import require_http_request_authority, uses_http_workflow
from runtime.hunt_http_exchange import HttpWorkflowExchange, prepare_http_exchange
from .http import execute_bound_http_request


async def prepare_http_operation(
    *, pool: Any, run: Mapping[str, Any], context: Mapping[str, Any], policy: Mapping[str, Any],
    action_id: Any, target: Any, target_url: str, inputs: Mapping[str, Any],
    trusted_headers: Mapping[str, str], principal_slot: str, requested_budget: Mapping[str, int],
    timeout_seconds: int, recorder: Callable[..., Any], revalidate: Callable[..., Any],
) -> tuple[Callable[..., Any], HttpWorkflowExchange, bool]:
    workflow = uses_http_workflow(inputs)
    require_http_request_authority(inputs, policy, requested_budget=requested_budget)
    exchange = HttpWorkflowExchange(str(run['id']), str(action_id), target, tuple(inputs.get('capture') or ()))
    injects_headers = bool(trusted_headers) or any('header' in item for item in inputs.get('request_bindings') or ())

    def record(captured: Mapping[str, Any]) -> None:
        recorder({**captured, "workflow_values_private": True} if workflow else captured)

    async def execute() -> dict[str, Any]:
        from runtime.credential_resolver import CredentialResolutionError
        from runtime.credential_refs import CredentialReferenceError
        wire_input, headers = {}, {}
        try:
            async with pool.acquire() as conn:
                owner = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", run['id'])
                if not owner or owner['status'] not in {'active', 'awaiting_planner', 'budget_exhausted'} or owner.get('completed_at'):
                    return {"ok": False, "error": "scope:Hunt stopped before HTTP dispatch"}
                try:
                    await revalidate(conn)
                    wire_input, headers, _ = await prepare_http_exchange(
                        conn, run=owner, action_id=action_id, target=target, context=context,
                        policy=policy, values=inputs, trusted_headers=trusted_headers, capture_state=exchange,
                    )
                except (ValueError, CredentialResolutionError, CredentialReferenceError) as exc:
                    return {"ok": False, "error": "http_workflow_preflight:" + str(exc)[:240]}
            response = await execute_bound_http_request(
                target_url, wire_input, target=target,
                allow_write=inputs['method'] in {'POST', 'PUT', 'PATCH', 'DELETE'},
                transaction_recorder=record, trusted_headers=headers,
                allow_identity_headers=bool(policy.get('allow_identity_headers')),
                direct_origin_addresses=tuple(policy.get('direct_origin_addresses') or ()),
                principal_slot="workflow_binding" if inputs.get("request_bindings") else principal_slot,
                timeout_seconds=timeout_seconds,
                allow_bound_origin_redirects=True, private_response_sink=exchange.capture_response,
                private_response_headers=exchange.response_headers,
            )
            if workflow:
                # Pairing values may be short PINs, arbitrary field names, or echoed
                # back under innocent keys. A heuristic scrubber is insufficient.
                summary = response.get('response')
                if isinstance(summary, Mapping):
                    response['response'] = {key: summary[key] for key in (
                        'status', 'content_length', 'bytes_observed', 'elapsed_ms',
                        'truncated', 'http_version',
                    ) if key in summary}
                    response['response']['workflow_values_visible'] = False
                response.pop('redirect_chain', None)
            if exchange.capture_error:
                response.update(ok=False, error=exchange.capture_error)
            return response
        finally:
            headers.clear()
            wire_input.clear()

    return execute, exchange, injects_headers

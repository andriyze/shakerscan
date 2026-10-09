"""Worker-only HTTP workflow operation; the canonical worker owns its ledger.

Keep supplied/captured credential values out of the worker's public input and
receipt construction. Normal HTTP observations retain their existing shape.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from runtime.hunt_http_contract import require_http_request_authority, uses_http_workflow
from runtime.hunt_http_exchange import HttpWorkflowExchange, prepare_http_exchange
from .http import execute_bound_http_request

try:
    from runtime.archive_body_masking import active_withheld_values
except ModuleNotFoundError:  # package import layout
    from api.runtime.archive_body_masking import active_withheld_values


_BOUND_VALUE_MARKER = "[withheld:bound]"


def _scrub_bound_values(value: Any, bound: list[str]) -> Any:
    """Withhold every echo of a bound value in every string of a public response: the body
    sample, ``location``, ``final_url``, redirect locations and selected headers, in any case,
    HTML/JSON/URL encoding or base64 (see ``KnownValueScrubber``). The body sample was already
    masked whole before it was cut, so no value is split by its end."""
    from runtime.archive_body_masking import KnownValueScrubber
    scrubber = KnownValueScrubber(sorted({str(item) for item in bound if item}))
    if not scrubber.values:
        return value

    def scrub(item: Any) -> Any:
        if isinstance(item, str):
            return scrubber.scrub(item, lambda _value: _BOUND_VALUE_MARKER)
        if isinstance(item, Mapping):
            return {scrub(key): scrub(nested) for key, nested in item.items()}
        if isinstance(item, (list, tuple)):
            return [scrub(nested) for nested in item]
        return item

    return scrub(value)


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
    bindings = tuple(inputs.get('request_bindings') or ())
    withheld_only = bool(bindings) and not inputs.get('capture') and all('withheld_ref' in item for item in bindings)

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
            collector = active_withheld_values()
            if collector is not None and withheld_only:
                # Every echo of a value sent by reference is withheld before any sample is cut.
                collector.bind_known(exchange.bound_values)
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
            if workflow and withheld_only:
                # Only withheld values (N56) were bound, and the worker knows each one exactly, so
                # the planner keeps the response it needs to judge access, with every bound value
                # replaced wherever the target echoes it.
                response = _scrub_bound_values(response, exchange.bound_values)
            elif workflow:
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
            exchange.bound_values.clear()

    return execute, exchange, injects_headers

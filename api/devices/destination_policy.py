"""Admission of a connected device's destination under the deployment's private-network policy.

The web plane refuses private, loopback and reserved targets outside a Lab environment when the
deployment sets ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse``. The device/network plane never
consulted that setting, so a refusing deployment still queued and scanned a private address
(the engine's own Docker network among them). Every device submission is admitted here before
it is queued, and the device worker re-checks the address it actually pins (DNS can answer
differently later) under the stricter of the admitting policy and its own.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException

try:
    import deployment_policy
    from scanner_tools.device_posture import (
        DEVICE_LAB_ENVIRONMENTS, PRIVATE_DESTINATION_REASON, device_private_destination_refusal,
        canonical_device_address, validate_device_destination,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from .. import deployment_policy
    from scanner.scanner_tools.device_posture import (
        DEVICE_LAB_ENVIRONMENTS, PRIVATE_DESTINATION_REASON, device_private_destination_refusal,
        canonical_device_address, validate_device_destination,
    )

Resolver = Callable[[str], Awaitable[list[str]]]
RESOLVE_TIMEOUT_SECONDS = 5.0


def device_policy_environment(value: Any) -> str:
    """The environment a device is judged under; unset or unknown is production."""
    judged = str(value or "").strip().lower()
    return "production" if not judged or judged == "unknown" else judged


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=RESOLVE_TIMEOUT_SECONDS,
    )
    return [str(info[4][0]).split("%", 1)[0] for info in infos]


async def admit_device_destination(
    locator: str,
    environment: Any,
    *,
    policy: str | None = None,
    resolve: Resolver | None = None,
) -> list[str]:
    """Return the admitted addresses of ``locator``, or raise a 422 naming the setting.

    Nothing needs checking (and nothing is resolved) when the deployment allows private-network
    targets or the device is in a Lab environment; the result is then empty. An unresolvable
    hostname is not refused here: the worker reports unresolved reachability for it.
    """
    effective = policy or deployment_policy.private_network_targets_policy()
    judged = device_policy_environment(environment)
    try:
        addresses = [str(ipaddress.ip_address(str(locator).strip("[]")))]
    except ValueError:
        if effective == "allow" or judged in DEVICE_LAB_ENVIRONMENTS:
            return []
        try:
            addresses = list(dict.fromkeys(await (resolve or _resolve)(str(locator))))
        except (OSError, TimeoutError, ValueError):
            return []
    admitted: list[str] = []
    refusal: str | None = None
    for address in addresses:
        reason = device_private_destination_refusal(address, judged, effective)
        if reason is None:
            admitted.append(address)
        else:
            refusal = refusal or reason
    if admitted or refusal is None:
        return admitted
    raise HTTPException(status_code=422, detail={
        "message": f"Connected device address is not an allowed destination class: {refusal}",
        "reason": PRIVATE_DESTINATION_REASON,
        "setting": deployment_policy.PRIVATE_NETWORK_TARGETS_ENV,
        "environment": judged,
    })


async def pin_device_connect_address(
    connect_address: str,
    environment: Any,
    *,
    policy: str | None = None,
    resolve: Resolver | None = None,
) -> str:
    """The one address a device request sent from the API process may connect to.

    A Device Hunt's ``device_http_request`` and the control-authorization replay connect from
    the API, to an address stored by an earlier posture scan or to the device's own locator
    (an operator-named port), which may be a hostname. That connection is checked exactly as
    the device worker checks the address it pins (``validate_device_destination``: the shared
    address classifier, the metadata deny list and the private-network policy under the
    device's environment), and a hostname is resolved once here and the request pinned to an
    admitted address. Raises a 422 naming the refusal.
    """
    effective = policy or deployment_policy.private_network_targets_policy()
    judged = device_policy_environment(environment)
    text = str(connect_address or "").strip().strip("[]")
    try:
        candidates = [canonical_device_address(text)]
    except ValueError:
        try:
            resolved = await (resolve or _resolve)(text)
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(status_code=422, detail={
                "message": f"Device address could not be resolved: {type(exc).__name__}",
                "reason": "device_address_unresolved",
            }) from exc
        candidates = []
        for item in resolved:
            try:
                candidates.append(canonical_device_address(item))
            except ValueError:
                continue
    refusal = "it resolves to no IP address"
    for candidate in dict.fromkeys(candidates):
        try:
            return validate_device_destination(candidate, environment=judged, policy=effective)
        except ValueError as exc:
            refusal = str(exc)
    raise HTTPException(status_code=422, detail={
        "message": f"Device address is not an allowed destination: {refusal}",
        "reason": PRIVATE_DESTINATION_REASON,
        "environment": judged,
    })


def device_destination_policy_record(environment: Any, policy: str) -> dict[str, Any]:
    """What the admission was judged under, carried in the job for audit and the worker."""
    judged = device_policy_environment(environment)
    return {
        "private_network_targets": policy,
        "environment": judged,
        "lab_environment": judged in DEVICE_LAB_ENVIRONMENTS,
    }

"""Explicit TLS trust policy shared by fleet node clients."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any


class FleetTLSConfigurationError(ValueError):
    pass


def normalize_tls_ca_state(state: dict[str, Any]) -> str:
    """Validate and normalize the node's explicit TLS trust mode.

    Older broker states did not persist ``tls_ca_mode``. They are safely
    interpreted as system-CA states because broker enrollment has always
    required a public CA-valid HTTPS endpoint. Overlay states never receive
    that fallback: their generated private CA must be configured explicitly.
    """
    ca_path = str(state.get("ca_cert_path") or "").strip()
    mode = str(state.get("tls_ca_mode") or "").strip().lower()
    transport = str(state.get("transport") or "").strip().lower()
    if not mode:
        if ca_path:
            mode = "file"
        elif transport == "broker":
            mode = "system"
        else:
            raise FleetTLSConfigurationError(
                "fleet CA is not configured; set tls_ca_mode=file and ca_cert_path"
            )
    if mode not in {"file", "system"}:
        raise FleetTLSConfigurationError("tls_ca_mode must be 'file' or 'system'")
    if mode == "file":
        if not ca_path:
            raise FleetTLSConfigurationError(
                "fleet CA is not configured; tls_ca_mode=file requires ca_cert_path"
            )
        if not Path(ca_path).is_file():
            raise FleetTLSConfigurationError(f"fleet CA certificate does not exist: {ca_path}")
    elif ca_path:
        raise FleetTLSConfigurationError(
            "tls_ca_mode=system cannot be combined with ca_cert_path"
        )
    state["tls_ca_mode"] = mode
    return mode


def create_fleet_ssl_context(state: dict[str, Any]) -> ssl.SSLContext:
    mode = normalize_tls_ca_state(state)
    if mode == "file":
        return ssl.create_default_context(cafile=str(state["ca_cert_path"]).strip())
    return ssl.create_default_context()

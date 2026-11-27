"""Shared fields of a network service identity: protocol, product, version, authentication.

A listener answers in layers, and each layer is a separate claim with its own evidence:

* ``protocol`` -- the wire protocol a parsed handshake or banner confirmed (``ssh``,
  ``mysql``, ``redis``...). ``None`` when nothing confirmed one. The port number never fills
  it; it is kept apart as ``port_hint`` (the conventional service name for that port), which
  only chooses the probe tried first.
* ``product`` / ``version`` -- what the server announced. ``version`` is the upstream release
  (``8.9p1``, ``8.0.36``); ``version_reported`` keeps the exact announced string including any
  distribution build suffix (``OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``), which backport-aware advisory
  matching needs. ``version_basis`` says how the version was learnt; a protocol that reveals no
  version before authentication (PostgreSQL) leaves it ``None`` rather than guessing.
* ``authentication`` -- whether unauthenticated access was shown. A handshake is protocol
  identity and never access proof: ``not_tested`` is the honest default. ``not_required`` needs
  a bounded, read-only command the server executed without credentials, named in
  ``authentication_proof``; ``required`` needs the server to have refused one.

Every value here can come from the target. Labels are bounded and stripped of control
characters before they reach a report, and proofs are fixed codes, never response text.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

SCHEMA_VERSION = "service-identity/v1"

AUTH_NOT_TESTED = "not_tested"
AUTH_REQUIRED = "required"
AUTH_NOT_REQUIRED = "not_required"
AUTH_INCONCLUSIVE = "inconclusive"
AUTHENTICATION_STATES = frozenset({AUTH_NOT_TESTED, AUTH_REQUIRED, AUTH_NOT_REQUIRED, AUTH_INCONCLUSIVE})

# The operator-facing wording for the default.
AUTH_NOT_TESTED_LABEL = "authentication not tested"

# Fixed codes for the bounded, read-only exchange that decided ``authentication``.
AUTHENTICATION_PROOFS: Mapping[str, str] = {
    "redis_info_without_credentials": "Redis answered INFO without credentials",
    "redis_noauth": "Redis refused INFO with NOAUTH",
    "redis_protected_mode": "Redis refused the remote client in protected mode",
    "mongodb_list_databases_without_credentials": "MongoDB listed database names without credentials",
    "mongodb_unauthorized": "MongoDB refused listDatabases without credentials",
    "elasticsearch_index_listing_without_credentials": "Elasticsearch listed indices without credentials",
    "elasticsearch_credentials_required": "Elasticsearch answered 401/403 without credentials",
    "memcached_stats_without_credentials": "Memcached answered stats without credentials",
    "memcached_unauthenticated_refused": "Memcached refused the command as unauthenticated",
    "vnc_security_none_accepted": "VNC accepted the None security type",
    "vnc_authentication_required": "VNC offered only authenticated security types",
    "rdp_nla_required": "RDP refused TLS-only security and required Network Level Authentication",
    "mqtt_anonymous_connect_accepted": "MQTT accepted a CONNECT without credentials",
    "mqtt_connect_not_authorized": "MQTT refused a CONNECT without credentials",
}

VERSION_REPORTED = "reported"
VERSION_BASES = frozenset({VERSION_REPORTED})

STATUS_IDENTIFIED = "identified"          # a parsed handshake confirmed the protocol
STATUS_UNIDENTIFIED = "not_identified"    # the listener answered, but no adapter matched
STATUS_SILENT = "inconclusive"            # no answer to any probe: silence proves nothing
STATUS_NOT_IDENTIFIABLE = "not_identifiable"  # protocol is silent by design (WireGuard)
STATUS_EXCLUDED = "excluded"              # deliberately not probed (printer raw ports)
STATUS_UNREACHABLE = "unreachable"        # the connection itself failed
STATUSES = frozenset({
    STATUS_IDENTIFIED, STATUS_UNIDENTIFIED, STATUS_SILENT, STATUS_NOT_IDENTIFIABLE,
    STATUS_EXCLUDED, STATUS_UNREACHABLE,
})

# The conventional service for a port. Used only as ``port_hint`` and to order probes; it is
# never a protocol, product or version claim.
CONVENTIONAL_PORT_SERVICES: Mapping[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 443: "https", 445: "smb", 465: "smtp", 500: "ike", 587: "smtp",
    502: "modbus", 993: "imap", 995: "pop3", 1194: "openvpn", 1883: "mqtt", 8883: "secure-mqtt",
    5671: "amqps", 5672: "amqp", 44818: "ethernetip", 1433: "mssql", 1521: "oracle", 1701: "l2tp",
    1723: "pptp", 2222: "ssh", 3306: "mysql", 3389: "rdp", 4500: "ike", 5432: "postgresql",
    5900: "vnc", 5901: "vnc", 5902: "vnc", 5903: "vnc", 6379: "redis", 8080: "http",
    8443: "https", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 27019: "mongodb", 51820: "wireguard",
}

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def label(value: Any, limit: int = 200) -> str | None:
    """A bounded, printable label from target-controlled text, or None."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL.sub("", value).replace("\r", " ").replace("\n", " ").strip()
    return cleaned[:limit] or None


def port_hint(port: Any) -> str | None:
    try:
        return CONVENTIONAL_PORT_SERVICES.get(int(port))
    except (TypeError, ValueError):
        return None


def identity_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """The allowlisted identity fields of an adapter or scanner row, for any consumer.

    Unknown authentication states and proof codes are dropped rather than passed through, so
    a fleet node's report cannot invent a stronger claim than the adapters can make.
    """
    authentication = row.get("authentication")
    if authentication not in AUTHENTICATION_STATES:
        authentication = AUTH_NOT_TESTED
    proof = row.get("authentication_proof")
    if proof not in AUTHENTICATION_PROOFS or authentication not in {AUTH_REQUIRED, AUTH_NOT_REQUIRED}:
        proof = None
    version_basis = row.get("version_basis")
    version = label(row.get("version"), 120)
    if version_basis not in VERSION_BASES or version is None:
        version_basis = None
    protocol = label(row.get("protocol"), 40)
    return {
        "protocol": protocol.lower() if protocol else None,
        "product": label(row.get("product"), 120),
        "version": version,
        "version_reported": label(row.get("version_reported"), 200),
        "version_basis": version_basis,
        "authentication": authentication,
        "authentication_proof": proof,
        "port_hint": label(row.get("port_hint"), 40),
    }


__all__ = [
    "AUTHENTICATION_PROOFS", "AUTHENTICATION_STATES", "AUTH_INCONCLUSIVE", "AUTH_NOT_REQUIRED",
    "AUTH_NOT_TESTED", "AUTH_NOT_TESTED_LABEL", "AUTH_REQUIRED", "CONVENTIONAL_PORT_SERVICES",
    "SCHEMA_VERSION", "STATUSES", "STATUS_EXCLUDED", "STATUS_IDENTIFIED", "STATUS_NOT_IDENTIFIABLE",
    "STATUS_SILENT", "STATUS_UNIDENTIFIED", "STATUS_UNREACHABLE", "VERSION_REPORTED",
    "identity_fields", "label", "port_hint",
]

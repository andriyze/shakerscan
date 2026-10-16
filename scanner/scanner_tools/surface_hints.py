"""Offline corporate identity/storage leads from URLs already observed in an artifact.

An embedded provider URL establishes neither ownership nor access. These hints never seed
requests, expand a target binding, add credentials or create verified findings.
Provider formats: Microsoft MSAL authority documentation; AWS S3 VirtualHosting;
Azure Blob object model; Google Cloud Storage request endpoints.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit
try:
    from ..redaction import redact_text
except ImportError:  # installed scanner_tools layout
    from redaction import redact_text
try:
    from capabilities.secret_material import selfevident_secret_matches
except ModuleNotFoundError:
    from api.capabilities.secret_material import selfevident_secret_matches

MAX_HINTS = 50
MAX_TEXT = 262_144
_URL = re.compile(r'''https?://[^\s'"`<>\\]{1,2000}''', re.IGNORECASE)
_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z')
_TENANT = re.compile(r'(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|'
                     r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|common|organizations|consumers)\Z')
_S3 = re.compile(r'(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3'
                 r'(?:[.-][a-z0-9-]+)?\.amazonaws\.com\Z')
_AZURE = re.compile(r'(?P<account>[a-z0-9]{3,24})\.blob\.core\.windows\.net\Z')
_GCS = re.compile(r'(?P<bucket>[a-z0-9][a-z0-9._-]{1,220}[a-z0-9])\.storage\.googleapis\.com\Z')


def corporate_surface_hints(content: str) -> list[dict[str, str]]:
    """At most 50 metadata-only leads; discard userinfo, query, fragment and object keys."""
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    # Slash escaping is common in serialized JS configuration. No expressions are evaluated.
    text = str(content or '')[:MAX_TEXT].replace('\\/', '/')
    for match in _URL.finditer(text):
        try:
            url = urlsplit(match.group().rstrip(');,}'))
            if not url.hostname or url.username is not None or url.password is not None:
                continue
            host, port = url.hostname.lower().rstrip('.'), url.port
            if port not in (None, 80, 443):
                continue
        except ValueError:
            continue
        origin = urlunsplit((url.scheme.lower(), host, '', '', ''))
        parts = [part for part in url.path.split('/') if part]
        kind = provider = identifier = ''
        if host == 'login.microsoftonline.com' and parts and _TENANT.fullmatch(parts[0]):
            # Shared sign-in audiences do not identify one organization's tenant.
            if parts[0] in {'common', 'organizations', 'consumers'}:
                continue
            kind, provider, identifier = 'identity_tenant', 'microsoft_entra', parts[0]
        elif host.endswith(('.okta.com', '.oktapreview.com', '.auth0.com')):
            kind, provider, identifier = 'identity_provider', ('auth0' if host.endswith('.auth0.com') else 'okta'), host
        elif 'realms' in parts:
            index = parts.index('realms')
            if index + 1 < len(parts) and _LABEL.fullmatch(parts[index + 1]):
                kind, provider, identifier = 'identity_realm', 'keycloak_candidate', parts[index + 1]
        else:
            s3, azure, gcs = _S3.fullmatch(host), _AZURE.fullmatch(host), _GCS.fullmatch(host)
            if s3:
                kind, provider, identifier = 'storage_bucket', 'amazon_s3', s3['bucket']
            elif azure:
                kind, provider, identifier = 'storage_account', 'azure_blob', azure['account']
            elif gcs:
                kind, provider, identifier = 'storage_bucket', 'google_cloud_storage', gcs['bucket']
            elif host == 'storage.googleapis.com' and parts and _LABEL.fullmatch(parts[0]):
                kind, provider, identifier = 'storage_bucket', 'google_cloud_storage', parts[0]
        if (not kind or redact_text(identifier) != identifier or redact_text(origin) != origin
                or selfevident_secret_matches(identifier)):
            continue
        key = kind, provider, identifier, origin
        if key in seen:
            continue
        seen.add(key)
        hints.append({'kind': kind, 'provider': provider, 'identifier': identifier,
                      'origin': origin, 'provenance': 'artifact_literal',
                      'ownership': 'unconfirmed', 'access_state': 'not_tested'})
        if len(hints) >= MAX_HINTS:
            break
    return hints

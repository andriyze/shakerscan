"""
Scanner tools package: modular implementations for different scanners.

Modules:
- api_auth: API login authentication (JSON login endpoints, token extraction)
- common: shared helpers (async run, time utils)
- http_scanner: HTTP probing, headers, cookies, CSP, browser fetch
- tls_scanner: TLS probes, OCSP, SSLyze, testssl parsing
- discovery: discovery utilities (tech fingerprinting, katana, CORS, WAF, deep discovery)
- active_checks: active vulnerability checks (XSS/SQLi/SSRF/etc.)
- credential_check: default/weak credential testing for login forms
- nmap: nmap-based scans (cipher enum, full scan)
- nuclei: nuclei-based vulnerability scans (including smart_nuclei_scan with tech filtering)
- subfinder: subdomain discovery via subfinder
- ssh_scanner: SSH configuration security checks (auth methods, password auth detection)
- domain_intel: domain intelligence (WHOIS, age, expiration, registrar reputation)
- ct_monitor: Certificate Transparency monitoring (CA diversity, wildcard abuse, suspicious certs)
- smtp_scanner: SMTP security testing (STARTTLS, open relay, banner analysis, MX redundancy)
- asn_discovery: ASN/IP discovery (hosting provider, geographic distribution, multi-homing)
- compliance_mapper: Compliance framework mapping (PCI DSS, SOC 2, HIPAA, GDPR, CIS Controls)
- network_services: Network service detection (VPN, RDP, VNC, IoT, Industrial/SCADA, databases)
- auth_session: Authenticated session management (cookie/header injection, session validation)
- form_login: Form-based login authentication (login detection, CSRF extraction, session capture)
- oauth_auth: OAuth 2.0/OIDC authentication (client credentials, password grant, token refresh, JWT)
- grpc_discovery: gRPC reflection discovery via grpcurl
- breach_check: Credential breach monitoring (HIBP, GitHub code search, email detection)
- sarif_output: SARIF output format for CI/CD integration (GitHub Security, Azure DevOps)
- vendor_risk: Third-party/vendor risk scoring (CDN analysis, supply chain security)
- request_collections: generic encrypted request collection parsing and selection
- request_replay: exact target-bound replay plans with redacted public descriptors
- model_intake: Model artifact intake checks (provenance, serialization, signatures, approval)
"""

__all__ = [
    "api_auth",
    "active_checks",
    "asn_discovery",
    "auth_session",
    "breach_check",
    "common",
    "compliance_mapper",
    "credential_check",
    "ct_monitor",
    "device_evidence",
    "device_posture",
    "device_probe",
    "device_protocols",
    "device_safety",
    "discovery",
    "domain_intel",
    "form_login",
    "grpc_discovery",
    "http_scanner",
    "model_intake",
    "network_services",
    "nmap",
    "nuclei",
    "oauth_auth",
    "request_collections",
    "request_replay",
    "sarif_output",
    "smtp_scanner",
    "ssh_scanner",
    "subfinder",
    "tls_scanner",
    "vendor_risk",
]

# Load narrow, idempotent V2 hardening while older worker images remain supported.
from .v2_request_replay_hardening import (
    apply_request_replay_hardening as _apply_request_replay_hardening,
)
from .v2_fingerprint_hardening import (
    apply_v2_fingerprint_hardening as _apply_v2_fingerprint_hardening,
)

_apply_request_replay_hardening()
_apply_v2_fingerprint_hardening()

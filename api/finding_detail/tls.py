"""Certificate and protocol findings (``tls.inspect``): names, dates, chain and the fix for this server."""

from __future__ import annotations

from typing import Any, Mapping

from .common import command, fact, facts, integer, join_limited, q, record, short_date, strings, text, url_parts

_LABELS = {
    "tls_certificate_hostname_mismatch": "Certificate hostname mismatch",
    "tls_certificate_untrusted": "Untrusted certificate chain",
    "tls_certificate_expired": "Expired certificate",
    "tls_certificate_not_yet_valid": "Certificate not yet valid",
    "tls_certificate_expiring": "Certificate expiring soon",
    "tls_legacy_protocol": "Legacy TLS protocol",
    "tls_weak_cipher": "Weak TLS cipher",
    "tls_certificate_weak_signature": "Weak certificate signature",
    "tls_certificate_weak_public_key": "Weak certificate key",
}

_TRUST_REASONS = {
    "self_signed": "the certificate is self-signed: it is its own issuer, so no trusted CA vouches for it",
    "untrusted_root": "the chain ends at a root certificate that is not in the client trust store (a private or unknown CA)",
    "issuer_not_found": "the issuing certificate was neither sent by the server nor found in the trust store (usually a missing intermediate)",
    "expired": "a certificate in the chain is past its expiry date",
    "not_yet_valid": "a certificate in the chain is not valid yet",
    "revoked": "the certificate was revoked by its CA",
    "invalid_ca": "an issuer in the chain is not marked as a certificate authority",
    "invalid_purpose": "the certificate is not issued for TLS server authentication",
    "issuer_public_key_missing": "the issuer's public key could not be read",
    "rejected": "the trust store explicitly rejects the root",
}

_SERVER_FIXES = {
    "protocol": [
        "nginx: ssl_protocols TLSv1.2 TLSv1.3;",
        "Apache httpd: SSLProtocol -all +TLSv1.2 +TLSv1.3",
        "HAProxy: ssl-default-bind-options ssl-min-ver TLSv1.2",
    ],
    "cipher": [
        "nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305; ssl_prefer_server_ciphers off;",
        "Apache httpd: SSLCipherSuite with the same list (Mozilla \"intermediate\" profile) and SSLHonorCipherOrder off",
    ],
}


def _connect(evidence: Mapping[str, Any], finding: Mapping[str, Any]) -> tuple[str, str, int | None]:
    """(address to connect, SNI host, port) the scan actually used."""
    origin = evidence.get("origin") or finding.get("url")
    _scheme, host, port, _path = url_parts(origin)
    requested = text(evidence.get("requested_host"), 255) or host
    port = integer(evidence.get("port")) or port
    address = text(evidence.get("pinned_address"), 64) or host
    return address, requested, port


def _s_client(address: str, sni: str, port: int | None, extra: str = "") -> str:
    target = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    return f"openssl s_client -connect {q(target)} -servername {q(sni)}{extra} </dev/null"


def build(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    check = text(evidence.get("check"), 80)
    cert = record(evidence.get("certificate"))
    trust = record(evidence.get("trust"))
    chain = [record(entry) for entry in evidence.get("chain") or () if isinstance(entry, Mapping)][:6]
    address, host, port = _connect(evidence, finding)
    origin = text(evidence.get("origin") or finding.get("url"), 300)
    names = strings(cert.get("dns_names"))
    ips = strings(cert.get("ip_addresses"))
    covered = join_limited(names + ips, 6) or text(cert.get("subject_cn")) or "no names recorded"
    show = _s_client(address, host, port) + " 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName"
    verify = command(
        _s_client(host or address, host, port, f" -verify_hostname {q(host)} -verify_return_error") + " 2>&1 | grep -E 'Verify return code|verify error'",
        expect="Verify return code: 0 (ok)",
    )
    where = facts(
        fact("Origin", origin, mono=True),
        fact("Requested name (SNI)", host, mono=True),
        fact("Connected address", address if address != host else "", mono=True),
        fact("Port", port),
    )
    cert_facts = facts(
        fact("Certificate names", covered, mono=True),
        fact("Subject", cert.get("subject")),
        fact("Issuer", cert.get("issuer")),
        fact("Valid from", cert.get("not_before")),
        fact("Valid until", cert.get("not_after")),
        fact("Key", " ".join(part for part in (text(cert.get("public_key_type")).removesuffix("PublicKey"), f"{cert.get('public_key_bits')} bits" if integer(cert.get("public_key_bits")) else "") if part)),
        fact("Signature hash", cert.get("signature_hash")),
        fact("Serial", cert.get("serial_hex"), mono=True),
    )
    context: list[str] = []
    same = strings(evidence.get("same_certificate_origins"), 10)
    if same:
        context.append(f"The same certificate is also served at {join_limited(same, 4)}; fixing it once fixes all of them.")
    others = [record(row) for row in evidence.get("other_tls_origins") or () if isinstance(row, Mapping)]
    good_other = [text(row.get("origin")) for row in others if row.get("hostname_matches") is True and row.get("trust") == "trusted"]
    out: dict[str, Any] = {
        "class": f"tls.{check.removeprefix('tls_')}" if check else "tls",
        "class_label": _LABELS.get(check, "TLS posture"),
        "where": where,
        "observed": cert_facts,
        "reproduce": command(show),
        "verify": verify,
    }
    days = integer(cert.get("days_remaining"))
    if check == "tls_certificate_hostname_mismatch":
        ip_requested = evidence.get("requested_host_kind") == "ip"
        out["summary"] = (
            f"{origin or host} presented a certificate for {covered}, which does not include "
            f"{'the IP address ' if ip_requested else ''}{host}."
        )
        out["expected"] = [f"A subjectAltName entry that matches {host} ({'an IP SAN' if ip_requested else 'the exact name or a one-label wildcard'})."]
        if trust.get("result") == "trusted":
            context.append(
                f"The chain itself is trusted (issued by {text(cert.get('issuer_cn') or cert.get('issuer'))}); only the name is wrong. "
                "This usually means the TLS terminator has no virtual host for this name and answers with its default certificate."
            )
        if ip_requested:
            context.append(
                "The scan reached this service by IP address. Certificates rarely name addresses; if users reach it by a DNS name, "
                "the defect that matters is whether that name is covered."
            )
        if good_other:
            context.append(f"{join_limited(good_other, 3)} on the same host presents a matching, trusted certificate.")
        out["fix"] = [
            f"Issue (or reuse) a certificate whose subjectAltName includes {host}; today it covers {covered}.",
            f"Bind it to {host} on the terminator for port {port}: a server/virtual host whose server_name (SNI) is {host}, not the default one.",
        ] + ([f"If clients must use the address {host}, add it as an IP SAN, or give the service a DNS name and use that."] if ip_requested else [])
    elif check == "tls_certificate_untrusted":
        failure = text(trust.get("failure"), 60)
        reason = _TRUST_REASONS.get(failure) or text(trust.get("error"), 200) or "the verifier refused the chain"
        length = integer(evidence.get("chain_length")) or len(chain)
        issuer = text(cert.get("issuer_cn") or cert.get("issuer"))
        out["summary"] = f"Clients that verify certificates refuse {origin or host}: {reason}."
        out["expected"] = ["A chain from the served certificate through its intermediates to a root the clients trust."]
        out["observed"] = facts(
            fact("Verifier result", " · ".join(part for part in (text(trust.get("error"), 200), f"code {trust.get('error_code')}" if trust.get("error_code") is not None else "") if part)),
            fact("Certificates sent by the server", length),
        ) + cert_facts
        fix = []
        if failure == "self_signed" or cert.get("self_signed") is True:
            fix = [
                "Replace the self-signed certificate with one issued by a public CA (ACME / Let's Encrypt is free and automatable) for a public service.",
                "For an internal-only service, issue it from your internal CA and install that CA's root on the clients; never tell clients to skip verification.",
            ]
        elif failure == "issuer_not_found":
            aia = strings(cert.get("aia_ca_issuers"), 3)
            fix = [
                f"The server sent {length} certificate(s). Configure the full chain: the leaf followed by the intermediate that issued it ({issuer}).",
                "nginx: ssl_certificate must point to the full-chain file (leaf + intermediates); Apache 2.4.8+: SSLCertificateFile with the chain appended.",
            ] + ([f"The certificate names where its issuer can be downloaded: {join_limited(aia, 2)}."] if aia else [])
        elif failure == "untrusted_root":
            root = text(chain[-1].get("subject")) if chain else issuer
            fix = [
                f"The chain ends at {root}, which public trust stores do not include.",
                "For a public service, use a certificate from a publicly trusted CA. For an internal service, distribute this root to the intended clients.",
            ]
        else:
            fix = ["Correct the cause the verifier named, reload the terminator, and re-check with the same trust store clients use."]
        out["fix"] = fix
    elif check in {"tls_certificate_expired", "tls_certificate_not_yet_valid", "tls_certificate_expiring"}:
        expired_links = [text(link.get("subject")) for index, link in enumerate(chain) if index and link.get("expired") is True]
        if check == "tls_certificate_expired":
            out["summary"] = f"The certificate served at {origin or host} expired on {short_date(cert.get('not_after'))}" + (f" ({abs(days)} days ago)." if days is not None and days < 0 else ".")
            out["expected"] = ["A certificate whose validity period includes today."]
            out["fix"] = [
                f"Renew the certificate for {covered} and install it with its intermediates.",
                f"The server still serves serial {text(cert.get('serial_hex')) or 'recorded above'}: if renewal ran, the terminator was not reloaded (check the ACME deploy/reload hook).",
            ]
        elif check == "tls_certificate_not_yet_valid":
            out["summary"] = f"The certificate served at {origin or host} only becomes valid on {short_date(cert.get('not_before'))}."
            out["expected"] = ["A certificate whose start date is in the past."]
            out["fix"] = [
                "Check the clock of the host that issued or installed the certificate (NTP); a future start date is usually a clock error.",
                "Install a certificate that is valid now, then reload the terminator.",
            ]
        else:
            out["summary"] = f"The certificate served at {origin or host} expires on {short_date(cert.get('not_after'))}" + (f", in {days} days." if days is not None else ".")
            out["expected"] = ["More than 30 days of validity left, renewed automatically."]
            out["fix"] = [
                "Renew now and confirm automated renewal (certbot/acme.sh timer, or your CA's renewal) is enabled for this name.",
                "Make sure the renewal hook reloads the terminator, then confirm the new expiry is what clients receive.",
            ]
        if expired_links:
            context.append(f"An intermediate in the served chain is also expired: {join_limited(expired_links, 2)}.")
        out["reproduce"] = command(_s_client(address, host, port) + " 2>/dev/null | openssl x509 -noout -subject -serial -dates")
    elif check == "tls_legacy_protocol":
        attempts = [record(row) for row in evidence.get("protocol_attempts") or () if isinstance(row, Mapping)]
        probes = [record(row) for row in evidence.get("legacy_protocol_probes") or () if isinstance(row, Mapping)]
        legacy = strings(evidence.get("legacy_protocols_supported"), 4, 20) or [
            text(row.get("protocol")) for row in probes if row.get("supported") is True
        ]
        modern = [text(row.get("protocol")) for row in attempts if row.get("supported") is True and text(row.get("protocol")).startswith("TLSv1.")]
        refused = [text(row.get("protocol")) for row in [*probes, *attempts] if row.get("supported") is False and text(row.get("protocol"))]
        best = text(evidence.get("protocol"))
        accepted = [*legacy, *[name for name in modern if name not in legacy]]
        out["summary"] = (
            f"{origin or host} accepts {join_limited(legacy, 4) or best or 'a legacy protocol'}"
            + (f" alongside {join_limited(modern, 3)}" if modern else (f"; its best protocol is {best}" if best else ""))
            + ". Clients that still offer the old versions can be held to them."
        )
        out["observed"] = facts(
            fact("Legacy versions accepted", join_limited(legacy, 4), mono=True),
            fact("Protocol versions accepted", join_limited(accepted, 6), mono=True),
            fact("Protocol versions refused", join_limited(refused, 6), mono=True),
            fact("Best protocol negotiated", best, mono=True),
            fact("How it was tested", "One ClientHello offering only that version; the server's ServerHello selected it." if probes else ""),
        )
        if "SSLv3" in legacy:
            context.append("SSL 3.0 is accepted: its CBC padding can be decrypted by an attacker in the network path (POODLE).")
        out["expected"] = ["TLS 1.2 and TLS 1.3 only (RFC 8996 deprecates TLS 1.0 and 1.1; SSL 3.0 is prohibited by RFC 7568)."]
        out["fix"] = ["Enable TLS 1.2 and 1.3 and disable SSL 3.0, TLS 1.0 and TLS 1.1 on the terminator for this port:"] + _SERVER_FIXES["protocol"]
        flag = {"TLSv1": " -tls1", "TLSv1.1": " -tls1_1", "SSLv3": " -ssl3"}.get(legacy[0] if legacy else "", " -tls1")
        out["reproduce"] = command(f"nmap --script ssl-enum-ciphers -p {port} {q(host or address)}",
                                   note="Lists every protocol version and suite the server accepts. A current OpenSSL client cannot offer TLS 1.0/1.1 at its default security level, so `openssl s_client` can fail locally even though the server accepts them.")
        out["verify"] = command(_s_client(host or address, host, port, flag + " -cipher 'DEFAULT:@SECLEVEL=0'") + " 2>&1 | grep -E 'Protocol|alert|error'",
                                expect="a handshake failure (alert) for every legacy version")
    elif check == "tls_weak_cipher":
        weak = strings(evidence.get("weak_ciphers_supported"), 12, 80)
        cipher = text(evidence.get("cipher"), 120) or (weak[0] if weak else "")
        bits = integer(evidence.get("cipher_bits")) if not weak else None
        negotiated = text(evidence.get("negotiated_cipher"), 120)
        out["summary"] = (
            f"{origin or host} accepts the weak cipher suite{'s' if len(weak) > 1 else ''} {join_limited(weak, 4) or cipher}"
            + (f" (a normal handshake negotiates {negotiated})" if negotiated and negotiated not in weak else "")
            + "."
        )
        out["observed"] = facts(
            fact("Weak suites accepted", join_limited(weak, 8) or cipher, mono=True),
            fact("Cipher bits", bits),
            fact("Suite a normal handshake negotiates", negotiated, mono=True),
            fact("Protocol", evidence.get("protocol"), mono=True),
            fact("How it was tested", "One ClientHello offering only the weak suite group; the server's ServerHello selected one of them." if weak else ""),
        )
        out["expected"] = ["Only AEAD suites (AES-GCM or ChaCha20-Poly1305) with forward secrecy (ECDHE); no RC4, DES/3DES, NULL, EXPORT or anonymous suites."]
        out["fix"] = [f"Remove {join_limited(weak, 4) or cipher} (and every RC4, DES/3DES, NULL, EXPORT and anonymous suite) from the server's cipher list:"] + _SERVER_FIXES["cipher"]
        out["reproduce"] = command(f"nmap --script ssl-enum-ciphers -p {port} {q(host or address)}", note="Lists every suite the server accepts, graded. A current OpenSSL client may lack RC4/DES entirely, so `openssl s_client -cipher` can fail locally.")
        out["verify"] = command(_s_client(host or address, host, port, f" -cipher {q((weak[0] if weak else cipher) + ':@SECLEVEL=0')}") + " 2>&1 | grep -E 'Cipher is|alert|error'", expect="a handshake failure for every weak suite")
    elif check == "tls_certificate_weak_signature":
        out["summary"] = f"The certificate served at {origin or host} is signed with {text(cert.get('signature_hash')).upper() or 'a weak hash'}."
        out["expected"] = ["A SHA-256 (or stronger) signature, which every public CA issues today."]
        out["fix"] = [f"Reissue the certificate for {covered} with a SHA-256 signature and install it with its current intermediates."]
    elif check == "tls_certificate_weak_public_key":
        out["summary"] = f"The certificate served at {origin or host} uses a {cert.get('public_key_bits')}-bit {text(cert.get('public_key_type')).removesuffix('PublicKey') or 'public'} key."
        out["expected"] = ["RSA 2048 bits or more, or an EC P-256 key."]
        out["fix"] = [
            "Generate a NEW key (renewing with the same key keeps it weak), e.g. openssl req -new -newkey rsa:3072 -nodes -keyout server.key -out server.csr, or an EC P-256 key.",
            "Have the CSR signed, install the new certificate and key, and reload the terminator.",
        ]
    else:
        out["summary"] = text(finding.get("title"))
    out["context"] = context
    return out


__all__ = ["build"]

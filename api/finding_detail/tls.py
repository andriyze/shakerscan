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
    "issuer_not_found": "the issuing certificate was neither sent by the server nor found in the trust store (a missing intermediate, or a private CA the clients do not trust)",
    "expired": "a certificate in the chain is past its expiry date",
    "not_yet_valid": "a certificate in the chain is not valid yet",
    "revoked": "the certificate was revoked by its CA",
    "invalid_ca": "an issuer in the chain is not marked as a certificate authority",
    "invalid_purpose": "the certificate is not issued for TLS server authentication",
    "issuer_public_key_missing": "the issuer's public key could not be read",
    "rejected": "the trust store explicitly rejects the root",
    "weak_key": "a certificate in the chain has a key smaller than the verifier accepts",
    "weak_signature": "a certificate in the chain is signed with a digest the verifier refuses (SHA-1 or MD5)",
}

# OpenSSL verify codes for a key (66 the server's, 67 an issuer's) or a signature digest (68)
# below the verifier's security level. Findings recorded before they had a name say "other".
_STRENGTH_FAILURES = {66: "weak_key", 67: "weak_key", 68: "weak_signature"}

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


def _weak_links(chain: list[dict[str, Any]], flag: str) -> list[dict[str, Any]]:
    """Issuing certificates the server sent whose key or signature is weak (``flag``).

    A self-signed root's own signature is never checked, so it is not named for a weak signature.
    """
    return [
        link for link in chain[1:]
        if link.get(flag) is True and not (flag == "weak_signature" and link.get("self_signed") is True)
    ]


def _issuer_not_found_fix(cert: Mapping[str, Any], chain: list[dict[str, Any]], sent: int | None) -> list[str]:
    """Code 20/2/21: the verifier could not find who issued the last certificate the server sent.

    That is a missing intermediate, or a CA (often a private root) the clients do not have; adding
    a root to the served chain does not make it trusted. A certificate that names where its issuer
    can be downloaded (AIA) comes from a CA that publishes its intermediates, so the missing
    intermediate is the likely cause; otherwise both are named.
    """
    last = chain[-1] if len(chain) > 1 and sent and sent > 1 else {}
    missing = text(last.get("issuer_cn") or last.get("issuer") or cert.get("issuer_cn") or cert.get("issuer")) or "its issuer"
    counted = f"The server sent {sent} certificate(s), and neither they nor the trust store include {missing}. " if sent else ""
    chain_step = "nginx: ssl_certificate must point to the full-chain file (leaf + intermediates); Apache 2.4.8+: SSLCertificateFile with the chain appended."
    aia = strings(cert.get("aia_ca_issuers"), 3)
    if aia:
        return [
            f"{counted}Configure the full chain: the leaf followed by the intermediate that issued it ({missing}).",
            chain_step,
            f"The certificate names where its issuer can be downloaded: {join_limited(aia, 2)}.",
        ]
    return [
        f"{counted}Either {missing} is an intermediate the server does not send, or it is a CA the clients do not trust (a private CA).",
        f"If {missing} is an intermediate: serve the leaf followed by it. {chain_step}",
        f"If {missing} is a private CA: for a public service, use a certificate from a publicly trusted CA; for an internal service, install its root on the clients. Sending a root in the chain does not make it trusted.",
    ]


def _strength_fix(failure: str, code: int | None, cert: Mapping[str, Any], chain: list[dict[str, Any]]) -> list[str]:
    """Codes 66/67/68 that no finding of the served certificate explains: name the weak one."""
    if failure == "weak_key":
        if code == 66:
            bits = integer(cert.get("public_key_bits"))
            return [
                f"The server certificate's {f'{bits}-bit key' if bits else 'key'} is below the verifier's minimum (RSA 2048 bits, EC 224 bits).",
                "Generate a NEW key (renewing with the same key keeps it weak), have it signed, install the certificate and key, and reload the terminator.",
            ]
        named = [
            f"{text(link.get('subject'))} uses a {link.get('public_key_bits')}-bit {text(link.get('public_key_type')).removesuffix('PublicKey')} key."
            for link in _weak_links(chain, "weak_public_key")[:2]
        ] or ["An issuing CA certificate (one the server sent, or the root it chains to) has a key below the verifier's minimum (RSA 2048 bits, EC 224 bits)."]
        return named + ["Install your CA's current intermediates; for a private CA, reissue its certificates with RSA 2048+ or EC P-256 keys and re-sign the server certificate."]
    if text(cert.get("signature_hash")).lower() in {"md5", "sha1"}:
        return [
            f"The server certificate is signed with {text(cert.get('signature_hash')).upper()}.",
            "Reissue it with a SHA-256 signature and install it with its current intermediates.",
        ]
    named = [
        f"{text(link.get('subject'))} is signed with {text(link.get('signature_hash')).upper() or 'a weak digest'}."
        for link in _weak_links(chain, "weak_signature")[:2]
    ] or ["An intermediate certificate in the chain is signed with SHA-1 or MD5."]
    return named + ["Install your CA's current SHA-256 intermediates; for a private CA, reissue the intermediate with a SHA-256 signature."]


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
        if failure in {"", "other"}:
            failure = _STRENGTH_FAILURES.get(integer(trust.get("error_code")) or -1, failure)
        reason = _TRUST_REASONS.get(failure) or text(trust.get("error"), 200) or "the verifier refused the chain"
        # `not_captured`: the runtime could not read the chain, so only the leaf is known.
        length = (integer(evidence.get("chain_length")) or len(chain)) if evidence.get("chain_status") != "not_captured" else None
        issuer = text(cert.get("issuer_cn") or cert.get("issuer"))
        out["summary"] = f"Clients that verify certificates refuse {origin or host}: {reason}."
        out["expected"] = ["A chain from the served certificate through its intermediates to a root the clients trust."]
        out["observed"] = facts(
            fact("Verifier result", " · ".join(part for part in (text(trust.get("error"), 200), f"code {trust.get('error_code')}" if trust.get("error_code") is not None else "") if part)),
            fact("Certificates sent by the server", length),
        ) + cert_facts
        out["reproduce"] = command(
            _s_client(address, host, port) + " 2>/dev/null | sed -n '/^Certificate chain/,/^---/p'",
            note="Lists every certificate the server sends, in order: s: is its subject and i: the issuer it names.",
        )
        fix = []
        if failure == "self_signed" or cert.get("self_signed") is True:
            fix = [
                "Replace the self-signed certificate with one issued by a public CA (ACME / Let's Encrypt is free and automatable) for a public service.",
                "For an internal-only service, issue it from your internal CA and install that CA's root on the clients; never tell clients to skip verification.",
            ]
        elif failure == "issuer_not_found":
            fix = _issuer_not_found_fix(cert, chain, length)
        elif failure in {"weak_key", "weak_signature"}:
            fix = _strength_fix(failure, integer(trust.get("error_code")), cert, chain)
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
        # Protocol versions only: `default_negotiation` names the scan's own fallback handshake.
        refused = [text(row.get("protocol")) for row in [*probes, *attempts]
                   if row.get("supported") is False and text(row.get("protocol")).startswith(("SSLv", "TLSv"))]
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
        enumerate_suites = f"nmap --script ssl-enum-ciphers -p {port} {q(host or address)}"
        out["reproduce"] = command(enumerate_suites, note="Lists every suite the server accepts, graded. nmap writes its own ClientHello, so it can offer RC4 and DES; a current OpenSSL client often cannot, and `openssl s_client -cipher` then fails locally with 'no cipher match' whatever the server accepts.")
        # The check offers the weak suites itself: `openssl s_client -cipher RC4...` on an OpenSSL
        # without RC4 printed the same local error for a fixed and a vulnerable server. Suite
        # names are IANA's (TLS_RSA_WITH_RC4_128_SHA); a bare NULL would match the
        # "compressors: NULL" line every server prints.
        out["verify"] = command(enumerate_suites + " | grep -E 'TLSv1|SSLv3|RC4|DES|WITH_NULL|EXPORT|_anon_'",
                                expect="only the protocol version headers (such as TLSv1.2:), with no RC4, DES/3DES, NULL, EXPORT or anon suite listed")
    elif check in {"tls_certificate_weak_signature", "tls_certificate_weak_public_key"}:
        signature = check == "tls_certificate_weak_signature"
        # The generic subject/issuer/dates printout showed neither the digest nor the key size.
        printed = "Signature Algorithm" if signature else "Public-Key"
        out["reproduce"] = command(_s_client(address, host, port) + f" 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|{printed}'")
        out["verify"] = command(
            _s_client(host or address, host, port) + f" 2>/dev/null | openssl x509 -noout -text | grep -E '{printed}'",
            expect=(
                "Signature Algorithm: sha256WithRSAEncryption (or ecdsa-with-SHA256, or a stronger digest); never sha1 or md5" if signature
                else "Public-Key: (2048 bit) or more for RSA, (256 bit) for EC"
            ),
        )
        code = integer(trust.get("error_code"))
        if trust.get("result") == "untrusted" and code == (68 if signature else 66):
            context.append(
                f"Clients that verify certificates refuse this certificate for its {'signature' if signature else 'key'} "
                f"(verifier: {text(trust.get('error'), 120) or 'refused'}, code {code})."
                + (" The verifier refuses a weak server key before it builds the chain, so whether the chain reaches a trusted root is checked only after the key is replaced."
                   if not signature else "")
            )
        if signature:
            out["summary"] = f"The certificate served at {origin or host} is signed with {text(cert.get('signature_hash')).upper() or 'a weak hash'}."
            out["expected"] = ["A SHA-256 (or stronger) signature, which every public CA issues today."]
            out["fix"] = [f"Reissue the certificate for {covered} with a SHA-256 signature and install it with its current intermediates."]
        else:
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

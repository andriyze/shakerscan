"""Guidance keyed by the canonical TLS check, with exact legacy-title compatibility."""

_VERIFY = ('openssl s_client -connect HOST:PORT -servername HOST '
           '-verify_hostname HOST -verify_return_error < /dev/null')

_CHECKS = {
    'tls_certificate_hostname_mismatch': ('TLS certificate hostname mismatch', [
        'Compare the requested host with the DNS names or IP addresses recorded in the certificate.',
        'Issue a certificate whose subjectAltName covers the actual service name. An IP address needs an IP SAN; a DNS SAN containing an address does not match it.',
        'Install that certificate on the TLS terminator for this host, including the correct SNI virtual host. Test each recorded service and address after reloading it.',
    ]),
    'tls_certificate_untrusted': ('TLS certificate chain is not trusted', [
        'Use the recorded verifier code, reason, issuer and presented chain to distinguish a missing intermediate, an untrusted CA, invalid validity dates or a certificate with the wrong purpose.',
        'Serve the leaf certificate followed by its required intermediates. For a private CA, provision the approved trust anchor to the intended clients; do not disable verification.',
        'Reload the TLS terminator and verify with the same trust store clients use. A hostname mismatch is a separate check.',
    ]),
    'tls_certificate_expired': ('TLS certificate is expired', [
        'Compare the recorded expiry with the current UTC time and check the server clock.',
        'Renew and install the certificate and its intermediates on every terminator serving this origin.',
        'Repair automated renewal and reload hooks, then check the served serial, fingerprint and validity dates.',
    ]),
    'tls_certificate_not_yet_valid': ('TLS certificate is not yet valid', [
        'Compare the recorded valid-from date with UTC and check clock synchronization.',
        'Install a currently valid certificate, or correct the deployment clock if it is wrong.',
        'Reload the terminator and verify the certificate clients actually receive.',
    ]),
    'tls_certificate_expiring': ('TLS certificate expires within 30 days', [
        'Renew before the recorded expiry date and confirm automated renewal is enabled.',
        'Test the deploy/reload hook so the renewed certificate is served, rather than only written to disk.',
        'Check each recorded address after renewal and monitor the served expiry date.',
    ]),
    'tls_legacy_protocol': ('Legacy TLS protocol negotiated', [
        'Enable TLS 1.2 and TLS 1.3 on the recorded service and update clients that require older versions.',
        'Disable TLS 1.0 and TLS 1.1 after checking client compatibility.',
        'Re-test the protocol versions recorded in the finding; one successful modern handshake does not prove legacy versions are disabled.',
    ]),
    'tls_weak_cipher': ('Weak TLS cipher negotiated', [
        'Use the recorded negotiated suite to identify the weak cipher or anonymous authentication.',
        'Remove NULL, EXPORT, anonymous, RC4 and 3DES suites; use the maintained TLS configuration for your server version.',
        'Check both modern-client negotiation and refusal of the previously observed weak suite.',
    ]),
    'tls_certificate_weak_signature': ('TLS certificate uses a weak signature', [
        'Identify the certificate and recorded signature hash in the presented chain.',
        'Reissue affected certificates with a current signature algorithm and replace affected intermediates through the issuing CA.',
        'Verify the complete served chain after reloading the terminator.',
    ]),
    'tls_certificate_weak_public_key': ('TLS certificate uses a weak public key', [
        'Use the recorded key type and size to identify the weak certificate.',
        'Generate a new key using the issuing CA and server current requirements, then reissue the certificate; renewing with the same weak key is insufficient.',
        'Deploy the new key/certificate securely, reload the terminator, and confirm the served key size and fingerprint.',
    ]),
}

TLS_REMEDIATIONS = {
    check: {
        'title': title, 'description': title, 'severity_base': 'medium', 'cwe': 'CWE-295',
        'business_impact': 'TLS clients may reject the connection or lose the protection this check examines. Use the recorded facts and severity rationale to assess the affected service.',
        'remediation_steps': steps, 'code_examples': {}, 'effort': 'hours',
        'verification': _VERIFY,
        'documentation_links': ['https://www.rfc-editor.org/rfc/rfc9525.html',
                                'https://docs.openssl.org/3.5/man1/openssl-s_client/'],
    } for check, (title, steps) in _CHECKS.items()
}
TLS_TITLE_CHECKS = {title.lower(): check for check, (title, _steps) in _CHECKS.items()}

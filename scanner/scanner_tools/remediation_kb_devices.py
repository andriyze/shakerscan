"""Remediation entries for the connected-device checks (SSH posture, service policy, TLS trust,
firmware advisories, management-interface response controls).

remediation_kb_findings.py merges these into its finding-type entries and maps each device check's
``tool`` (and title, where one check reports several kinds) to a key here. Plain data only.
"""

from __future__ import annotations

from typing import Any

_SSHD_VERIFY = "sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods)'"

DEVICE_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "ssh_password_auth": {
        "title": "SSH Password Authentication Enabled",
        "severity_base": "medium",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "The SSH service accepts passwords, so anyone who can reach it can attempt logins by guessing or replaying credentials.",
        "business_impact": "A guessed, reused or leaked password gives an attacker a shell on the device; online guessing against SSH is continuous on reachable hosts.",
        "remediation_steps": [
            "Provision public keys (or SSH certificates) for every account that needs access, and confirm key login works before changing anything else",
            "Set PasswordAuthentication no and KbdInteractiveAuthentication no in sshd_config, then reload sshd",
            "Disable direct root login (PermitRootLogin no or prohibit-password)",
            "If the device firmware cannot disable passwords, restrict SSH to the management network and enforce a strong, unique password with lockout",
        ],
        "code_examples": {
            "sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\nAuthenticationMethods publickey",
        },
        "documentation_links": [
            "https://man.openbsd.org/sshd_config",
            "https://www.ssh.com/academy/ssh/sshd_config",
        ],
        "verification": _SSHD_VERIFY,
        "effort": "hours",
    },
    "ssh_keyboard_interactive": {
        "title": "SSH Keyboard-Interactive Authentication Enabled",
        "severity_base": "low",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "The SSH service offers keyboard-interactive authentication, which on most systems is a password prompt by another name (PAM).",
        "business_impact": "Password guessing remains possible even when PasswordAuthentication is off, unless keyboard-interactive is tied to a second factor.",
        "remediation_steps": [
            "Set KbdInteractiveAuthentication no (ChallengeResponseAuthentication no on older OpenSSH) if it is not used for a second factor",
            "If it carries a second factor, require a key as well: AuthenticationMethods publickey,keyboard-interactive",
            "Reload sshd and confirm the offered methods",
        ],
        "code_examples": {
            "sshd_config": "KbdInteractiveAuthentication no\n# or, when it is a second factor:\nAuthenticationMethods publickey,keyboard-interactive",
        },
        "documentation_links": ["https://man.openbsd.org/sshd_config"],
        "verification": _SSHD_VERIFY,
        "effort": "hours",
    },
    "ssh_weak_algorithms": {
        "title": "Weak SSH Algorithms Negotiated",
        "severity_base": "medium",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "The SSH server negotiated a legacy cipher, MAC, key exchange or an undersized host key (the finding's evidence lists which).",
        "business_impact": "Legacy algorithms weaken the confidentiality and integrity of management sessions and keep downgrade paths open.",
        "remediation_steps": [
            "Restrict Ciphers, MACs and KexAlgorithms in sshd_config to modern choices; remove CBC, 3DES, arcfour, hmac-md5 and hmac-sha1",
            "Replace RSA host keys under 2048 bits and DSA host keys with an Ed25519 (or RSA 3072+) host key",
            "Update the device's SSH firmware if the vendor build cannot be configured",
            "Check the result with ssh-audit or by listing the server's offered algorithms",
        ],
        "code_examples": {
            "sshd_config": (
                "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr\n"
                "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
                "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org\n"
                "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n"
                "HostKey /etc/ssh/ssh_host_ed25519_key"
            ),
        },
        "documentation_links": [
            "https://man.openbsd.org/sshd_config",
            "https://github.com/jtesta/ssh-audit",
        ],
        "verification": "ssh-audit <device-host>",
        "effort": "hours",
    },
    "device_service_policy": {
        "title": "Device Service Outside the Approved Policy",
        "severity_base": "medium",
        "cwe": "CWE-284",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A listening service on the device is denied by, not covered by, or does not meet the requirements of the approved connected-device policy. The finding's description gives the policy's reason.",
        "business_impact": "Every unapproved or misconfigured service is attack surface the device owner did not accept, often with weaker authentication than the intended management path.",
        "remediation_steps": [
            "Disable the service on the device if it is not needed",
            "If it is needed, bind it to the management interface or VLAN, or firewall it to the approved management hosts",
            "For a requirement not met, bring the service configuration in line with the stated requirement (for example key-only SSH, no weak algorithms)",
            "If the service is approved, add a narrowly scoped rule (transport, port, service) to the device policy with the reason",
            "Rescan the device to confirm the service's policy disposition",
        ],
        "code_examples": {},
        "documentation_links": ["https://csrc.nist.gov/pubs/sp/800/213/final"],
        "verification": "Rescan the device and check the service's policy disposition",
        "effort": "hours",
    },
    "device_tls_trust": {
        "title": "Device Management Certificate Not Trusted",
        "severity_base": "medium",
        "cwe": "CWE-295",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Strict TLS verification of the device's HTTPS management interface failed: the certificate is self-signed, expired, issued for another name, or otherwise does not chain to a trusted root.",
        "business_impact": "Administrators learn to click through certificate warnings, so an interception of the management session would not be noticed.",
        "remediation_steps": [
            "Issue a certificate for the device's management hostname from your internal or a public CA and install it on the device",
            "Reach the interface by the hostname on the certificate, not by IP address",
            "Renew before expiry and replace factory default certificates",
            "If the device cannot hold a trusted certificate, keep the interface on an isolated management network and pin its certificate in the tools that use it",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
        "verification": "openssl s_client -connect <device-host>:443 -servername <device-host> -verify_return_error </dev/null",
        "effort": "hours",
    },
    "device_firmware_advisory": {
        "title": "Known-Vulnerable Device Software",
        "severity_base": "high",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "description": "The device's observed software identity and version fall in the affected range of a published advisory.",
        "business_impact": "Published advisories are what attackers scan for; an affected, reachable device is an exposed known vulnerability.",
        "remediation_steps": [
            "Apply the vendor's fixed firmware or software version named in the advisory",
            "Until it is patched, disable the affected service or restrict it to the management network",
            "If the vendor has no fix, apply the advisory's workaround or plan the device's replacement",
            "Rescan the device to confirm the reported version is outside the affected range",
        ],
        "code_examples": {},
        "documentation_links": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        "verification": "Rescan the device and confirm the advisory no longer matches",
        "effort": "days",
    },
    "sensitive_response_caching": {
        "title": "Sensitive Responses Cacheable",
        "severity_base": "medium",
        "cwe": "CWE-525",
        "owasp": "A04:2021 - Insecure Design",
        "description": "An authenticated response did not forbid caching, so shared or browser caches may keep sensitive management data.",
        "business_impact": "Cached management pages or API responses can be read later from a shared proxy or by another user of the same browser.",
        "remediation_steps": [
            "Return Cache-Control: no-store on authenticated management and API responses",
            "Where some caching is required, use Cache-Control: private with a short max-age",
            "Avoid placing sensitive data in URLs that caches may key on",
        ],
        "code_examples": {
            "nginx": 'add_header Cache-Control "no-store" always;',
            "apache": 'Header always set Cache-Control "no-store"',
        },
        "documentation_links": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"],
        "verification": "curl -sI -b <session-cookie> https://<device-host>/ | grep -i cache-control",
        "effort": "hours",
    },
}

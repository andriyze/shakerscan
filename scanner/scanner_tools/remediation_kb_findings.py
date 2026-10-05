"""Remediation entries for findings the keyword table could not name, and how to match them.

remediation_kb.py merges these entries into REMEDIATION_DATABASE. Matching here is by what
produced the finding, not by words in its title: the check (`tool`), an exact title from a fixed
catalog (AI Gate probes), the header a missing-header finding names, or the AI Gate probe family.
Plain data only; no imports from remediation_kb, so either module can import the other's names.
The connected-device entries live in remediation_kb_devices.py and are merged in here.
"""

from __future__ import annotations

import re
from typing import Any

from .remediation_kb_devices import DEVICE_REMEDIATIONS

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def _header(title: str, cwe: str, description: str, impact: str, steps: list[str], value: str,
            effort: str = "minutes", severity: str = "low") -> dict[str, Any]:
    name = title.split(" Header")[0]
    return {
        "title": title,
        "severity_base": severity,
        "cwe": cwe,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": description,
        "business_impact": impact,
        "remediation_steps": steps,
        "code_examples": {
            "nginx": f'add_header {name} "{value}" always;',
            "apache": f'Header always set {name} "{value}"',
        },
        "documentation_links": [_MDN + name],
        "verification": f"curl -sI https://example.com | grep -i {name.lower()}",
        "effort": effort,
    }


FINDING_TYPE_REMEDIATIONS: dict[str, dict[str, Any]] = {
    # ------------------------------------------------------------------ HTTP response headers
    "missing_referrer_policy": _header(
        "Referrer-Policy Header Missing", "CWE-200",
        "Responses do not set Referrer-Policy, so browsers use their default and may send full URLs, "
        "including paths and query strings, to other sites.",
        "Tokens, IDs or search terms in URLs can reach third-party sites in the Referer header.",
        ["Send Referrer-Policy: strict-origin-when-cross-origin on every response, or no-referrer where URLs are sensitive",
         "Keep secrets and personal data out of URLs regardless of the policy"],
        "strict-origin-when-cross-origin"),
    "missing_permissions_policy": _header(
        "Permissions-Policy Header Missing", "CWE-693",
        "Responses do not set Permissions-Policy, so scripts and framed content may request powerful "
        "browser features (camera, microphone, geolocation, payment) the site never uses.",
        "A compromised or third-party script can prompt users for access the site itself never needs.",
        ["List the browser features the site uses and disable the rest with Permissions-Policy",
         "Allow a feature only for the origins that need it, for example geolocation=(self)"],
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    "missing_coop": _header(
        "Cross-Origin-Opener-Policy Header Missing", "CWE-693",
        "Responses do not set Cross-Origin-Opener-Policy, so a page opened from another origin keeps a "
        "reference to this window.",
        "Other sites can interact with the window across origins, which enables cross-site leaks and "
        "weakens isolation against side-channel attacks.",
        ["Send Cross-Origin-Opener-Policy: same-origin",
         "Use same-origin-allow-popups instead where the site relies on popups it opens itself, such as an OAuth sign-in window"],
        "same-origin"),
    "missing_coep": _header(
        "Cross-Origin-Embedder-Policy Header Missing", "CWE-693",
        "Responses do not set Cross-Origin-Embedder-Policy. It is needed only for cross-origin isolation, "
        "which features such as SharedArrayBuffer and high-resolution timers require.",
        "Without cross-origin isolation the page cannot use those features; on its own the missing header "
        "is not exploitable.",
        ["If the site needs cross-origin isolation, send Cross-Origin-Embedder-Policy: require-corp (or credentialless) together with COOP same-origin",
         "Every cross-origin resource the page loads must then allow it through CORS or Cross-Origin-Resource-Policy",
         "If the site does not need cross-origin isolation, this finding can be accepted as informational"],
        "require-corp", effort="hours", severity="info"),
    "missing_corp": _header(
        "Cross-Origin-Resource-Policy Header Missing", "CWE-693",
        "Responses do not set Cross-Origin-Resource-Policy, so any site may load them as images, scripts or "
        "other subresources.",
        "Other sites can pull the resources into their own pages, which side-channel attacks can use to read data.",
        ["Send Cross-Origin-Resource-Policy: same-origin for private responses",
         "Use same-site where sibling subdomains load the resource, and cross-origin only for public assets such as a CDN"],
        "same-origin"),
    "missing_x_permitted_cross_domain_policies": _header(
        "X-Permitted-Cross-Domain-Policies Header Missing", "CWE-693",
        "Responses do not set X-Permitted-Cross-Domain-Policies, which tells Adobe clients whether to honor "
        "crossdomain.xml policy files.",
        "Low: Flash is retired, but Acrobat and similar clients still read these policies to allow cross-domain data access.",
        ["Send X-Permitted-Cross-Domain-Policies: none",
         "Remove any crossdomain.xml or clientaccesspolicy.xml the site does not need"],
        "none", severity="info"),
    "security_headers_baseline": {
        "title": "Security Headers Missing",
        "severity_base": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Responses lack one or more standard security headers.",
        "business_impact": "Browsers apply weaker defaults: framing, MIME sniffing, downgrade to HTTP and cross-origin loading are not restricted.",
        "remediation_steps": [
            "Set the baseline on every response, ideally once at the edge or in shared middleware",
            "Start the Content Security Policy in report-only mode and tighten it before enforcing",
            "Check the finding's evidence for which headers this response lacked",
        ],
        "code_examples": {
            "nginx": """add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'; base-uri 'none'" always;""",
            "express": "app.use(require('helmet')())",
        },
        "documentation_links": ["https://owasp.org/www-project-secure-headers/"],
        "verification": "curl -sI https://example.com",
        "effort": "hours",
    },
    "https_redirect": {
        "title": "HTTP Not Redirected to HTTPS",
        "severity_base": "medium",
        "cwe": "CWE-319",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "The site answers plain HTTP instead of redirecting to HTTPS.",
        "business_impact": "Visitors who type the address or follow an old link use an unencrypted connection that can be read or altered.",
        "remediation_steps": [
            "Redirect every HTTP request to the same URL over HTTPS with a 301",
            "Then send Strict-Transport-Security so browsers stop trying HTTP at all",
        ],
        "code_examples": {
            "nginx": """server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}""",
            "apache": """RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]""",
        },
        "documentation_links": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        "verification": "curl -sI http://example.com | grep -i -E '^(HTTP|location)'   # expect 301 to https://",
        "effort": "minutes",
    },
    # ------------------------------------------------------------------ Authentication and abuse
    "rate_limiting": {
        "title": "No Rate Limiting",
        "severity_base": "medium",
        "cwe": "CWE-770",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "The endpoint accepted a burst of requests without slowing or refusing them.",
        "business_impact": "Attackers can try passwords and codes at full speed, enumerate accounts, or drive up load and cost.",
        "remediation_steps": [
            "Limit requests per client and, on authentication endpoints, per account",
            "Answer over-limit requests with 429 Too Many Requests and a Retry-After header",
            "Enforce the limit server-side or at the edge, not in the client",
            "Alert on sustained limit hits, which usually mean an attack",
        ],
        "code_examples": {
            "nginx": """limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /login {
    limit_req zone=login burst=5 nodelay;
    limit_req_status 429;
}""",
            "express": """const rateLimit = require('express-rate-limit')
app.use('/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }))""",
        },
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"],
        "verification": "Send 20 quick requests to the endpoint and confirm later ones get 429",
        "effort": "hours",
    },
    "login_bruteforce": {
        "title": "Brute-Force Protection Missing",
        "severity_base": "high",
        "cwe": "CWE-307",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "The sign-in endpoint accepted repeated failed attempts without slowing, challenging or blocking them.",
        "business_impact": "Attackers can guess passwords or replay leaked credentials until one works.",
        "remediation_steps": [
            "Limit failed sign-ins per account and per source, with growing delays or a temporary lockout",
            "Avoid permanent lockouts, which let anyone lock users out",
            "Offer or require multi-factor authentication",
            "Return the same error for a wrong user name and a wrong password",
            "Alert on spikes in failed sign-ins",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
        "verification": "Fail ten sign-ins for one account and confirm further attempts are slowed or refused",
        "effort": "days",
    },
    "mfa_weakness": {
        "title": "Second Factor Can Be Bypassed or Guessed",
        "severity_base": "high",
        "cwe": "CWE-308",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "The second-factor step does not hold: codes can be tried without limit, or protected pages open without completing it.",
        "business_impact": "An attacker with the password gets in anyway, which removes the protection MFA was added for.",
        "remediation_steps": [
            "Limit code attempts per challenge (for example five) and expire the challenge after that",
            "Bind each challenge to the sign-in session that started it",
            "Grant the authenticated session only after the second factor succeeds, and check that on every protected route",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"],
        "verification": "With a password only, request a protected page directly and submit wrong codes repeatedly; both must fail",
        "effort": "days",
    },
    "webhook_signature": {
        "title": "Webhook Signature Not Verified",
        "severity_base": "high",
        "cwe": "CWE-345",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "description": "The webhook endpoint accepted a request without a valid signature from the sending service.",
        "business_impact": "Anyone can send forged events, such as a paid invoice or a pushed commit, and trigger the actions they cause.",
        "remediation_steps": [
            "Verify the provider's signature header over the raw request body with the shared secret",
            "Compare signatures in constant time and reject the request when the header is missing or wrong",
            "Check the event timestamp to refuse replays of old events",
            "Keep the webhook secret in a secret manager and rotate it if it was ever exposed",
        ],
        "code_examples": {
            "node": """const crypto = require('crypto')
function verified(rawBody, header, secret) {
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex')
  return header && crypto.timingSafeEqual(Buffer.from(header), Buffer.from(expected))
}""",
        },
        "documentation_links": [
            "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
            "https://docs.stripe.com/webhooks#verify-events",
        ],
        "verification": "Send the endpoint an event with a wrong signature and confirm it is refused",
        "effort": "hours",
    },
    # ------------------------------------------------------------------ HTTP handling
    "risky_http_methods": {
        "title": "Unneeded HTTP Methods Allowed",
        "severity_base": "low",
        "cwe": "CWE-650",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server advertises methods such as PUT and DELETE on these paths.",
        "business_impact": "If a method is enabled where nothing needs it, or without authorization, files or records can be changed or removed.",
        "remediation_steps": [
            "Allow only the methods each route uses; disable WebDAV and TRACE",
            "Where an API does use PUT or DELETE, confirm each requires authentication and authorization",
            "If both hold, accept this finding as expected API behavior",
        ],
        "code_examples": {
            "nginx": """location /static/ {
    limit_except GET HEAD { deny all; }
}""",
            "apache": """<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>""",
        },
        "documentation_links": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
        "verification": "curl -si -X OPTIONS https://example.com/<path> | grep -i allow",
        "effort": "hours",
    },
    "cache_poisoning": {
        "title": "Web Cache Poisoning",
        "severity_base": "high",
        "cwe": "CWE-349",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A request header the cache does not key on changes the response, so one request can plant a response that the cache serves to everyone.",
        "business_impact": "An attacker can serve other users a modified page: a redirect elsewhere, injected script, or a broken page.",
        "remediation_steps": [
            "Stop using headers such as X-Forwarded-Host or X-Original-URL to build responses unless the cache keys on them",
            "Strip or overwrite those headers at the edge before they reach the application",
            "Add Vary for any header that legitimately changes the response",
            "Do not cache responses that reflect request input",
        ],
        "code_examples": {
            "nginx": """proxy_set_header X-Forwarded-Host $host;   # overwrite, never pass the client's value
proxy_set_header X-Original-URL "";""",
        },
        "documentation_links": ["https://portswigger.net/web-security/web-cache-poisoning"],
        "verification": "Send the request with the poisoning header, then fetch it without; the second response must not reflect it",
        "effort": "hours",
    },
    "http_request_smuggling": {
        "title": "HTTP Request Smuggling",
        "severity_base": "high",
        "cwe": "CWE-444",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The front end and the back end disagree on where a request ends, so part of one request is treated as the start of another.",
        "business_impact": "Attackers can prefix other users' requests: hijack sessions, bypass front-end access rules, or poison caches.",
        "remediation_steps": [
            "Reject requests that carry both Content-Length and Transfer-Encoding, or an ambiguous Transfer-Encoding",
            "Normalize requests at the edge and keep proxies and servers current",
            "Use HTTP/2 end to end where possible",
            "As a stopgap, disable connection reuse between the proxy and the back end",
        ],
        "code_examples": {},
        "documentation_links": ["https://portswigger.net/web-security/request-smuggling"],
        "verification": "Repeat the smuggling probe after the change and confirm it is refused",
        "effort": "days",
    },
    "api_excessive_data": {
        "title": "Sensitive Data in API Response",
        "severity_base": "medium",
        "cwe": "CWE-213",
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "description": "An API response returns fields the caller should not see, such as secrets, internal identifiers or other users' personal data.",
        "business_impact": "Data leaks to every client, including attackers who only read responses.",
        "remediation_steps": [
            "Return only the fields the client needs, through response schemas or allowlisted serializers",
            "Never serialize whole database models",
            "Filter fields by the caller's permissions",
            "Rotate any secret that appeared in a response",
        ],
        "code_examples": {},
        "documentation_links": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
        "verification": "Call the endpoint as an ordinary user and confirm the sensitive fields are gone",
        "effort": "hours",
    },
    "vulnerable_js_library": {
        "title": "Vulnerable JavaScript Library",
        "severity_base": "medium",
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "description": "The page loads a JavaScript library version with a published vulnerability.",
        "business_impact": "Attackers can use the known weakness if the vulnerable code path is reachable, often to run script in users' browsers.",
        "remediation_steps": [
            "Upgrade the library to a release that fixes the advisory named in the finding",
            "Rebuild and redeploy the bundle so the old copy is no longer served",
            "Run a dependency audit in CI so new advisories fail the build",
        ],
        "code_examples": {"npm": "npm install <library>@latest && npm audit"},
        "documentation_links": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        "verification": "npm ls <library>   # the fixed version is the only one installed",
        "effort": "hours",
    },
    "broken_authorization": {
        "title": "Broken Authorization",
        "severity_base": "high",
        "cwe": "CWE-285",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "An action that should need a specific role, owner or approval completed without it.",
        "business_impact": "Users can perform actions, or approve them, beyond what they are allowed.",
        "remediation_steps": [
            "Check the caller's permission for the action and the object on the server, on every request",
            "Deny by default; grant actions explicitly per role",
            "Enforce approval steps in the workflow's state on the server, not only in the interface",
            "Add tests that call the endpoint as a user without the permission",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
        "verification": "Repeat the request as a user without the permission and confirm it is refused",
        "effort": "days",
    },
    # ------------------------------------------------------------------ Client-side code
    "prototype_pollution": {
        "title": "Client-Side Prototype Pollution",
        "severity_base": "medium",
        "cwe": "CWE-1321",
        "owasp": "A03:2021 - Injection",
        "description": "Client code merges or assigns properties from untrusted input in a way that can reach Object.prototype.",
        "business_impact": "Polluted properties change how the rest of the code behaves and often lead to DOM XSS.",
        "remediation_steps": [
            "Do not merge untrusted objects recursively; copy only expected keys",
            "Reject __proto__, constructor and prototype keys in parsers and merge helpers",
            "Use Map or Object.create(null) for lookup tables built from input",
            "Update libraries with known prototype-pollution fixes",
        ],
        "code_examples": {
            "javascript": """const BLOCKED = new Set(['__proto__', 'constructor', 'prototype'])
for (const [key, value] of Object.entries(input)) {
  if (!BLOCKED.has(key)) target[key] = value
}""",
        },
        "documentation_links": ["https://portswigger.net/web-security/prototype-pollution"],
        "verification": "Load the page with ?__proto__[polluted]=1 and confirm ({}).polluted is undefined",
        "effort": "hours",
    },
    "postmessage_origin": {
        "title": "postMessage Handler Without Origin Check",
        "severity_base": "medium",
        "cwe": "CWE-346",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "A message event handler uses event.data without checking which origin sent it.",
        "business_impact": "Any site that opens or frames the page can send it messages and drive what the handler does.",
        "remediation_steps": [
            "Check event.origin against an allowlist before using the message",
            "Validate the message's shape and types",
            "When sending, name the exact target origin instead of '*'",
        ],
        "code_examples": {
            "javascript": """window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') return
  // handle event.data
})""",
        },
        "documentation_links": ["https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns"],
        "verification": "Send a message from another origin and confirm the handler ignores it",
        "effort": "minutes",
    },
    # ------------------------------------------------------------------ DNS and disclosure policy
    "missing_security_txt": {
        "title": "security.txt Missing",
        "severity_base": "info",
        "cwe": None,
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The site publishes no /.well-known/security.txt.",
        "business_impact": "Researchers who find a vulnerability have no published way to report it.",
        "remediation_steps": [
            "Publish /.well-known/security.txt with at least Contact and Expires (RFC 9116)",
            "Renew Expires before it lapses",
        ],
        "code_examples": {
            "security.txt": """Contact: mailto:security@example.com
Expires: 2027-12-31T23:00:00.000Z
Preferred-Languages: en""",
        },
        "documentation_links": ["https://www.rfc-editor.org/rfc/rfc9116"],
        "verification": "curl -s https://example.com/.well-known/security.txt",
        "effort": "minutes",
    },
    "missing_caa": {
        "title": "CAA Record Missing",
        "severity_base": "info",
        "cwe": "CWE-295",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The domain has no CAA record naming the certificate authorities allowed to issue for it.",
        "business_impact": "Any public CA may issue a certificate for the domain, which widens the room for mis-issuance.",
        "remediation_steps": [
            "Publish CAA records for the CAs you use",
            "Add an iodef record to be told about refused requests",
        ],
        "code_examples": {
            "dns": """example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 iodef "mailto:security@example.com\"""",
        },
        "documentation_links": ["https://www.rfc-editor.org/rfc/rfc8659"],
        "verification": "dig +short CAA example.com",
        "effort": "minutes",
    },
    "mta_sts": {
        "title": "Mail Transport Security Not Enforced",
        "severity_base": "low",
        "cwe": "CWE-319",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "The domain publishes no MTA-STS policy or TLS-RPT reporting address.",
        "business_impact": "Mail sent to the domain can be downgraded to plaintext in transit without anyone noticing.",
        "remediation_steps": [
            "If the domain receives mail, publish an MTA-STS policy in testing mode, then enforce it",
            "Publish a TLS-RPT record to receive reports of delivery failures",
            "If the domain sends and receives no mail, accept this as informational (a null MX record states it)",
        ],
        "code_examples": {
            "dns": """_mta-sts.example.com.  TXT "v=STSv1; id=20261001"
_smtp._tls.example.com. TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com\"""",
            "mta-sts.txt": """# served at https://mta-sts.example.com/.well-known/mta-sts.txt
version: STSv1
mode: testing
mx: mail.example.com
max_age: 86400""",
        },
        "documentation_links": ["https://www.rfc-editor.org/rfc/rfc8461", "https://www.rfc-editor.org/rfc/rfc8460"],
        "verification": "dig +short TXT _mta-sts.example.com",
        "effort": "hours",
    },
    "dnssec": {
        "title": "DNSSEC Not Enabled",
        "severity_base": "info",
        "cwe": "CWE-350",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The domain's DNS answers are not signed with DNSSEC.",
        "business_impact": "Resolvers cannot detect forged answers, which helps DNS spoofing and cache poisoning.",
        "remediation_steps": [
            "Enable DNSSEC signing at the DNS provider",
            "Publish the DS record at the registrar",
            "Monitor signing and key rollovers; a broken chain makes the domain unreachable",
        ],
        "code_examples": {},
        "documentation_links": ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"],
        "verification": "dig +dnssec example.com | grep -i rrsig",
        "effort": "hours",
    },
    # ------------------------------------------------------------------ AI applications (OWASP LLM Top 10, 2025)
    "ai_prompt_injection": {
        "title": "Prompt Injection",
        "severity_base": "high",
        "cwe": "CWE-1427",
        "owasp": "LLM01:2025 - Prompt Injection",
        "description": "Instructions in user input, documents or tool results changed what the model did.",
        "business_impact": "An attacker can make the assistant ignore its rules, reveal data or take actions on their behalf.",
        "remediation_steps": [
            "Treat everything the model reads (user input, retrieved documents, tool output) as untrusted",
            "Enforce permissions in the tools and the application, never only in the prompt",
            "Require confirmation outside the model for consequential actions",
            "Keep untrusted content separated and labelled in the prompt",
            "Re-run AI Gate after changes to confirm the probe no longer succeeds",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm01-prompt-injection/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "days",
    },
    "ai_sensitive_output": {
        "title": "Sensitive Data in AI Responses",
        "severity_base": "high",
        "cwe": "CWE-200",
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
        "description": "The assistant's response contained credentials, personal data or other information the user should not receive.",
        "business_impact": "Secrets and other people's data leak to whoever asks the right question.",
        "remediation_steps": [
            "Keep secrets and other users' data out of everything the model can read: prompts, context and retrieval",
            "Scope retrieval and tool results to the requesting user's permissions",
            "Scan responses for credentials and personal data before returning them",
            "Rotate any credential that appeared in a response",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "days",
    },
    "ai_system_prompt_leakage": {
        "title": "System Prompt Leakage",
        "severity_base": "medium",
        "cwe": "CWE-200",
        "owasp": "LLM07:2025 - System Prompt Leakage",
        "description": "The assistant revealed its system prompt or internal policy text.",
        "business_impact": "Attackers learn the rules to work around and anything placed in the prompt, such as names, internal processes or credentials.",
        "remediation_steps": [
            "Assume the system prompt is public: remove secrets and sensitive internal details from it",
            "Enforce rules in application code, not only in prompt text",
            "Detect and block responses that repeat the system prompt",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "hours",
    },
    "ai_improper_output": {
        "title": "Unsafe Handling of Model Output",
        "severity_base": "high",
        "cwe": "CWE-116",
        "owasp": "LLM05:2025 - Improper Output Handling",
        "description": "Model output contained executable content (HTML, script, markup or commands) that the application may render or run.",
        "business_impact": "A manipulated response can run script in users' browsers or reach interpreters behind the application.",
        "remediation_steps": [
            "Encode model output for where it lands: HTML-escape it and never render it as raw HTML",
            "Never pass model output to eval, a shell, SQL or a template engine",
            "Validate structured output against a strict schema and refuse what does not match",
            "Add a Content Security Policy as a second line of defense",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "hours",
    },
    "ai_excessive_agency": {
        "title": "Excessive Agency",
        "severity_base": "high",
        "cwe": "CWE-862",
        "owasp": "LLM06:2025 - Excessive Agency",
        "description": "The agent took, or agreed to take, an action without the authorization or approval it needs.",
        "business_impact": "A manipulated conversation can send messages, change data or spend money in the user's name.",
        "remediation_steps": [
            "Give the agent only the tools and permissions the task needs",
            "Require human approval for consequential actions, enforced by the application so the model cannot skip it",
            "Run tools with the requesting user's permissions, not a broad service account",
            "Log every tool action and rate-limit them",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm062025-excessive-agency/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "days",
    },
    "ai_cross_tenant": {
        "title": "Cross-Account Access Through the AI Application",
        "severity_base": "critical",
        "cwe": "CWE-639",
        "owasp": "LLM06:2025 - Excessive Agency",
        "description": "The assistant acted on, or returned, another account's data.",
        "business_impact": "One user can read or change another user's or tenant's data by asking the assistant.",
        "remediation_steps": [
            "Check ownership in every tool and retrieval call using the authenticated identity, never an identifier the model supplies",
            "Partition retrieval indexes per tenant, or filter by tenant on every query",
            "Test with two accounts that each cannot reach the other's data",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
        "verification": "Retest the finding with AI Gate using two principals",
        "effort": "days",
    },
    "ai_trace_disclosure": {
        "title": "Sensitive Data in Agent Traces",
        "severity_base": "high",
        "cwe": "CWE-532",
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
        "description": "Agent traces or logs exposed secrets, prompts or tool data to someone who should not see them.",
        "business_impact": "Traces collect everything the agent touched; exposing them leaks credentials and user data in bulk.",
        "remediation_steps": [
            "Redact secrets and personal data from traces before they are stored",
            "Restrict trace access to operators who need it",
            "Never return traces or their artifacts to end users",
            "Set a retention period and delete old traces",
        ],
        "code_examples": {},
        "documentation_links": ["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"],
        "verification": "Retest the finding with AI Gate",
        "effort": "hours",
    },
    "ai_unbounded_consumption": {
        "title": "Unbounded Model Consumption",
        "severity_base": "medium",
        "cwe": "CWE-770",
        "owasp": "LLM10:2025 - Unbounded Consumption",
        "description": "Requests could make the model produce unbounded output or loop without a stop.",
        "business_impact": "An attacker can run up cost and exhaust capacity for everyone else.",
        "remediation_steps": [
            "Cap output tokens per request and requests per user",
            "Cap retries, tool calls and agent loop iterations",
            "Set timeouts and alert on unusual spend",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "hours",
    },
    "ai_mcp_trust": {
        "title": "Untrusted MCP Server",
        "severity_base": "high",
        "cwe": "CWE-829",
        "owasp": "LLM03:2025 - Supply Chain",
        "description": "The agent connected to, or kept trusting, an MCP server whose identity or tools were not verified.",
        "business_impact": "A malicious or swapped server can inject instructions through tool descriptions and receive the agent's data.",
        "remediation_steps": [
            "Allow only approved MCP servers, pinned by URL and TLS identity",
            "Re-approve a server when its tool list or descriptions change",
            "Review tool descriptions for embedded instructions",
            "Give each server its own narrowly scoped credentials",
        ],
        "code_examples": {},
        "documentation_links": ["https://modelcontextprotocol.io/specification/latest/basic/security_best_practices"],
        "verification": "Retest the finding with AI Gate",
        "effort": "days",
    },
    "ai_memory_poisoning": {
        "title": "Unvalidated Agent Memory",
        "severity_base": "high",
        "cwe": "CWE-1427",
        "owasp": "LLM04:2025 - Data and Model Poisoning",
        "description": "Input could write instructions or false facts into the agent's persistent memory.",
        "business_impact": "A planted memory keeps influencing later conversations, including other users' if memory is shared.",
        "remediation_steps": [
            "Require approval for persistent memory writes and record where each came from",
            "Keep memory per user and never share it across users or tenants",
            "Treat recalled memory as untrusted input",
            "Let users review and delete what is remembered",
        ],
        "code_examples": {},
        "documentation_links": ["https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/"],
        "verification": "Retest the finding with AI Gate",
        "effort": "days",
    },
}

FINDING_TYPE_REMEDIATIONS.update(DEVICE_REMEDIATIONS)

# Nuclei template ids (evidence.template_id), matched exactly. Only ids reviewed from the pinned
# template bundle (api/scan/work_manifests.py); their titles ("Git Credentials - Detect") name no
# keyword the title table knows. http-missing-security-headers is left to the per-header match.
TEMPLATE_REMEDIATION: dict[str, str] = {
    "git-config": "exposed_git",
    "git-credentials-disclosure": "exposed_secret_file",
    "openapi": "open_api_exposed",
    "server-status": "exposed_metrics_endpoint",
    "web-config": "exposed_confidential_file",
}

# A finding's check (`tool`) names its kind for these, whatever the title says.
TOOL_REMEDIATION: dict[str, str] = {
    "rate_limiting": "rate_limiting",
    "bruteforce_protection": "login_bruteforce",
    "2fa_bypass": "mfa_weakness",
    "http_methods": "risky_http_methods",
    "security_txt": "missing_security_txt",
    "cache_poisoning": "cache_poisoning",
    "http_smuggling": "http_request_smuggling",
    "webhook_checks": "webhook_signature",
    "directory_listing": "directory_listing",
    "device_policy": "device_service_policy",
    "device_tls": "device_tls_trust",
}

# Checks that report several kinds; the title picks which (first pattern that matches wins).
TOOL_TITLE_REMEDIATION: dict[str, list[tuple[str, str]]] = {
    "dns_policy": [(r"\bcaa\b", "missing_caa"), (r"mta-sts|tls-rpt", "mta_sts"), (r"dnssec", "dnssec")],
    "client_side": [(r"prototype pollution", "prototype_pollution"), (r"postmessage", "postmessage_origin")],
    "redirect_check": [(r"redirect http to https", "https_redirect")],
    "api_security": [(r"sensitive data exposed", "api_excessive_data")],
    "exposed_file": [(r"\.env\b", "exposed_secret_file"), (r".", "exposed_confidential_file")],
    "exposed_files": [(r"\.env\b", "exposed_secret_file"), (r"\.git\b", "exposed_git"), (r".", "exposed_confidential_file")],
    "package_exposure": [(r".", "exposed_confidential_file")],
    "data_exposure": [(r"aws access key", "exposed_cloud_credential"), (r".", "api_excessive_data")],
    "forced_browsing": [(r"cloud metadata|\.aws", "exposed_cloud_credential"), (r"sensitive file", "exposed_confidential_file")],
    "tls.inspect": [(r"legacy tls|weak cipher", "weak_tls")],
    "js_dependency": [(r"vulnerable javascript library", "vulnerable_js_library")],
    "approval_checks": [(r"authorization|approval", "broken_authorization")],
    "device_ssh": [
        (r"password authentication", "ssh_password_auth"),
        (r"keyboard-interactive", "ssh_keyboard_interactive"),
        (r"weak cryptographic|weak algorithm", "ssh_weak_algorithms"),
    ],
    "device_web_headers": [
        (r"\bhsts\b", "missing_hsts"),
        (r"content security policy", "missing_csp"),
        (r"framing protection", "missing_x_frame_options"),
        (r"content-type sniffing", "missing_x_content_type_options"),
        (r"cache control", "sensitive_response_caching"),
        (r"cookie", "insecure_cookies"),
    ],
    # The worker's re-verified device candidates and the device route's advisory row (which
    # carries no remediation text of its own).
    "device_candidate_verifier": [
        (r"^affected connected-device software", "device_firmware_advisory"),
        (r"^policy-denied connected-device service", "device_service_policy"),
        (r"^device ssh cryptographic posture", "ssh_weak_algorithms"),
        (r"^device https identity verification", "device_tls_trust"),
        (r"^device api authentication bypass", "broken_authorization"),
    ],
}

# Response headers named by "Missing HTTP response header: X" or "X missing".
HEADER_REMEDIATION: dict[str, str] = {
    "content-security-policy": "missing_csp",
    "strict-transport-security": "missing_hsts",
    "x-frame-options": "missing_x_frame_options",
    "x-content-type-options": "missing_x_content_type_options",
    "referrer-policy": "missing_referrer_policy",
    "permissions-policy": "missing_permissions_policy",
    "cross-origin-opener-policy": "missing_coop",
    "cross-origin-embedder-policy": "missing_coep",
    "cross-origin-resource-policy": "missing_corp",
    "x-permitted-cross-domain-policies": "missing_x_permitted_cross_domain_policies",
}
_HEADER_TITLE = re.compile(r"^(?:missing http response header:\s*(?P<named>[a-z0-9-]+)|(?P<bare>[a-z0-9-]+) (?:header )?missing)\b")

# Fixed titles from finding catalogs (AI Gate probes, Hunt workflows), normalized: lower case,
# without a trailing "(LLM0n)" or "(N occurrences)".
EXACT_TITLE_REMEDIATION: dict[str, str] = {
    "http missing security headers": "security_headers_baseline",
    "anonymous read exposes provider credential material": "exposed_cloud_credential",
    **{title: "ai_prompt_injection" for title in (
        "prompt injection compliance detected", "direct prompt injection", "hidden instructions survived document intake",
        "encoding obfuscation bypass", "authority roleplay override", "context carryover injection",
        "refusal rephrase bypass", "refusal consistency",
    )},
    **{title: "ai_sensitive_output" for title in (
        "pii or credential pattern in response", "sensitive information disclosure", "retrieved source disclosure",
        "audit secret inventory", "unverified secret exfiltration claim", "secret exfiltration via tool chain",
    )},
    **{title: "ai_system_prompt_leakage" for title in (
        "system prompt disclosure", "system prompt leakage", "internal policy summary disclosed",
        "translated prompt leakage", "simulated confidential roleplay", "leakage-adjacent refusal response",
    )},
    **{title: "ai_improper_output" for title in (
        "executable content in model output", "output format violation", "improper output handling",
        "blocked content smuggled through structured output", "json schema coercion bypass",
    )},
    **{title: "ai_excessive_agency" for title in (
        "approval bypass", "excessive agency", "excessive agency — action compliance", "ai trace approval bypass",
        "privileged sub-agent inheritance", "unfiltered multi-agent handoff",
    )},
    **{title: "ai_cross_tenant" for title in (
        "cross-account action without ownership proof", "cross-tenant agent trace context disclosed",
        "browser cross-account data bleed",
    )},
    **{title: "ai_trace_disclosure" for title in (
        "secret-bearing agent trace disclosed", "ai trace listing disclosed", "sensitive ai trace detail disclosed",
        "sensitive ai trace artifact disclosed",
    )},
    **{title: "ai_unbounded_consumption" for title in ("unbounded output / cost abuse", "retry and stop-reason bypass")},
    **{title: "ai_mcp_trust" for title in (
        "untrusted mcp server connection", "shadow mcp server rebinding", "sensitive mcp resource disclosed",
    )},
    **{title: "ai_memory_poisoning" for title in ("unvalidated agent memory injection", "unapproved agent memory write")},
}

# AI Gate probe family, for a catalog title not listed above.
AI_FAMILY_REMEDIATION: dict[str, str] = {
    "prompt_injection": "ai_prompt_injection",
    "prompt_leakage": "ai_system_prompt_leakage",
    "sensitive_disclosure": "ai_sensitive_output",
    "data_exfiltration": "ai_sensitive_output",
    "retrieval_leakage": "ai_sensitive_output",
    "improper_output": "ai_improper_output",
    "excessive_agency": "ai_excessive_agency",
    "tool_abuse": "ai_excessive_agency",
    "cross_tenant_retrieval": "ai_cross_tenant",
    "unbounded_consumption": "ai_unbounded_consumption",
}

_TITLE_SUFFIX = re.compile(r"\s*\((?:llm\d+|\d+ occurrences?)\)\s*$")


def normalized_title(title: Any) -> str:
    text = str(title or "").strip().lower()
    while True:
        stripped = _TITLE_SUFFIX.sub("", text)
        if stripped == text:
            return text
        text = stripped


def finding_type_remediation_key(finding: dict[str, Any], evidence: dict[str, Any]) -> str | None:
    """The knowledge-base key for a finding identified by its check, template id, catalog title or header."""
    title = normalized_title(finding.get("title"))
    tool = str(finding.get("tool") or "").strip().lower()
    if title in EXACT_TITLE_REMEDIATION:
        return EXACT_TITLE_REMEDIATION[title]
    template_id = str(evidence.get("template_id") or "").strip().lower()
    if template_id in TEMPLATE_REMEDIATION:
        return TEMPLATE_REMEDIATION[template_id]
    if tool in TOOL_REMEDIATION:
        return TOOL_REMEDIATION[tool]
    for pattern, key in TOOL_TITLE_REMEDIATION.get(tool, ()):
        if re.search(pattern, title):
            return key
    header = _HEADER_TITLE.match(title)
    if header:
        key = HEADER_REMEDIATION.get(header.group("named") or header.group("bare") or "")
        if key:
            return key
    family = str(evidence.get("family") or evidence.get("probe_family") or "").strip().lower()
    if str(finding.get("source") or "") == "ai_gate" or family in AI_FAMILY_REMEDIATION:
        return AI_FAMILY_REMEDIATION.get(family)
    return None


# MDN documents no page for this legacy header.
FINDING_TYPE_REMEDIATIONS["missing_x_permitted_cross_domain_policies"]["documentation_links"] = [
    "https://owasp.org/www-project-secure-headers/",
]

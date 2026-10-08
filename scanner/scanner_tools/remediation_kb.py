"""
Comprehensive remediation knowledge base with framework-specific code examples.

Provides actionable fix guidance for security findings.
"""

import json
import re
from typing import Any

from .remediation_kb_findings import FINDING_TYPE_REMEDIATIONS, finding_type_remediation_key

# ---------------------------------------------------------------------------
# Remediation Database
# ---------------------------------------------------------------------------

REMEDIATION_DATABASE: dict[str, dict[str, Any]] = {
    # =========================================================================
    # HTTP Security Headers
    # =========================================================================
    "missing_hsts": {
        "title": "HTTP Strict Transport Security (HSTS) Not Configured",
        "severity_base": "medium",
        "cwe": "CWE-319",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The server does not enforce HTTPS via HSTS header, allowing potential downgrade attacks.",
        "business_impact": "Users could be downgraded to HTTP via man-in-the-middle attacks, exposing credentials, session tokens, and sensitive data.",
        "remediation_steps": [
            "Add Strict-Transport-Security header to all HTTPS responses",
            "Set max-age to at least 31536000 (1 year)",
            "Include 'includeSubDomains' if all subdomains use HTTPS",
            "Consider 'preload' directive for browser preload list inclusion"
        ],
        "code_examples": {
            "nginx": """# Add to server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;""",
            "apache": """# Add to VirtualHost or .htaccess
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload\"""",
            "cloudflare": "Enable 'Always Use HTTPS' and 'HSTS' in SSL/TLS > Edge Certificates settings",
            "express": """const helmet = require('helmet');
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));""",
            "django": """# settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True""",
            "rails": """# config/environments/production.rb
config.force_ssl = true
config.ssl_options = { hsts: { subdomains: true, preload: true, expires: 1.year } }""",
            "nextjs": """// next.config.js
async headers() {
  return [{
    source: '/:path*',
    headers: [{
      key: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains; preload'
    }]
  }];
}"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://hstspreload.org/"
        ],
        "verification": "curl -sI https://example.com | grep -i strict-transport-security",
        "effort": "hours"
    },

    "missing_csp": {
        "title": "Content Security Policy (CSP) Not Configured",
        "severity_base": "medium",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "No Content-Security-Policy header to prevent XSS and injection attacks.",
        "business_impact": "Cross-site scripting attacks can steal user credentials, session tokens, and execute unauthorized actions on behalf of users.",
        "remediation_steps": [
            "Define a baseline CSP starting with default-src 'self'",
            "Add specific directives for scripts, styles, images, fonts",
            "Use nonces or hashes instead of 'unsafe-inline' for scripts",
            "Deploy in report-only mode first to identify issues",
            "Gradually tighten policy over time"
        ],
        "code_examples": {
            "nginx": """# Starter CSP (customize per application)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';" always;""",
            "apache": """Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\"""",
            "express": """const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    fontSrc: ["'self'"],
    frameAncestors: ["'none'"]
  }
}));""",
            "django": """# settings.py (using django-csp)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")""",
            "nextjs": """// next.config.js
async headers() {
  return [{
    source: '/:path*',
    headers: [{
      key: 'Content-Security-Policy',
      value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    }]
  }];
}""",
            "meta_tag": """<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';">"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://csp-evaluator.withgoogle.com/",
            "https://report-uri.com/home/generate"
        ],
        "verification": "curl -sI https://example.com | grep -i content-security-policy",
        "effort": "days"
    },

    "missing_x_frame_options": {
        "title": "X-Frame-Options Header Missing",
        "severity_base": "medium",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Missing X-Frame-Options allows clickjacking attacks where malicious sites can embed your page in an iframe.",
        "business_impact": "Attackers can trick users into clicking hidden buttons, potentially leading to unauthorized actions like fund transfers or account changes.",
        "remediation_steps": [
            "Add X-Frame-Options: DENY or SAMEORIGIN header",
            "Also add CSP frame-ancestors directive for modern browsers",
            "Test that legitimate iframe uses are not blocked"
        ],
        "code_examples": {
            "nginx": """add_header X-Frame-Options "DENY" always;
# Or for same-origin iframes:
add_header X-Frame-Options "SAMEORIGIN" always;""",
            "apache": """Header always set X-Frame-Options "DENY\"""",
            "express": """const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));""",
            "django": """# settings.py
X_FRAME_OPTIONS = 'DENY'""",
            "rails": """# config/application.rb
config.action_dispatch.default_headers['X-Frame-Options'] = 'DENY'"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ],
        "verification": "curl -sI https://example.com | grep -i x-frame-options",
        "effort": "hours"
    },

    "missing_x_content_type_options": {
        "title": "X-Content-Type-Options Header Missing",
        "severity_base": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Missing X-Content-Type-Options allows browsers to MIME-sniff responses, potentially executing malicious content.",
        "business_impact": "Uploaded files could be executed as scripts by browsers that MIME-sniff, leading to XSS attacks.",
        "remediation_steps": [
            "Add X-Content-Type-Options: nosniff header to all responses",
            "Ensure Content-Type headers are correctly set for all responses"
        ],
        "code_examples": {
            "nginx": """add_header X-Content-Type-Options "nosniff" always;""",
            "apache": """Header always set X-Content-Type-Options "nosniff\"""",
            "express": """const helmet = require('helmet');
app.use(helmet.noSniff());""",
            "django": """# Enabled by default via SecurityMiddleware
# settings.py
SECURE_CONTENT_TYPE_NOSNIFF = True"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        "verification": "curl -sI https://example.com | grep -i x-content-type-options",
        "effort": "hours"
    },

    # =========================================================================
    # CORS Issues
    # =========================================================================
    "cors_misconfiguration": {
        "title": "CORS Misconfiguration",
        "severity_base": "high",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Overly permissive CORS policy allows unauthorized cross-origin requests.",
        "business_impact": "Malicious websites can make authenticated requests on behalf of users, stealing data or performing unauthorized actions.",
        "remediation_steps": [
            "Never use Access-Control-Allow-Origin: * with credentials",
            "Whitelist specific trusted origins instead of reflecting Origin header",
            "Validate Origin header against an allowlist",
            "Avoid null origin reflection",
            "Limit allowed methods and headers to what's needed"
        ],
        "code_examples": {
            "express": """const cors = require('cors');
const allowedOrigins = ['https://trusted-site.com', 'https://app.example.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));""",
            "django": """# settings.py (django-cors-headers)
CORS_ALLOWED_ORIGINS = [
    "https://trusted-site.com",
    "https://app.example.com",
]
CORS_ALLOW_CREDENTIALS = True
# Never use: CORS_ALLOW_ALL_ORIGINS = True""",
            "nginx": """# Only allow specific origin
set $cors_origin "";
if ($http_origin ~* "^https://(trusted-site\\.com|app\\.example\\.com)$") {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials true always;""",
            "rails": """# config/initializers/cors.rb
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins 'https://trusted-site.com', 'https://app.example.com'
    resource '*',
      headers: :any,
      methods: [:get, :post],
      credentials: true
  end
end"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://portswigger.net/web-security/cors"
        ],
        "verification": "curl -sI -H 'Origin: https://evil.com' https://example.com | grep -i access-control",
        "effort": "hours"
    },

    # =========================================================================
    # CSRF
    # =========================================================================
    "csrf_vulnerability": {
        "title": "Cross-Site Request Forgery (CSRF) Vulnerability",
        "severity_base": "high",
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Forms lack CSRF protection, allowing attackers to trick users into performing unintended actions.",
        "business_impact": "Attackers can force authenticated users to transfer funds, change passwords, modify account settings, or perform any state-changing action.",
        "remediation_steps": [
            "Implement CSRF tokens for all state-changing operations",
            "Use SameSite=Strict or SameSite=Lax on session cookies",
            "Validate Origin and Referer headers as defense-in-depth",
            "Require re-authentication for sensitive operations"
        ],
        "code_examples": {
            "django": """# settings.py
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

# In templates
<form method="post">
    {% csrf_token %}
    ...
</form>""",
            "express": """const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({
  cookie: {
    sameSite: 'strict',
    httpOnly: true,
    secure: true
  }
}));

// In route handler
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});""",
            "rails": """# application_controller.rb
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# In views
<%= form_with do |f| %>
  <%= hidden_field_tag :authenticity_token, form_authenticity_token %>
<% end %>""",
            "laravel": """// In Blade templates
<form method="POST">
    @csrf
    ...
</form>

// For AJAX (add to meta tag)
<meta name="csrf-token" content="{{ csrf_token() }}">

// In JavaScript
axios.defaults.headers.common['X-CSRF-TOKEN'] =
  document.querySelector('meta[name="csrf-token"]').content;""",
            "nextjs": """// Using next-csrf or similar
import { csrfToken } from 'next-auth/react';

export default function Form({ csrfToken }) {
  return (
    <form method="post">
      <input name="csrfToken" type="hidden" defaultValue={csrfToken} />
    </form>
  );
}"""
        },
        "documentation_links": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        ],
        "verification": "Inspect form HTML for csrf_token, _token, or authenticity_token hidden fields",
        "effort": "days"
    },

    # =========================================================================
    # SQL Injection
    # =========================================================================
    "sql_injection": {
        "title": "SQL Injection Vulnerability",
        "severity_base": "critical",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "description": "Application is vulnerable to SQL injection, allowing attackers to read, modify, or delete database data.",
        "business_impact": "Complete database compromise including customer PII, financial data, and credentials. Potential for lateral movement to other systems via database server access.",
        "remediation_steps": [
            "Use parameterized queries/prepared statements for ALL database queries",
            "Implement input validation with allowlisting",
            "Apply principle of least privilege to database accounts",
            "Enable query logging and anomaly detection",
            "Consider Web Application Firewall (WAF) as additional layer"
        ],
        "code_examples": {
            "python_psycopg2": """# VULNERABLE - string concatenation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE - parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))""",
            "python_sqlalchemy": """# SECURE with ORM (recommended)
user = session.query(User).filter(User.id == user_id).first()

# SECURE with raw SQL and bindparams
from sqlalchemy import text
stmt = text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id)
result = session.execute(stmt)""",
            "nodejs_pg": """// VULNERABLE
client.query(`SELECT * FROM users WHERE id = ${userId}`);

// SECURE - parameterized
client.query('SELECT * FROM users WHERE id = $1', [userId]);""",
            "java_jdbc": """// VULNERABLE
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// SECURE - PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();""",
            "php_pdo": """// VULNERABLE
$stmt = $pdo->query("SELECT * FROM users WHERE id = $id");

// SECURE - prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);""",
            "django": """# SECURE with ORM (default)
user = User.objects.get(id=user_id)

# SECURE with raw SQL
User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])"""
        },
        "documentation_links": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection"
        ],
        "verification": "Review code for string concatenation in SQL queries; test with sqlmap in safe mode",
        "effort": "days"
    },

    # =========================================================================
    # XSS
    # =========================================================================
    "xss_vulnerability": {
        "title": "Cross-Site Scripting (XSS) Vulnerability",
        "severity_base": "high",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "Application reflects user input without proper encoding, allowing script injection.",
        "business_impact": "Attackers can steal session cookies, credentials, perform actions as the user, deface the website, or redirect to malicious sites.",
        "remediation_steps": [
            "Implement output encoding based on context (HTML, JavaScript, URL, CSS)",
            "Use templating engines with auto-escaping enabled",
            "Implement Content Security Policy (CSP)",
            "Validate and sanitize all user inputs",
            "Use HTTPOnly flag on session cookies"
        ],
        "code_examples": {
            "javascript": """// VULNERABLE - innerHTML with user input
element.innerHTML = userInput;

// SECURE - textContent (automatic encoding)
element.textContent = userInput;

// SECURE - with sanitization library (DOMPurify)
element.innerHTML = DOMPurify.sanitize(userInput);""",
            "react": """// SECURE by default - React escapes values
<div>{userInput}</div>

// VULNERABLE - dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />  // AVOID!

// If needed, sanitize first
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />""",
            "django": """# SECURE by default - Django auto-escapes
{{ user_input }}

# VULNERABLE - marking as safe
{{ user_input|safe }}  # Only use with trusted/sanitized content

# Sanitize if HTML needed
import bleach
safe_html = bleach.clean(user_input, tags=['p', 'b', 'i'])""",
            "express_ejs": """<!-- VULNERABLE -->
<%- userInput %>

<!-- SECURE - HTML encoded -->
<%= userInput %>""",
            "php": """// VULNERABLE
echo $userInput;

// SECURE
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');"""
        },
        "documentation_links": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/xss/"
        ],
        "verification": "Test with payloads like <script>alert(1)</script> and check if encoded in response",
        "effort": "days"
    },

    # =========================================================================
    # Exposed Files
    # =========================================================================
    "exposed_git": {
        "title": "Exposed .git Directory",
        "severity_base": "critical",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The .git directory is publicly accessible, exposing source code and potentially secrets.",
        "business_impact": "Attackers can download entire source code including hardcoded credentials, API keys, database passwords, and proprietary business logic.",
        "remediation_steps": [
            "Block access to .git directory in web server configuration immediately",
            "Remove .git from deployed artifacts (use clean builds)",
            "Rotate all credentials that may have been committed",
            "Audit git history for secrets using truffleHog or git-secrets",
            "Set up pre-commit hooks to prevent future secret commits"
        ],
        "code_examples": {
            "nginx": """# Block .git access
location ~ /\\.git {
    deny all;
    return 404;
}""",
            "apache": """# Block .git access
<DirectoryMatch "^\\.git">
    Require all denied
</DirectoryMatch>

# Or in .htaccess
RedirectMatch 404 /\\.git""",
            "cloudflare": """# WAF Rule
# URI Path contains "/.git" -> Block""",
            "docker": """# In Dockerfile - exclude .git from build
COPY --chown=app:app . /app/
RUN rm -rf /app/.git

# Or use .dockerignore
# .dockerignore contents:
.git
.gitignore""",
            "vercel": """// vercel.json
{
  "headers": [
    {
      "source": "/.git/(.*)",
      "headers": [{ "key": "X-Robots-Tag", "value": "noindex" }]
    }
  ],
  "rewrites": [
    { "source": "/.git/(.*)", "destination": "/404" }
  ]
}"""
        },
        "documentation_links": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
        ],
        "verification": "curl -sI https://example.com/.git/HEAD",
        "effort": "hours"
    },

    "exposed_env": {
        "title": "Exposed Environment File (.env)",
        "severity_base": "critical",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Environment file containing secrets is publicly accessible.",
        "business_impact": "Database credentials, API keys, encryption secrets, and other sensitive configuration exposed to attackers.",
        "remediation_steps": [
            "Block access to .env files in web server configuration immediately",
            "Rotate ALL credentials in the exposed .env file",
            "Move secrets to proper secret management (AWS Secrets Manager, Vault, etc.)",
            "Audit access logs to determine if file was accessed"
        ],
        "code_examples": {
            "nginx": """# Block dotfiles
location ~ /\\. {
    deny all;
    return 404;
}""",
            "apache": """# Block dotfiles
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>""",
            "htaccess": """# Deny access to dotfiles
<FilesMatch "^\\.">
    Order allow,deny
    Deny from all
</FilesMatch>"""
        },
        "documentation_links": [
            "https://12factor.net/config"
        ],
        "verification": "curl -sI https://example.com/.env",
        "effort": "hours"
    },
    "weak_csp": {
        "title": "Content Security Policy Allows Unsafe Sources",
        "severity_base": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A Content Security Policy is set, but a directive weakens it: 'unsafe-inline' or 'unsafe-eval' script or style sources, or no Trusted Types requirement.",
        "business_impact": "An injection that a strict policy would block can still run script, so the policy gives less protection against XSS than it appears to.",
        "remediation_steps": [
            "Replace 'unsafe-inline' scripts with nonces or hashes, and move inline handlers into script files",
            "Remove 'unsafe-eval' by replacing eval, new Function and string timers in application code",
            "Roll out the stricter policy with Content-Security-Policy-Report-Only first and watch the reports",
            "Consider require-trusted-types-for 'script' once DOM sinks are covered"
        ],
        "code_examples": {
            "header": """Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'none'""",
            "nginx": """# A per-request nonce must be generated by the application and injected into script tags
add_header Content-Security-Policy "script-src 'self' 'nonce-$request_id'; object-src 'none'; base-uri 'none'" always;"""
        },
        "documentation_links": [
            "https://web.dev/articles/strict-csp",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
        ],
        "verification": "curl -sI https://example.com | grep -i content-security-policy   # no unsafe-inline or unsafe-eval",
        "effort": "days"
    },
    "exposed_secret_file": {
        "title": "Publicly Served File Containing Secrets",
        "severity_base": "high",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A file that holds secrets (passwords, tokens, keys, connection strings) is served to anyone who requests it, for example a .env file or a framework heap or configuration dump.",
        "business_impact": "Whoever fetched the file holds working secrets: database access, third-party API keys, signing keys. Removing the file does not revoke what was already copied.",
        "remediation_steps": [
            "Stop serving the file now: remove it from the web root or deny the path in the web server or proxy",
            "Rotate every secret the file contained; treat each one as compromised",
            "Check access logs for earlier requests to the path to learn whether, and since when, it was read",
            "Keep secrets out of deployable files: inject them at runtime from a secret manager",
            "Disable framework diagnostic endpoints (heap dumps, environment and configuration dumps) in production"
        ],
        "code_examples": {
            "nginx": """# Deny dotfiles and dump files anywhere under the site
location ~ /\\.(?!well-known) { deny all; return 404; }
location ~* \\.(env|hprof|dump)$ { deny all; return 404; }""",
            "apache": """<FilesMatch "^\\.|\\.(env|hprof|dump)$">
    Require all denied
</FilesMatch>""",
            "spring": """# application-prod.properties: expose only health and info
management.endpoints.web.exposure.include=health,info
management.endpoint.heapdump.enabled=false
management.endpoint.env.enabled=false"""
        },
        "documentation_links": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://12factor.net/config"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/.env   # expect 403 or 404",
        "effort": "hours"
    },
    "exposed_private_key": {
        "title": "Exposed Private Key",
        "severity_base": "critical",
        "cwe": "CWE-321",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "A private key (SSH, TLS, PGP or signing key) is served publicly.",
        "business_impact": "Anyone with the key can impersonate the server or user it belongs to: log in over SSH, decrypt or forge TLS traffic, or sign code and tokens as you.",
        "remediation_steps": [
            "Stop serving the file now and remove it from the web root and the deployed artifact",
            "Treat the key as compromised: revoke it (remove it from authorized_keys, revoke the certificate, or revoke the signing key) and issue a new key pair",
            "Replace the public key wherever the old one is trusted: servers, CI, certificate authorities, package registries",
            "Review logs for use of the old key since it was first exposed",
            "Store private keys outside the web root with owner-only permissions, or in a key vault or HSM"
        ],
        "code_examples": {
            "nginx": """location ~* (id_rsa|id_ecdsa|id_ed25519|\\.pem|\\.key)$ { deny all; return 404; }""",
            "shell": """# On each host that trusted the key, delete its line from authorized_keys
KEY="$(cut -d' ' -f2 exposed_key.pub)"
grep -vF "$KEY" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new \\
  && mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys"""
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/321.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/id_rsa   # expect 403 or 404",
        "effort": "hours"
    },
    "exposed_cloud_credential": {
        "title": "Exposed Cloud Credentials",
        "severity_base": "critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Cloud provider credentials (for example an AWS access key and secret) are served publicly.",
        "business_impact": "The credentials act with every permission their identity holds: reading or deleting data, starting compute at your expense, or moving deeper into the account.",
        "remediation_steps": [
            "Deactivate the exposed key at the provider immediately, then delete it once nothing depends on it",
            "Issue a new credential with the least privilege it needs, preferably a short-lived role instead of a long-lived key",
            "Review the provider's audit log (for AWS, CloudTrail) for activity by the old key since it was first exposed",
            "Remove the file from the web root and the deployed artifact",
            "Load credentials from the runtime environment (instance roles, workload identity, a secret manager), never from served files"
        ],
        "code_examples": {
            "aws_cli": """aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name <user>
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
aws iam delete-access-key --access-key-id AKIA... --user-name <user>"""
        },
        "documentation_links": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console"
        ],
        "verification": "aws iam list-access-keys --user-name <user>   # the exposed key is gone",
        "effort": "hours"
    },
    "exposed_confidential_file": {
        "title": "Exposed Confidential File",
        "severity_base": "high",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A file that should not be public (configuration, credentials store, internal document) is served to anyone who requests it.",
        "business_impact": "The file's contents are disclosed; configuration files often lead to further access.",
        "remediation_steps": [
            "Remove the file from the web root or deny the path",
            "Rotate any secret the file contained",
            "Deploy from a clean build that includes only the files the site serves",
            "Check access logs for earlier requests to the path"
        ],
        "code_examples": {},
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/538.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/<path>   # expect 403 or 404",
        "effort": "hours"
    },
    "exposed_backup_artifact": {
        "title": "Exposed Backup or Source File",
        "severity_base": "high",
        "cwe": "CWE-530",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A backup, archive or source file (.bak, .zip, .sql, an editor copy) is served publicly.",
        "business_impact": "Source code and database dumps disclose application logic, data and embedded secrets.",
        "remediation_steps": [
            "Remove backups, archives and editor copies from the web root",
            "Rotate secrets found in the exposed files",
            "Keep backups in storage the web server cannot serve",
            "Deny common backup extensions at the web server"
        ],
        "code_examples": {
            "nginx": """# Editor copies and dumps are never meant to be served; archives may be, so list those by name
location ~* \\.(bak|old|orig|swp|sql)$ { deny all; return 404; }"""
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/530.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/<path>   # expect 403 or 404",
        "effort": "hours"
    },
    "directory_listing": {
        "title": "Directory Listing Enabled",
        "severity_base": "medium",
        "cwe": "CWE-548",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The web server lists a directory's files when no index page exists.",
        "business_impact": "Attackers can browse and download every file in the directory, including files no page links to.",
        "remediation_steps": [
            "Turn off automatic directory indexes in the web server or framework",
            "Review the listed files and remove anything that should not be public",
            "Add an index page or a deny rule where a directory must stay reachable"
        ],
        "code_examples": {
            "nginx": "autoindex off;",
            "apache": "Options -Indexes",
            "express": """// serve-index exposes listings; serve static files without it
app.use(express.static('public', { index: false }))"""
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/548.html"
        ],
        "verification": "curl -s https://example.com/<directory>/ | grep -i 'index of'   # expect no match",
        "effort": "minutes"
    },
    "exposed_metrics_endpoint": {
        "title": "Public Metrics Endpoint",
        "severity_base": "medium",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A monitoring endpoint (for example Prometheus /metrics) is served publicly.",
        "business_impact": "Metrics reveal internal hostnames, versions, routes, queue and user counts, and sometimes credentials embedded in labels.",
        "remediation_steps": [
            "Serve metrics on an internal port or interface the public cannot reach",
            "If it must be reachable, require authentication or restrict it to the monitoring system's addresses",
            "Remove sensitive values from metric labels"
        ],
        "code_examples": {
            "nginx": """location /metrics {
    allow 10.0.0.0/8;   # the monitoring network
    deny all;
}"""
        },
        "documentation_links": [
            "https://prometheus.io/docs/operating/security/"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/metrics   # expect 403 or 404",
        "effort": "hours"
    },
    "exposed_actuator": {
        "title": "Framework Management Endpoint Reachable",
        "severity_base": "low",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A framework management endpoint (for example Spring Boot Actuator) answers publicly.",
        "business_impact": "Management endpoints disclose configuration and can expose heap dumps, environment variables or shutdown controls when more of them are enabled.",
        "remediation_steps": [
            "Expose only health and info publicly, or move management endpoints to a separate internal port",
            "Require authentication for every other management endpoint"
        ],
        "code_examples": {
            "spring": """management.server.port=9090          # internal only
management.endpoints.web.exposure.include=health,info"""
        },
        "documentation_links": [
            "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/actuator/env   # expect 401, 403 or 404",
        "effort": "hours"
    },
    "exposed_debug_interface": {
        "title": "Debug or Diagnostic Page Served Publicly",
        "severity_base": "medium",
        "cwe": "CWE-215",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A diagnostic page meant for developers (phpinfo(), the Werkzeug debugger console, Go's /debug/pprof) answers anyone who requests it.",
        "business_impact": "These pages disclose server paths, versions, environment variables and secrets; an interactive debugger console executes code once its PIN is guessed or leaked.",
        "remediation_steps": [
            "Remove the diagnostic page or route from the production build",
            "Run the framework with debug mode off in production",
            "Rotate any secret the page displayed",
            "If a profiler must stay reachable, bind it to an internal interface"
        ],
        "code_examples": {
            "php": "// delete phpinfo.php / info.php from the web root",
            "flask": "app.run(debug=False)  # never enable the Werkzeug debugger in production",
            "go": """// serve net/http/pprof on a separate, internal-only listener
go http.ListenAndServe("127.0.0.1:6060", nil)"""
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/215.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/phpinfo.php   # expect 403 or 404",
        "effort": "minutes"
    },
    "exposed_directory_metadata": {
        "title": "Directory Metadata File Served Publicly",
        "severity_base": "low",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "A desktop file-index such as macOS .DS_Store was deployed with the site and is served publicly.",
        "business_impact": "The file lists the names of files and folders in the directory, including ones no page links to, such as backups and configuration files.",
        "remediation_steps": [
            "Delete .DS_Store files from the deployed site",
            "Exclude them from deployments (.gitignore, build ignore rules)",
            "Deny dotfiles at the web server"
        ],
        "code_examples": {
            "nginx": "location ~ /\\.(?!well-known) { deny all; return 404; }"
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/538.html"
        ],
        "verification": "curl -s -o /dev/null -w '%{http_code}' https://example.com/.DS_Store   # expect 403 or 404",
        "effort": "minutes"
    },
    "verbose_errors": {
        "title": "Verbose Error Messages",
        "severity_base": "medium",
        "cwe": "CWE-209",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Error responses include stack traces, queries, file paths or framework details.",
        "business_impact": "Internal details help attackers target specific versions, file layouts and queries.",
        "remediation_steps": [
            "Run the application in production mode, with debug output off",
            "Return a generic error page to clients and log the details server-side",
            "Add a catch-all error handler so unhandled exceptions never reach the response"
        ],
        "code_examples": {
            "django": "DEBUG = False",
            "express": """app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).send('Internal Server Error')
})"""
        },
        "documentation_links": [
            "https://cwe.mitre.org/data/definitions/209.html"
        ],
        "verification": "Trigger the error again and confirm the response holds no stack trace or query",
        "effort": "hours"
    },

    # =========================================================================
    # TLS/SSL
    # =========================================================================
    "weak_tls": {
        "title": "Weak TLS Configuration",
        "severity_base": "high",
        "cwe": "CWE-326",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Server supports outdated TLS versions or weak cipher suites.",
        "business_impact": "Encrypted traffic can be intercepted and decrypted. Non-compliant with PCI DSS, HIPAA, and other regulations.",
        "remediation_steps": [
            "Disable TLS 1.0 and TLS 1.1 (only allow TLS 1.2+)",
            "Remove weak ciphers (RC4, DES, 3DES, export ciphers)",
            "Prefer ECDHE for forward secrecy",
            "Enable TLS 1.3 if possible",
            "Test configuration with SSL Labs after changes"
        ],
        "code_examples": {
            "nginx": """# Modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;""",
            "apache": """# Modern TLS configuration
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLSessionTickets off""",
            "aws_elb": """# Use predefined security policy
# Recommended: ELBSecurityPolicy-TLS13-1-2-2021-06
# Minimum: ELBSecurityPolicy-TLS-1-2-2017-01""",
            "aws_cloudfront": """# Use TLSv1.2_2021 security policy or newer
# In distribution settings: Minimum Origin SSL Protocol -> TLSv1.2"""
        },
        "documentation_links": [
            "https://ssl-config.mozilla.org/",
            "https://www.ssllabs.com/ssltest/"
        ],
        "verification": "nmap --script ssl-enum-ciphers -p 443 example.com",
        "effort": "hours"
    },

    "certificate_expiring": {
        "title": "TLS Certificate Expiring Soon",
        "severity_base": "high",
        "cwe": "CWE-298",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "TLS certificate is expiring within 30 days.",
        "business_impact": "Expired certificates cause browser warnings, break user trust, and can completely block access to your site.",
        "remediation_steps": [
            "Renew certificate before expiration",
            "Set up automated renewal (Let's Encrypt/certbot)",
            "Configure monitoring for certificate expiration",
            "Test renewal process in staging first"
        ],
        "code_examples": {
            "certbot": """# Auto-renew Let's Encrypt certificates
sudo certbot renew --dry-run  # Test first
sudo certbot renew

# Add to crontab for automation
0 0,12 * * * root certbot renew --quiet""",
            "aws_acm": """# ACM certificates auto-renew if validated via DNS
# Verify DNS validation records are still in place
aws acm describe-certificate --certificate-arn <arn>"""
        },
        "documentation_links": [
            "https://letsencrypt.org/docs/",
            "https://certbot.eff.org/"
        ],
        "verification": "echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates",
        "effort": "hours"
    },

    "ocsp_stapling": {
        "title": "OCSP Stapling Not Configured",
        "severity_base": "low",
        "cwe": "CWE-295",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "OCSP stapling is not enabled. The server does not provide a stapled OCSP response, requiring clients to contact the CA directly for certificate revocation status.",
        "business_impact": "Without OCSP stapling, clients must make additional requests to Certificate Authority servers, increasing page load times and potentially exposing user browsing patterns to third parties.",
        "remediation_steps": [
            "Enable OCSP stapling in your web server configuration",
            "Ensure the server can reach the CA's OCSP responder",
            "Verify OCSP stapling is working with openssl s_client",
            "Consider enabling OCSP must-staple for stronger security"
        ],
        "code_examples": {
            "nginx": """# Enable OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;

# Trusted CA certificate for OCSP response verification
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;

# DNS resolver for OCSP responder lookup
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;""",
            "apache": """# Enable OCSP stapling
SSLUseStapling on
SSLStaplingCache shmcb:/var/run/ocsp(128000)
SSLStaplingReturnResponderErrors off
SSLStaplingResponderTimeout 5

# In VirtualHost
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off""",
            "haproxy": """# Enable OCSP stapling in HAProxy
bind *:443 ssl crt /etc/haproxy/certs/site.pem ocsp-update on

# Or manually update OCSP response
# haproxy-ocsp-stapling-updater.sh""",
            "caddy": """# Caddy enables OCSP stapling by default
# No additional configuration needed
# To verify: curl -I --cert-status https://example.com"""
        },
        "documentation_links": [
            "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_stapling",
            "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslusestapling",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency"
        ],
        "verification": "echo | openssl s_client -connect example.com:443 -status 2>/dev/null | grep -A 1 'OCSP Response Status'",
        "effort": "hours"
    },

    # =========================================================================
    # DNS Security
    # =========================================================================
    "missing_spf": {
        "title": "SPF Record Missing or Invalid",
        "severity_base": "medium",
        "cwe": "CWE-290",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "No SPF record to prevent email spoofing.",
        "business_impact": "Attackers can send emails appearing to come from your domain, enabling phishing attacks against customers and partners.",
        "remediation_steps": [
            "Create SPF record listing all authorized mail servers",
            "Use -all (hard fail) for strict enforcement",
            "Keep SPF record under 10 DNS lookups",
            "Test with SPF validation tools before deploying"
        ],
        "code_examples": {
            "dns_record": """# Basic SPF record
example.com.  IN  TXT  "v=spf1 include:_spf.google.com -all"

# Multiple providers
example.com.  IN  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net include:mailchimp.com -all"

# If you don't send email from this domain
example.com.  IN  TXT  "v=spf1 -all\"""",
            "cloudflare": """# Add TXT record
Type: TXT
Name: @ (or subdomain)
Content: v=spf1 include:_spf.google.com -all""",
            "route53": """# AWS CLI
aws route53 change-resource-record-sets --hosted-zone-id XXXX --change-batch '{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "example.com",
      "Type": "TXT",
      "TTL": 300,
      "ResourceRecords": [{"Value": "\\"v=spf1 include:_spf.google.com -all\\""}]
    }
  }]
}'"""
        },
        "documentation_links": [
            "https://www.spfwizard.net/",
            "https://mxtoolbox.com/spf.aspx"
        ],
        "verification": "dig TXT example.com +short | grep spf",
        "effort": "hours"
    },

    "missing_dmarc": {
        "title": "DMARC Record Missing",
        "severity_base": "medium",
        "cwe": "CWE-290",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "No DMARC policy to enforce email authentication.",
        "business_impact": "Without DMARC, SPF and DKIM failures are not enforced, and you have no visibility into email authentication failures or spoofing attempts.",
        "remediation_steps": [
            "Start with p=none to monitor without blocking",
            "Configure rua (aggregate reports) to receive data",
            "Analyze reports and fix authentication issues",
            "Gradually move to p=quarantine then p=reject"
        ],
        "code_examples": {
            "dns_record": """# Start with monitoring (p=none)
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com;"

# Quarantine policy (after monitoring)
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100;"

# Reject policy (full enforcement)
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100;\"""",
            "cloudflare": """# Add TXT record
Type: TXT
Name: _dmarc
Content: v=DMARC1; p=none; rua=mailto:dmarc@example.com;"""
        },
        "documentation_links": [
            "https://dmarc.org/overview/",
            "https://mxtoolbox.com/dmarc.aspx"
        ],
        "verification": "dig TXT _dmarc.example.com +short",
        "effort": "hours"
    },

    # =========================================================================
    # Cookie Security
    # =========================================================================
    "insecure_cookies": {
        "title": "Insecure Cookie Configuration",
        "severity_base": "medium",
        "cwe": "CWE-614",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Session cookies lack Secure, HttpOnly, or SameSite attributes.",
        "business_impact": "Session cookies can be stolen via XSS (missing HttpOnly), network interception (missing Secure), or CSRF attacks (missing SameSite).",
        "remediation_steps": [
            "Add Secure flag to all session cookies",
            "Add HttpOnly flag to prevent JavaScript access",
            "Add SameSite=Strict or SameSite=Lax",
            "Review all cookies, not just session cookies"
        ],
        "code_examples": {
            "express": """// express-session configuration
app.use(session({
  secret: 'your-secret',
  cookie: {
    secure: true,        // Only send over HTTPS
    httpOnly: true,      // Not accessible via JavaScript
    sameSite: 'strict',  // Prevent CSRF
    maxAge: 86400000     // 24 hours
  }
}));""",
            "django": """# settings.py
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'""",
            "rails": """# config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: '_app_session',
  secure: Rails.env.production?,
  httponly: true,
  same_site: :strict""",
            "php": """// php.ini or runtime
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');

// Or when setting cookie
setcookie('session', $value, [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);""",
            "laravel": """// config/session.php
'secure' => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'strict',"""
        },
        "documentation_links": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            "https://owasp.org/www-community/controls/SecureCookieAttribute"
        ],
        "verification": "Check Set-Cookie headers in browser DevTools Network tab",
        "effort": "hours"
    },

    # =========================================================================
    # GraphQL Security
    # =========================================================================
    "graphql_introspection": {
        "title": "GraphQL Introspection Enabled",
        "severity_base": "medium",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "GraphQL introspection is enabled in production, exposing the entire API schema.",
        "business_impact": "Attackers can discover all queries, mutations, and types, making it easier to find vulnerabilities and craft attacks.",
        "remediation_steps": [
            "Disable introspection in production environments",
            "Keep introspection enabled in development/staging only",
            "Implement field-level authorization regardless",
            "Consider query complexity limits and rate limiting"
        ],
        "code_examples": {
            "apollo_server": """// Apollo Server 4
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});""",
            "graphql_yoga": """// GraphQL Yoga
import { createYoga } from 'graphql-yoga'

const yoga = createYoga({
  schema,
  graphiql: process.env.NODE_ENV !== 'production',
  // Disable introspection in production
  maskedErrors: process.env.NODE_ENV === 'production',
})""",
            "graphene_django": """# settings.py
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': [
        'graphql_jwt.middleware.JSONWebTokenMiddleware',
    ],
}

# In schema.py - use middleware to block introspection
from graphql import GraphQLError

class DisableIntrospectionMiddleware:
    def resolve(self, next, root, info, **args):
        if info.field_name.startswith('__'):
            raise GraphQLError('Introspection disabled')
        return next(root, info, **args)""",
            "ruby_graphql": """# app/graphql/my_schema.rb
class MySchema < GraphQL::Schema
  disable_introspection_entry_points if Rails.env.production?
end"""
        },
        "documentation_links": [
            "https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/",
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
        ],
        "verification": 'curl -X POST -H "Content-Type: application/json" -d \'{"query":"{ __schema { types { name } } }"}\' https://example.com/graphql',
        "effort": "hours"
    },

    # =========================================================================
    # API Security
    # =========================================================================
    "open_api_exposed": {
        "title": "OpenAPI/Swagger Schema Publicly Exposed",
        "severity_base": "low",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "OpenAPI specification file is publicly accessible, revealing API structure and endpoints.",
        "business_impact": "Attackers can easily understand API structure, authentication patterns, and find potentially vulnerable endpoints.",
        "remediation_steps": [
            "Restrict access to OpenAPI endpoints in production",
            "Require authentication to access API documentation",
            "Remove sensitive information from API descriptions",
            "Disable Swagger UI in production"
        ],
        "code_examples": {
            "express_swagger": """// Only enable in development
if (process.env.NODE_ENV !== 'production') {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));
  app.get('/openapi.json', (req, res) => res.json(swaggerDoc));
}""",
            "fastapi": """# Disable docs in production
app = FastAPI(
    docs_url="/docs" if os.environ.get("ENV") != "production" else None,
    redoc_url="/redoc" if os.environ.get("ENV") != "production" else None,
    openapi_url="/openapi.json" if os.environ.get("ENV") != "production" else None,
)""",
            "django_drf": """# settings.py
REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# urls.py - Only in DEBUG mode
if settings.DEBUG:
    urlpatterns += [
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    ]""",
            "nginx": """# Block swagger/openapi endpoints
location ~ ^/(swagger|openapi|api-docs) {
    deny all;
    return 404;
}"""
        },
        "documentation_links": [
            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        ],
        "verification": "curl -sI https://example.com/openapi.json",
        "effort": "hours"
    },
}


REMEDIATION_DATABASE.update(FINDING_TYPE_REMEDIATIONS)


# ---------------------------------------------------------------------------
# Finding-to-Remediation Mapping
# ---------------------------------------------------------------------------

def _normalize_key(text: str) -> str:
    """Normalize text for matching."""
    return text.lower().replace("-", "_").replace(" ", "_")


# Mapping from finding keywords to remediation keys
FINDING_TO_REMEDIATION_MAP = {
    # Headers
    "hsts": "missing_hsts",
    "strict-transport": "missing_hsts",
    "strict_transport": "missing_hsts",
    "csp": "missing_csp",
    # A weakness in a policy that exists, matched before the bare "csp" (longest keyword first)
    "unsafe-inline": "weak_csp",
    "unsafe_inline": "weak_csp",
    "unsafe-eval": "weak_csp",
    "unsafe_eval": "weak_csp",
    "trusted types": "weak_csp",
    "content-security": "missing_csp",
    "content_security": "missing_csp",
    "x-frame": "missing_x_frame_options",
    "x_frame": "missing_x_frame_options",
    "clickjacking": "missing_x_frame_options",
    "x-content-type": "missing_x_content_type_options",
    "x_content_type": "missing_x_content_type_options",
    "nosniff": "missing_x_content_type_options",
    # CORS
    "cors": "cors_misconfiguration",
    # CSRF
    "csrf": "csrf_vulnerability",
    "cross-site request": "csrf_vulnerability",
    "cross_site_request": "csrf_vulnerability",
    # Injection
    "sql injection": "sql_injection",
    "sqli": "sql_injection",
    "xss": "xss_vulnerability",
    "cross-site scripting": "xss_vulnerability",
    "cross_site_scripting": "xss_vulnerability",
    # Exposed files
    ".git": "exposed_git",
    "git directory": "exposed_git",
    # Nuclei titles for rows saved without a template id ("Git Credentials - Detect").
    "git credentials": "exposed_secret_file",
    "git configuration": "exposed_git",
    "git_directory": "exposed_git",
    ".env": "exposed_env",
    "env file": "exposed_env",
    "environment file": "exposed_env",
    # TLS
    "weak tls": "weak_tls",
    "weak_tls": "weak_tls",
    "weak cipher": "weak_tls",
    "weak_cipher": "weak_tls",
    "tls 1.0": "weak_tls",
    "tls 1.1": "weak_tls",
    "ssl": "weak_tls",
    "certificate expir": "certificate_expiring",
    "cert expir": "certificate_expiring",
    "ocsp stapling": "ocsp_stapling",
    "ocsp_stapling": "ocsp_stapling",
    # DNS
    "spf": "missing_spf",
    "dmarc": "missing_dmarc",
    # Cookies
    "cookie": "insecure_cookies",
    "httponly": "insecure_cookies",
    "samesite": "insecure_cookies",
    # GraphQL
    "graphql introspection": "graphql_introspection",
    "graphql_introspection": "graphql_introspection",
    # API
    "openapi": "open_api_exposed",
    "swagger": "open_api_exposed",
}


# "CORS allows credentialed cross-origin reads: /api/openapi.json" is about CORS; keyword matching
# on the path after the colon gave the OpenAPI guidance.
_TRAILING_LOCATION = re.compile(r":\s+(?:/|https?://)\S*.*$")


def _evidence_dict(finding: dict[str, Any]) -> dict[str, Any]:
    value = finding.get("evidence")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def match_remediation(finding: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """Guidance for a finding and how it was matched.

    In order: ``exposure_class`` (the exposure prover's classification), ``finding_type`` (the check
    that produced it, a nuclei template id, a fixed catalog title, or the header a missing-header
    finding names), ``title`` (keywords in the title: general guidance for that kind of issue), and
    ``producer`` (the check's own remediation text kept in evidence, for findings the knowledge
    base does not know, such as per-probe device catalog titles).
    """
    evidence = _evidence_dict(finding)
    entry = get_remediation_for_exposure_class(str(evidence.get("exposure_class") or ""))
    if entry:
        return entry, "exposure_class"
    key = finding_type_remediation_key(finding, evidence)
    if key and key in REMEDIATION_DATABASE:
        return REMEDIATION_DATABASE[key].copy(), "finding_type"
    subject = _TRAILING_LOCATION.sub("", str(finding.get("title") or "")).strip()
    entry = _keyword_remediation(str(finding.get("tool") or ""), subject)
    if entry:
        return entry, "title"
    steps = _producer_steps(evidence)
    if steps:
        return {
            "title": str(finding.get("title") or "").strip() or None,
            "description": None,
            "remediation_steps": steps,
            "code_examples": {},
            "documentation_links": [],
            "verification": None,
            "effort": None,
        }, "producer"
    return None


def _producer_steps(evidence: dict[str, Any]) -> list[str]:
    """The check's own guidance from evidence: a string (one step) or a list of strings.

    ``remediation`` is what the worker persists; ``recommendation`` is where the SSH check (and rows
    saved before that) kept it. Structured values such as grading output are not guidance.
    """
    for key in ("remediation", "recommendation"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            steps = [item.strip() for item in value if item.strip()]
            if steps:
                return steps
    return []


def get_remediation_for_finding(finding: dict[str, Any]) -> dict[str, Any] | None:
    """
    Get comprehensive remediation guidance for a finding.

    Returns enriched remediation with code examples and documentation,
    or None if no specific remediation is available.
    """
    matched = match_remediation(finding)
    return matched[0] if matched else None


def _keyword_remediation(tool: str, title: str) -> dict[str, Any] | None:
    tool = (tool or "").lower()
    title = (title or "").lower()

    # Try to match by keywords
    combined = f"{tool} {title}"
    combined_norm = _normalize_key(combined)

    # Sort keywords by length descending to match longer/more specific patterns first
    # This ensures "ocsp stapling" matches before "csp" could incorrectly match
    sorted_keywords = sorted(FINDING_TO_REMEDIATION_MAP.keys(), key=len, reverse=True)

    for keyword in sorted_keywords:
        remediation_key = FINDING_TO_REMEDIATION_MAP[keyword]
        # Use word boundary matching to prevent substring false positives
        # e.g., "csp" should NOT match inside "ocsp"
        pattern = rf'\b{re.escape(keyword)}\b'
        if re.search(pattern, combined, re.IGNORECASE) or re.search(pattern, combined_norm, re.IGNORECASE):
            if remediation_key in REMEDIATION_DATABASE:
                return REMEDIATION_DATABASE[remediation_key].copy()

    return None


# The exposure prover names what it found precisely (api/capabilities/exposure_probe.py), so its
# findings map to guidance by class instead of by words in their titles.
EXPOSURE_CLASS_REMEDIATION = {
    "private_key_material": "exposed_private_key",
    "cloud_credential_material": "exposed_cloud_credential",
    "environment_secret_file": "exposed_secret_file",
    "version_control_exposure": "exposed_git",
    "confidential_file": "exposed_confidential_file",
    "backup_or_source_artifact": "exposed_backup_artifact",
    "directory_listing": "directory_listing",
    "metrics_endpoint": "exposed_metrics_endpoint",
    "actuator_endpoint": "exposed_actuator",
    "exposed_api_specification": "open_api_exposed",
    "verbose_error_disclosure": "verbose_errors",
    "actuator_secret_disclosure": "exposed_secret_file",
    "actuator_heapdump_exposed": "exposed_secret_file",
    "api_specification_secret": "exposed_secret_file",
    "configuration_secret_file": "exposed_secret_file",
    "configuration_file": "exposed_confidential_file",
    "directory_metadata_file": "exposed_directory_metadata",
    "phpinfo_disclosure": "exposed_debug_interface",
    "debug_interface_exposure": "exposed_debug_interface",
}


def get_remediation_for_exposure_class(exposure_class: str) -> dict[str, Any] | None:
    """Guidance for an exposure the prover classified, or None for an unmapped class."""
    key = EXPOSURE_CLASS_REMEDIATION.get(str(exposure_class or ""))
    return get_remediation_by_key(key) if key else None


def get_remediation_by_key(key: str) -> dict[str, Any] | None:
    """Get remediation by direct key lookup."""
    return REMEDIATION_DATABASE.get(key, {}).copy() or None


def list_available_remediations() -> list[str]:
    """List all available remediation keys."""
    return list(REMEDIATION_DATABASE.keys())


def get_code_example(
    remediation: dict[str, Any],
    framework: str | None = None
) -> str | None:
    """
    Get code example for a specific framework.

    If framework is None, returns the first available example.
    """
    examples = remediation.get("code_examples", {})

    if not examples:
        return None

    if framework:
        # Try exact match first
        if framework in examples:
            return examples[framework]
        # Try normalized match
        framework_norm = _normalize_key(framework)
        for key, code in examples.items():
            if _normalize_key(key) == framework_norm:
                return code

    # Return first available
    return next(iter(examples.values()), None)

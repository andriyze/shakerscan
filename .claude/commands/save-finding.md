# Save Finding

Save a security finding discovered during manual testing or an AI security session.

**Usage**: `/save-finding [session_id]`

## Overview

This skill helps you save findings discovered during:
- Interactive AI security sessions (`/ai-security-session`)
- Manual penetration testing
- Bug bounty hunting

Findings are persisted to the database and linked to the target for tracking.

## Instructions

### Step 1: Gather Finding Details

Ask the user for the following information (or extract from conversation context):

**Required:**
- **Title**: Short description (e.g., "BOLA on Basket API")
- **Severity**: critical, high, medium, low, or info
- **Target**: The target URL (auto-populated if session_id provided)

**Optional but recommended:**
- **Description**: Detailed explanation of the vulnerability
- **Category**: BOLA, XSS, SQLi, SSRF, IDOR, Auth Bypass, etc.
- **CWE**: CWE identifier (e.g., "CWE-639" for BOLA)
- **Evidence**: Proof of the vulnerability
- **URL**: Specific vulnerable endpoint
- **Request/Response**: HTTP traffic showing the issue
- **Remediation**: How to fix

### Step 2: Save the Finding

**If a session_id is provided (from an active AI security session):**

```bash
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "FINDING_TITLE",
    "severity": "SEVERITY",
    "description": "DESCRIPTION",
    "category": "CATEGORY",
    "cwe": "CWE-XXX",
    "evidence": "EVIDENCE",
    "url": "VULNERABLE_URL"
  }'
```

**For standalone manual findings (no session):**

```bash
curl -X POST "http://localhost:8080/findings/manual" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "title": "FINDING_TITLE",
    "severity": "SEVERITY",
    "description": "DESCRIPTION",
    "category": "CATEGORY",
    "cwe": "CWE-XXX",
    "evidence": "EVIDENCE",
    "url": "VULNERABLE_URL"
  }'
```

### Step 3: Confirm Save

Report back to the user:
- Finding ID
- Whether it was created new or matched an existing finding
- Link to view in UI: `http://localhost:3000/findings/{id}`

## Common Categories and CWEs

| Category | CWE | Description |
|----------|-----|-------------|
| BOLA/IDOR | CWE-639 | Broken Object Level Authorization |
| XSS | CWE-79 | Cross-Site Scripting |
| SQLi | CWE-89 | SQL Injection |
| SSRF | CWE-918 | Server-Side Request Forgery |
| Auth Bypass | CWE-287 | Improper Authentication |
| CSRF | CWE-352 | Cross-Site Request Forgery |
| Open Redirect | CWE-601 | URL Redirection to Untrusted Site |
| Path Traversal | CWE-22 | Path Traversal |
| Command Injection | CWE-78 | OS Command Injection |
| XXE | CWE-611 | XML External Entity |
| Insecure Deserialization | CWE-502 | Deserialization of Untrusted Data |
| Broken Access Control | CWE-284 | Improper Access Control |
| Security Misconfiguration | CWE-16 | Configuration |
| Sensitive Data Exposure | CWE-200 | Information Exposure |

## Severity Guidelines

| Severity | CVSS | Examples |
|----------|------|----------|
| **Critical** | 9.0-10.0 | RCE, Auth bypass to admin, SQLi with data exfil |
| **High** | 7.0-8.9 | BOLA with write access, Stored XSS, SSRF to internal |
| **Medium** | 4.0-6.9 | BOLA read-only, Reflected XSS, CSRF |
| **Low** | 0.1-3.9 | Information disclosure, Missing headers |
| **Info** | 0.0 | Best practice recommendations |

## Example Conversation

```
User: /save-finding abc123

Claude: I'll help you save a finding from session abc123 (target: https://juice-shop.herokuapp.com).

Based on our testing, I found a BOLA vulnerability. Let me save it:

[Executes API call]

✓ Finding saved successfully!
  - ID: f8a3b2c1-...
  - Title: BOLA on Basket API
  - Severity: Critical
  - Target: https://juice-shop.herokuapp.com

View in UI: http://localhost:3000/findings/f8a3b2c1-...
```

## Finding Sources

All findings are tagged with a `source` field to track their origin:

| Source | Description | Created By |
|--------|-------------|------------|
| `scan` | Automated scanner findings | Automated scans (quick, standard, deep, full, smart) |
| `ai_session` | AI security session discoveries | `POST /session/{id}/findings` |
| `manual` | Manual testing findings | `POST /findings/manual` |

Session findings also include a `session_id` field linking back to the original testing session.

## Tips

- **Be specific**: Include the exact endpoint, parameter, and payload in the evidence
- **Include reproduction steps**: Make findings actionable for developers
- **Link related findings**: Note if this finding enables other attacks
- **Use session context**: If saving from an AI session, reference the session for context
- **Filter by source**: Use `curl "http://localhost:8080/findings?source=ai_session"` to view only session findings

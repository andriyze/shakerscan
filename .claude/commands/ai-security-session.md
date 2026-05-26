# AI Security Session

Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` for API calls. Use `UI_BASE=${SHAKERSCAN_UI_BASE:-http://localhost:3000}` for UI links; on a remote VPS, use the URL printed by `./scanner.sh start --remote` or `./scanner.sh status`.

Interactive security testing session with Claude AI. This is a collaborative workflow for manual penetration testing where Claude analyzes the target, suggests testing approaches, and the user guides the exploration.

**Usage**: `/ai-security-session <target_url>`

## Overview

This is **not** an automated scan. Instead, it's an interactive session where:
1. Claude bootstraps from existing scan data (endpoints, tech, findings)
2. Claude analyzes the target application structure
3. Claude suggests testing approaches based on app type and existing findings
4. User directs which areas to test
5. Claude executes tests and reports findings in real-time
6. User can ask follow-up questions and explore deeper
7. Validated findings are saved to the database

**Best Practice**: Run a smart scan first (`/scan-smart <url>`), then use interactive session to validate findings and explore areas scanners miss.

## Instructions

### Step 1: Check Scanner Health

First verify the scanner API is running:
```bash
curl -s http://localhost:8080/health
```

If not running, ask user if they want to start it:
```bash
./scanner.sh start
```

### Step 2: Start Interactive Session

Start an interactive browser session for the target:
```bash
curl -X POST http://localhost:8080/session/start \
  -H "Content-Type: application/json" \
  -d '{"target": "$ARGUMENTS"}'
```

This returns a `session_id` for subsequent operations.

### Step 2.5: Bootstrap from Existing Scans (Recommended)

**Before exploring manually, check if there's existing scan data for this target.** This dramatically improves session effectiveness by providing:
- Discovered API endpoints to test
- Technology stack for tailored testing
- Existing findings to validate/exploit
- Crawled URLs to navigate

```bash
# Find existing scans for this target
curl -s "http://localhost:8080/scans?limit=5" | jq '[.scans[] | select(.target_url | contains("TARGET_DOMAIN")) | {id, status, scan_type, findings_count}]'

# If a completed scan exists, fetch its results
curl -s "http://localhost:8080/scans/{scan_id}/result" | jq '{
  endpoints: .discovery.browser_api_endpoints[:10],
  tech: .discovery.tech.items,
  crawled_urls: .discovery.browser_crawl.sampled_urls[:5]
}'

# Get existing findings for validation
curl -s "http://localhost:8080/findings?target_url=TARGET_URL&status=active" | jq '[.findings[] | {id, title, severity, url}]'
```

**If no scan exists**, ask permission to run a quick or smart scan first:
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "$ARGUMENTS", "options": {"scan_type": "smart"}}'
```

Don't wait for completion - report scan ID and continue with manual exploration while scan runs in background.

**Using Scan Context:**

| Data | Location | Use For |
|------|----------|---------|
| API endpoints | `result.discovery.browser_api_endpoints` | BOLA/IDOR testing candidates |
| Crawled URLs | `result.discovery.browser_crawl.sampled_urls` | Navigation targets |
| Tech stack | `result.discovery.tech.items` | Tailored attack vectors |
| Existing findings | `GET /findings?target_url=...` | Validation, exploitation, evidence |
| Auth tokens | `result.discovery.auth_tokens` | Multi-user testing |

### Step 3: Initial Analysis

Take a screenshot and analyze the application:
```bash
# Save screenshot directly to file (raw PNG endpoint)
curl -s "http://localhost:8080/session/{session_id}/screenshot.png" -o /tmp/session_screenshot.png
```

Then use the Read tool to view `/tmp/session_screenshot.png`.

**Important**: If the screenshot fails to load or you see "Could not process image", delete the file and retake:
```bash
rm /tmp/session_screenshot.png
curl -s "http://localhost:8080/session/{session_id}/screenshot.png" -o /tmp/session_screenshot.png
```

Optionally, submit a quick scan for background recon (don't wait for it):
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "$ARGUMENTS", "options": {"scan_type": "quick"}}'
```

**Note**: Don't poll for scan completion - scans run in background. Instead, use the session's browser capabilities to explore the app directly and discover:
- Technology stack (visible in page source, headers, JS frameworks)
- Authentication type (login forms, JWT in localStorage, cookies)
- App type (e-commerce, SaaS, API, CMS, etc.)
- API endpoints (captured automatically from network traffic)

### Step 4: Present Findings and Suggest Testing

Based on the analysis, present findings and suggest testing approaches. Tailor suggestions to the app type:

**For E-commerce/Shopping Apps:**
- BOLA/IDOR - Access other users' carts, orders, wishlists
- Business logic - Price manipulation, quantity tampering, coupon abuse
- Payment bypass - Skip payment steps, modify totals

**For SaaS/Multi-tenant Apps:**
- Tenant isolation - Access other tenants' data
- BOLA on resources - Access other users' projects, documents, settings
- Privilege escalation - User to admin, free to paid tier

**For APIs:**
- BOLA on all endpoints - Test ID parameters with different user contexts
- Mass assignment - Add admin fields to user updates
- Rate limiting - Check for enumeration opportunities

**For Auth Systems:**
- Session management - Fixation, hijacking
- JWT vulnerabilities - Algorithm confusion, weak secrets
- MFA bypass - Skip steps, brute force

Ask the user: "What would you like to focus on?"

### Step 5: Collaborative Testing

Based on user direction, help test vulnerabilities:

**For BOLA/IDOR Testing:**

1. Ask user for credentials or offer to create accounts:
   - "I need two test accounts to test cross-user access. Should I create them or do you have credentials?"

2. If creating accounts, use the session API:
   ```bash
   curl -X POST "http://localhost:8080/session/{session_id}/action" \
     -H "Content-Type: application/json" \
     -d '{
       "action": "register",
       "data": {"email": "testuser1@example.com", "password": "TestPass123!"}
     }'
   ```

3. Login as user1 and capture resources:
   ```bash
   curl -X POST "http://localhost:8080/session/{session_id}/action" \
     -H "Content-Type: application/json" \
     -d '{
       "action": "login",
       "data": {"email": "testuser1@example.com", "password": "TestPass123!"}
     }'
   ```

4. Navigate and capture resource IDs from API responses:
   ```bash
   curl -X POST "http://localhost:8080/session/{session_id}/action" \
     -H "Content-Type: application/json" \
     -d '{
       "action": "navigate",
       "url": "/cart"
     }'
   ```

5. Test cross-user access:
   ```bash
   curl -X POST "http://localhost:8080/session/{session_id}/test-endpoint" \
     -H "Content-Type: application/json" \
     -d '{
       "endpoint": "/api/BasketItems/42",
       "method": "GET",
       "as_user": "user2"
     }'
   ```

6. Report findings immediately in real-time

**For Business Logic Testing:**

1. Identify key workflows (checkout, transfer, etc.)
2. Use browser actions to interact with forms
3. Intercept and modify requests
4. Document each test and result

### Step 6: Save Findings

When you discover vulnerabilities during the session, save them to the database using the session findings API:

```bash
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on Basket API",
    "severity": "critical",
    "description": "User2 can read, modify, and delete User1 basket items via /api/BasketItems/{id}",
    "category": "BOLA",
    "cwe": "CWE-639",
    "evidence": "GET /api/BasketItems/42 with User2 JWT returns User1 basket data",
    "url": "/api/BasketItems/42"
  }'
```

Alternatively, use the `/save-finding` skill for a guided experience.

The finding will be:
- Automatically linked to the session's target
- Marked with `source: "ai_session"` and `session_id`
- Visible in the UI at `${UI_BASE}/findings`

### Step 7: Cleanup

When done testing, end the session:
```bash
curl -X DELETE "http://localhost:8080/session/{session_id}"
```

## Testing Scenarios

Interactive sessions are ideal for testing vulnerabilities that require human judgment, multi-step interactions, or context that automated scanners miss.

### Access Control Testing

| Scenario | What to Test | How to Test |
|----------|--------------|-------------|
| **Horizontal BOLA** | User A accessing User B's resources | Login as 2 users, swap resource IDs |
| **Vertical BOLA** | Regular user accessing admin resources | Test admin endpoints with user token |
| **IDOR in URLs** | Predictable IDs in paths | Increment/decrement ID parameters |
| **IDOR in POST body** | Object references in request bodies | Modify IDs in JSON payloads |
| **Function-level access** | Unauthorized actions | Call admin-only API endpoints as user |
| **Multi-tenancy bypass** | Cross-tenant data access | Test with tenant IDs from different orgs |

### Authentication & Session Testing

| Scenario | What to Test | How to Test |
|----------|--------------|-------------|
| **Session fixation** | Session ID reuse after login | Note session before login, check after |
| **Session timeout** | Sessions expire appropriately | Wait and check if token still works |
| **Concurrent sessions** | Multiple active sessions | Login from two contexts, check both |
| **JWT vulnerabilities** | Algorithm confusion, weak secrets | Decode JWT, try alg:none, test signature |
| **Token in URL** | Sensitive tokens in URLs | Check for tokens in GET parameters |
| **Logout invalidation** | Tokens invalidated on logout | Use token after logout |

### Business Logic Flaws

| Scenario | What to Test | How to Test |
|----------|--------------|-------------|
| **Price manipulation** | Client-side price changes | Intercept checkout, modify price/total |
| **Quantity tampering** | Negative or large quantities | Set quantity to -1 or 999999 |
| **Coupon abuse** | Multiple use, expired codes | Apply same coupon twice, test old codes |
| **Race conditions** | Concurrent request exploits | Rapid parallel requests to same endpoint |
| **Workflow bypass** | Skipping required steps | Access confirmation page directly |
| **Currency confusion** | Currency parameter tampering | Change currency code mid-transaction |

### API Security Testing

| Scenario | What to Test | How to Test |
|----------|--------------|-------------|
| **Mass assignment** | Adding protected fields | Include admin/role fields in user updates |
| **Parameter pollution** | Duplicate parameters | Send same param multiple times |
| **GraphQL introspection** | Schema exposure | Query __schema, __type |
| **GraphQL batching** | DoS via nested queries | Deep query nesting, batch mutations |
| **Rate limiting** | Enumeration/brute force | Rapid requests to sensitive endpoints |
| **Verbose errors** | Information disclosure | Trigger errors, check response details |

### Client-Side Testing

| Scenario | What to Test | How to Test |
|----------|--------------|-------------|
| **Reflected XSS** | Input reflected in response | Inject script in URL params |
| **Stored XSS** | Persistent script execution | Submit script in profile/comments |
| **DOM XSS** | Client-side script injection | Modify URL fragments, postMessage |
| **Open redirect** | Redirect to arbitrary URLs | Modify redirect/return/next params |
| **Clickjacking** | UI redress attacks | Check X-Frame-Options, frame target |
| **Sensitive data exposure** | Tokens in localStorage/DOM | Inspect browser storage and page source |

### When to Use Interactive Sessions vs Automated Scans

| Use Interactive Sessions When | Use Automated Scans When |
|------------------------------|-------------------------|
| Testing complex business logic | Running baseline security checks |
| Verifying BOLA with real user contexts | Scanning for known CVEs |
| Exploring authentication edge cases | Checking security headers |
| Investigating findings from automated scans | Testing large numbers of endpoints |
| Testing workflows that require judgment | Initial reconnaissance |
| Demonstrating vulnerabilities to stakeholders | Scheduled security assessments |

### Finding Validation Workflow

When existing findings need validation or further exploitation:

**1. Fetch the finding details:**
```bash
curl -s "http://localhost:8080/findings/{finding_id}" | jq '{title, severity, url, evidence, description}'
```

**2. Reproduce in session:**
- Navigate to the vulnerable endpoint
- Set up the required auth context (user accounts)
- Execute the exact payload/request from the finding
- Take screenshot as evidence

**3. Escalate/Chain findings:**
- Can XSS steal session tokens? Test with real cookies
- Can SQLi extract sensitive data? Try data exfiltration
- Can BOLA be chained with other vulns? Test combinations

**4. Update finding with validation:**
```bash
# Add validation evidence to existing finding
curl -X PATCH "http://localhost:8080/findings/{finding_id}" \
  -H "Content-Type: application/json" \
  -d '{"notes": "Validated in session {session_id}. Confirmed exploitable - able to extract user data."}'

# Or save as new finding if you discovered something new
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQLi data extraction confirmed",
    "severity": "critical",
    "description": "Chained from finding {original_id}. Successfully extracted user emails.",
    "category": "SQLi",
    "cwe": "CWE-89"
  }'
```

**Example: Validating an XSS finding:**
```
1. GET /findings?severity=high&status=active → Find XSS finding
2. Start session, navigate to vulnerable page
3. Inject the payload from finding evidence
4. Screenshot the alert/execution
5. Test if it can steal cookies (escalation)
6. Update finding with "Validated - can steal httpOnly=false cookies"
```

## Guidelines

- **Always explain what you're doing and why** - Transparency builds trust
- **Ask user for guidance when multiple paths exist** - This is collaborative
- **Report findings in real-time** - Don't wait until the end
- **Be thorough but respect user's time** - Ask before deep dives
- **Stop when user says stop** - User controls the session
- **Handle sensitive data carefully** - Don't log passwords or tokens unnecessarily
- **Save confirmed findings** - Use `/save-finding` or POST to session findings endpoint

## Example Conversation Flow

```
User: /ai-security-session https://juice-shop.example.com

Claude: Starting interactive security session for https://juice-shop.example.com...
        [Takes screenshot, runs quick scan]

        This appears to be a web shop application (OWASP Juice Shop) with:
        - Express.js backend with REST API
        - Angular frontend
        - JWT authentication
        - Shopping cart functionality
        - User reviews and feedback

        Interesting endpoints discovered:
        - /api/BasketItems/{id} - Cart items (BOLA candidate)
        - /api/Products/{id}/reviews - Product reviews
        - /api/Feedbacks - User feedback (no auth check?)
        - /rest/user/login - JWT login endpoint

        I can help test for:
        1. BOLA/IDOR - Access other users' carts, orders
        2. JWT vulnerabilities - Weak secrets, algorithm confusion
        3. Injection - SQLi in search, XSS in reviews
        4. Business logic - Price manipulation, coupon abuse

        What would you like to focus on?

User: Let's test BOLA on the cart

Claude: I'll need two test accounts to verify cross-user access.
        Should I create them or do you have existing credentials?

User: Create them

Claude: Creating test accounts...
        ✓ user1@test.com registered
        ✓ user2@test.com registered

        Logging in as user1 and adding item to cart...
        ✓ Logged in as user1
        ✓ Added "Apple Juice" to cart
        ✓ Found cart endpoint: GET /api/BasketItems/42

        Now testing if user2 can access user1's cart item...
        [Logs in as user2, requests /api/BasketItems/42]

        BOLA CONFIRMED: User2 can read User1's basket item!

        Evidence:
        - Request: GET /api/BasketItems/42 (as user2)
        - Response: 200 OK
        - Body: {"id":42,"ProductId":1,"BasketId":6,"quantity":1}

        The BasketId (6) belongs to user1, but user2 can access it.
        Severity: HIGH (OWASP API1:2023 - Broken Object Level Authorization)

        Would you like me to test if user2 can also modify or delete it?

User: Yes, test modification and deletion

Claude: Testing write operations...

        PUT /api/BasketItems/42 {"quantity": 999}
        Result: 200 OK - User2 CAN modify User1's cart quantity!

        DELETE /api/BasketItems/42
        Result: 200 OK - User2 CAN delete User1's cart items!

        Summary: Complete BOLA - User2 has full CRUD access to User1's cart.

        This is a CRITICAL vulnerability because:
        1. Attackers can view other users' shopping carts (privacy breach)
        2. Attackers can modify quantities (business logic abuse)
        3. Attackers can delete items (denial of service)

        Want to continue testing other endpoints or move to a different vulnerability type?
```

## Session API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/session/start` | POST | Start interactive browser session |
| `/session/{id}` | GET | Get session state and info |
| `/session/{id}/screenshot` | POST | Get page screenshot (JSON with base64) |
| `/session/{id}/screenshot.png` | GET | Get page screenshot (raw PNG bytes) |
| `/session/{id}/action` | POST | Execute browser action |
| `/session/{id}/test-endpoint` | POST | Test specific endpoint with auth |
| `/session/{id}/findings` | POST | Save finding discovered during session |
| `/session/{id}` | DELETE | End session and cleanup |

## Security: Scope Restrictions

By default, all navigation and endpoint testing is restricted to the **same origin** as the target to prevent SSRF attacks.

- **navigate action**: Only allows same-origin URLs
- **test-endpoint**: Only allows same-origin endpoints

To test cross-origin URLs (use with caution), set `allow_out_of_scope: true`:

```bash
# Navigate to external URL (requires explicit opt-in)
curl -X POST "http://localhost:8080/session/{id}/action" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "navigate",
    "data": {"url": "https://other-domain.com", "allow_out_of_scope": true}
  }'

# Test cross-origin endpoint
curl -X POST "http://localhost:8080/session/{id}/test-endpoint" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://api.other-domain.com/users",
    "allow_out_of_scope": true
  }'
```

## Tips

- **Bootstrap from scans first** - Always check for existing scan data before manual exploration
- **Use discovered endpoints** - `browser_api_endpoints` from scans are prime BOLA/IDOR candidates
- **Validate before exploring** - Start by validating existing high/critical findings
- **Use the screenshot feature** - Visual context helps identify UI-driven attack vectors
- **Test in layers** - Start with read access, then write, then destructive operations
- **Chain findings** - Look for combinations (XSS + weak cookies = ATO, SQLi + admin panel = full compromise)
- **Save as you go** - Use `POST /session/{id}/findings` to persist discoveries immediately
- **Recommended workflow**: `/scan-smart` → wait for completion → `/ai-security-session` → validate + explore

## Troubleshooting

### "Could not process image" error
If Claude fails to read a screenshot:
1. Delete the corrupted file: `rm /tmp/session_screenshot.png`
2. Check session is still active: `curl -s http://localhost:8080/session/{session_id}`
3. Retake screenshot using the raw endpoint: `curl -s "http://localhost:8080/session/{session_id}/screenshot.png" -o /tmp/session_screenshot.png`

### Session expired
Sessions timeout after 30 minutes of inactivity. Start a new session if needed:
```bash
curl -X POST http://localhost:8080/session/start \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Screenshot returns empty or error
Check that the browser context is valid:
```bash
# Check session status
curl -s http://localhost:8080/session/{session_id}

# If session shows no pages, try navigating first
curl -X POST "http://localhost:8080/session/{session_id}/action" \
  -H "Content-Type: application/json" \
  -d '{"action": "navigate", "data": {"url": "/"}}'
```

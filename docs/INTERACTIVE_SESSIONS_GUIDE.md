# Interactive AI Security Sessions - User Guide

**Status:** live guide, reconciled 2026-07-11. Interactive sessions are agent-driven manual testing,
not autonomous proof or permission to test a third party. Use them only for local systems or targets
you own and are authorized to test. Saving a finding is an explicit operator action.

A real-time, browser-based security testing mode where you and a coding agent collaborate to investigate
behavior that automated scans may miss. The agent drives ShakerScan's headless Playwright session API,
takes screenshots, and tests endpoints while you guide the exploration. The conversations below are
illustrative; they are not claims that a vulnerability will exist or that every action is automatic.

## What You Can Do

| Capability | Description |
|------------|-------------|
| **BOLA/IDOR Testing** | Test if User A can access User B's resources (carts, profiles, orders) |
| **Authentication Testing** | Session fixation, JWT manipulation, logout invalidation |
| **Business Logic Flaws** | Price manipulation, coupon abuse, workflow bypass, race conditions |
| **Finding Validation** | Reproduce and confirm vulnerabilities from automated scans |
| **Attack Chaining** | Combine findings (XSS + weak cookies = account takeover) |
| **Visual Evidence** | Screenshots for reports and proof of exploitation |

## How to Use

### Option 1: Quick Start

```
/ai-security-session https://juice-shop.example.com
```

Claude will analyze the app, suggest testing approaches, and ask what you want to focus on.

### Option 2: Recommended Workflow (Scan First)

```
/scan-smart https://juice-shop.example.com
```

Wait for completion, then:

```
/ai-security-session https://juice-shop.example.com
```

Claude auto-fetches discovered endpoints and existing findings to validate.

## Example Conversations

### Testing BOLA

```
You: /ai-security-session https://juice-shop.example.com

Claude: [Takes screenshot, analyzes app]
        Found shopping cart API at /rest/basket/{id}. Want to test BOLA?

You: Yes, test if users can access each other's baskets

Claude: Creating two test accounts...
        ✓ user1@test.com - basket ID 9
        ✓ user2@test.com - basket ID 10

        Testing cross-user access...
        🔴 BOLA CONFIRMED: user2 can read user1's basket!

        Want me to save this finding?

You: Yes, save it

Claude: [Saves via POST /session/{id}/findings]
        ✓ Finding saved - view at http://localhost:3000/findings/abc123
```

### Validating Scan Findings

```
You: /ai-security-session https://api.example.com

Claude: Found 3 existing findings from your last scan:
        1. SQLi in /api/search (HIGH)
        2. XSS in /api/comments (MEDIUM)
        3. Missing rate limiting (LOW)

        Which would you like to validate first?

You: Validate the SQLi

Claude: Navigating to search endpoint...
        Testing payload from finding evidence...
        [Screenshot showing SQL error]

        ✓ Confirmed exploitable. Attempting data extraction...
        Successfully extracted 5 user emails.

        This escalates from HIGH to CRITICAL. Save updated finding?
```

### Business Logic Testing

```
You: Test if I can manipulate prices at checkout

Claude: Adding item to cart (price: $29.99)...
        Intercepting checkout request...
        Modifying price to $0.01...

        🔴 Price manipulation successful! Order completed for $0.01

        This is a CRITICAL business logic flaw. Save finding?
```

### Authentication Testing

```
You: Test JWT security

Claude: Analyzing JWT from localStorage...
        Token: eyJhbGciOiJIUzI1NiIs...

        Testing:
        1. Algorithm confusion (alg:none) - ❌ Rejected
        2. Weak secret brute force - ✓ Secret is "secret"!
        3. Token expiry - Token valid for 7 days (excessive)

        🔴 JWT uses weak secret "secret" - can forge any user token

        Want me to demonstrate admin access?
```

### Multi-Tenant Isolation

```
You: Test if tenant A can access tenant B's data

Claude: Setting up two tenant contexts...
        ✓ Tenant A (acme-corp) - logged in
        ✓ Tenant B (globex) - logged in

        Testing cross-tenant API access...
        GET /api/projects with Tenant A token but Tenant B project ID...

        🔴 TENANT ISOLATION BYPASS: Tenant A can read Tenant B projects!

        This is CRITICAL for multi-tenant SaaS. Save finding?
```

## Key Commands During Session

| What You Say | What Claude Does |
|--------------|------------------|
| "Take a screenshot" | Captures current page state |
| "Login as user1/user2" | Creates separate auth contexts |
| "Test endpoint X as user2" | BOLA/IDOR cross-user test |
| "Save this finding" | Persists to database |
| "What endpoints were discovered?" | Shows API endpoints from scan/crawl |
| "Validate the SQLi finding" | Reproduces finding with real browser |
| "Test price manipulation" | Business logic testing |
| "Check JWT security" | Token analysis and attacks |
| "End session" | Cleans up browser contexts |

## Testing Scenarios Reference

### Access Control

| Test | How to Ask |
|------|------------|
| Horizontal BOLA | "Can user2 access user1's cart/profile/orders?" |
| Vertical BOLA | "Can regular user access admin endpoints?" |
| IDOR | "Test if I can access resources by changing IDs" |
| Function-level | "Can user call admin-only API functions?" |

### Authentication & Sessions

| Test | How to Ask |
|------|------------|
| Session fixation | "Check if session ID changes after login" |
| Token expiry | "How long are sessions/tokens valid?" |
| Logout | "Does logout actually invalidate the token?" |
| Concurrent sessions | "Can I have multiple active sessions?" |
| JWT attacks | "Analyze the JWT for vulnerabilities" |

### Business Logic

| Test | How to Ask |
|------|------------|
| Price manipulation | "Can I change the price at checkout?" |
| Quantity abuse | "What happens with negative quantities?" |
| Coupon stacking | "Can I apply the same coupon twice?" |
| Workflow bypass | "Can I skip the payment step?" |
| Race conditions | "Test concurrent requests to the same endpoint" |

### API Security

| Test | How to Ask |
|------|------------|
| Mass assignment | "Can I add admin:true to my profile update?" |
| Rate limiting | "Is there rate limiting on login/search?" |
| GraphQL introspection | "Can I query the GraphQL schema?" |
| Parameter pollution | "Test duplicate parameters" |

## When to Use Interactive vs Automated

| Use Interactive Session | Use Automated Scan |
|------------------------|-------------------|
| Validating scanner findings | Initial reconnaissance |
| Multi-user access control (BOLA) | Known CVE detection |
| Complex business logic | Security headers check |
| Auth flow edge cases | Large endpoint coverage |
| Generating evidence for reports | Scheduled assessments |
| Chaining vulnerabilities | Technology fingerprinting |
| Demonstrating to stakeholders | Compliance checks |

## Saving Findings

All discoveries can be saved to the database:

**Option 1: Ask Claude**
```
You: Save this finding
Claude: [Saves automatically with proper metadata]
```

**Option 2: Use the skill**
```
/save-finding {session_id}
```

**Option 3: Direct API**
```bash
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on Basket API",
    "severity": "critical",
    "category": "BOLA",
    "cwe": "CWE-639",
    "description": "User2 can access User1 basket items"
  }'
```

All findings appear in the UI at `http://localhost:3000/findings`. In the product type filter they are grouped under **AI** (`source_type=ai`) alongside AI Gate findings.

## Tips for Effective Sessions

1. **Run a scan first** - `/scan-smart` gives Claude endpoints and context to work with
2. **Start with high-severity findings** - Validate critical/high findings from scans first
3. **Test in layers** - Read access → Write access → Delete access
4. **Chain findings** - XSS + weak cookies = account takeover
5. **Save as you go** - Don't wait until the end to save findings
6. **Take screenshots** - Visual evidence is valuable for reports
7. **Be specific** - "Test BOLA on /api/orders" is better than "find vulnerabilities"

## Troubleshooting

### Session expired
Sessions timeout after 30 minutes of inactivity. Start a new one:
```
/ai-security-session https://example.com
```

### Screenshot not loading
```
You: Screenshot isn't working
Claude: [Retakes screenshot with fresh browser context]
```

### Need to switch targets
End current session first:
```
You: End session and start new one for https://other-site.com
```

## Related Commands

| Command | Description |
|---------|-------------|
| `/scan-smart <url>` | Run smart scan (do this first) |
| `/save-finding [session_id]` | Save discovered vulnerability |
| `/findings` | List all findings |
| `/status` | Check scanner status |

# Save Finding

Save an evidence-backed finding from authorized manual or interactive testing.

**Usage**: `/save-finding [session_id]`

Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` for API calls and
`UI_BASE=${SHAKERSCAN_UI_BASE:-http://localhost:3000}` for UI links. On a remote VPS, use the URLs
printed by `./scanner.sh status`; the supported agent launcher exports them automatically.

## Evidence gate

Before saving, establish:

- authorized target and exact affected endpoint
- title, severity, category, and applicable CWE
- reproducible request and response or workflow evidence
- control result that distinguishes vulnerable behavior from normal behavior
- concrete security impact
- remediation guidance

Do not save a vulnerability from a status code, reflection, route existence, version string, or
model judgment alone. If evidence is incomplete, keep it as a lead or hypothesis.

## Save from a session

The target is derived from the active session:

```bash
curl -X POST "$API_BASE/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on order detail API",
    "severity": "high",
    "description": "A distinct second principal can read the first principal order.",
    "category": "BOLA",
    "cwe": "CWE-639",
    "url": "/api/orders/42",
    "evidence": "Owner control and attacker replay evidence...",
    "request": "GET /api/orders/42 ...",
    "response": "Redacted sensitive response...",
    "remediation": "Enforce object ownership on every order lookup."
  }'
```

## Save a standalone manual finding

```bash
curl -X POST "$API_BASE/findings/manual" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://app.example.test",
    "title": "Evidence-backed finding title",
    "severity": "medium",
    "description": "What is vulnerable and why it matters.",
    "category": "Access Control",
    "cwe": "CWE-284",
    "url": "/affected/path",
    "evidence": "Reproduction and control evidence...",
    "request": "Redacted request...",
    "response": "Redacted response...",
    "remediation": "Specific corrective action."
  }'
```

Report the finding ID, whether it was created, matched, or resurfaced, and
`${UI_BASE}/findings/{id}`.

Use `source_type=ai_session` to list interactive-session findings and `source_type=manual` for
standalone manual findings:

```bash
curl "$API_BASE/findings?source_type=ai_session&status=active"
curl "$API_BASE/findings?source_type=manual&status=active"
```

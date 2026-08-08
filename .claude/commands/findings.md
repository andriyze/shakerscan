# List Security Findings

Show security findings from scans.

**Usage**: `/findings [severity|dast|ai|ai_gate|ai_session|autonomous|model_intake|asm|manual]`

## Instructions

Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` for API calls. On a remote VPS, set it
to the API URL printed by `./scanner.sh status`.

1. Check if scanner is running:
   ```bash
   curl -s "$API_BASE/health"
   ```

2. Fetch findings based on arguments:

   If no argument (show all active):
   ```bash
   curl "$API_BASE/findings?status=active&limit=50"
   ```

   If a source type is specified:
   ```bash
   curl "$API_BASE/findings?source_type=$ARGUMENTS&status=active&limit=50"
   ```

   If severity specified (critical, high, medium, low):
   ```bash
   curl "$API_BASE/findings?severity=$ARGUMENTS&status=active&limit=50"
   ```

3. Format output as a table:
   ```
   | Type | Severity | Title | Target | Tool |
   |------|----------|-------|--------|------|
   | DAST | critical | SQL Injection in /api | example.com | sqlmap |
   | AI | high | Prompt injection compliance detected | support bot | shaker-ai-gate |
   ```

4. Include summary counts at the end

Keep reported/suspected and exploit-verified findings distinct. Include the latest verification
verdict when it affects the interpretation.

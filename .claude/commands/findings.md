# List Security Findings

Show security findings from scans.

**Usage**: `/findings [severity|ai|dast]`

## Instructions

1. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```

2. Fetch findings based on arguments:

   If no argument (show all active):
   ```bash
   curl "http://localhost:8080/findings?status=active&limit=50"
   ```

   If type specified (`ai` or `dast`):
   ```bash
   curl "http://localhost:8080/findings?source_type=$ARGUMENTS&status=active&limit=50"
   ```

   If severity specified (critical, high, medium, low):
   ```bash
   curl "http://localhost:8080/findings?severity=$ARGUMENTS&status=active&limit=50"
   ```

3. Format output as a table:
   ```
   | Type | Severity | Title | Target | Tool |
   |------|----------|-------|--------|------|
   | DAST | critical | SQL Injection in /api | example.com | sqlmap |
   | AI | high | Prompt injection compliance detected | support bot | shaker-ai-gate |
   ```

4. Include summary counts at the end

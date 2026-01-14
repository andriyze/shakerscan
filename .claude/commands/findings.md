# List Security Findings

Show security findings from scans.

**Usage**: `/findings [severity]`

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

   If severity specified (critical, high, medium, low):
   ```bash
   curl "http://localhost:8080/findings?severity=$ARGUMENTS&status=active&limit=50"
   ```

3. Format output as a table:
   ```
   | Severity | Title | Target | Tool |
   |----------|-------|--------|------|
   | critical | SQL Injection in /api | example.com | sqlmap |
   | high | XSS in search | example.com | dalfox |
   ```

4. Include summary counts at the end

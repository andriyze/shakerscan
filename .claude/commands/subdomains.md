# Subdomain Discovery

Discover subdomains for a domain using CT logs and passive sources.

**Usage**: `/subdomains <domain>`

## Instructions

1. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```

2. Start subdomain discovery:
   ```bash
   curl -X POST "http://localhost:8080/discovery?root_domain=$ARGUMENTS"
   ```

3. Extract discovery_id from response

4. Poll for completion:
   ```bash
   curl http://localhost:8080/discovery/{discovery_id}
   ```

5. When complete, report:
   - Total subdomains found
   - List of subdomains (truncate if > 50)
   - Offer to add them as scan targets

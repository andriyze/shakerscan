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

3. Extract discovery_id from the response

4. Report that discovery was started and STOP — do not poll or wait. This matches the global
   asynchronous-handoff rule in AGENTS.md ("Report that discovery was started - done (don't wait)").
   Discovery can take a while; the user can check results later:
   ```bash
   # later, on request only:
   curl http://localhost:8080/discovery/{discovery_id}
   ```

5. When the user later asks for results, report:
   - Total subdomains found
   - List of subdomains (truncate if > 50)
   - Offer to add them as scan targets

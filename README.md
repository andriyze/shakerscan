# Shaker Scan - Open Source Edition

A comprehensive Dynamic Application Security Testing (DAST) scanner for web applications. Run security assessments from your local machine with a modern web UI, persistent storage, and enterprise-grade scanning capabilities.

## Contents

- [Features](#features)
- [Claude Code Integration](#claude-code-integration)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Scan Types](#scan-types)
- [Interactive Security Sessions](#interactive-security-sessions)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Integrated Tools](#integrated-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

**[Visual Walkthrough](WALKTHROUGH.md)** - Screenshots showing the terminal and web UI experience.

**[Interactive Sessions Guide](INTERACTIVE_SESSIONS_GUIDE.md)** - User guide for AI-assisted manual penetration testing.

**[Smart Scan Policy](docs/SMART_SCAN_POLICY.md)** - Budgeting, safety controls, and quality SLOs for next-gen smart scanning.

## Features

- **Comprehensive Security Scanning**
  - DNS analysis (SPF, DMARC, DKIM, DNSSEC)
  - TLS/SSL certificate validation and cipher analysis
  - HTTP security headers evaluation
  - Content discovery and technology fingerprinting
  - Headless browser crawl (Playwright) with API capture (auth-aware)
  - Subdomain enumeration (Gungnir, Subfinder, crt.sh)
  - JavaScript dependency scanning (Retire.js methodology)
  - Secret detection in client-side code

- **Active Vulnerability Testing** (opt-in)
  - XSS detection (dalfox)
  - SQL injection testing (sqlmap)
  - Nuclei templates (5000+ vulnerability checks)
  - Auth-aware Nuclei/Dalfox scanning across discovered endpoints
  - API security testing
  - CSRF, IDOR, path traversal detection

- **AI-Assisted Verification** (optional)
  - Confidence scoring and false-positive reduction
  - Cross-finding correlation signals (attack-chain hints)

- **Modern Web Interface**
  - Real-time dashboard with metrics
  - Scan management and history
  - Finding tracking with status management
  - Target organization
  - Dark theme optimized for security work

- **Production-Ready Architecture**
  - PostgreSQL for persistent storage
  - Redis-based job queue
  - Horizontal scaling (multiple workers)
  - Full API access

- **Interactive AI Security Sessions**
  - Real-time browser-based testing with Playwright
  - Multi-user BOLA/IDOR testing
  - Visual screenshots for context
  - Finding persistence to database
  - Collaborative human-AI security testing

## Claude Code Integration

This project is designed to work seamlessly with Claude Code. Just clone and open:

```bash
git clone https://github.com/andriyze/shakerscan
cd shakerscan
claude    # Claude reads CLAUDE.md and understands the project
```

### Slash Commands

| Command | Description |
|---------|-------------|
| `/scan <url>` | Quick security scan |
| `/scan-full <url>` | Full assessment (asks permission first) |
| `/scan-smart <url>` | Smart adaptive scan |
| `/ai-security-session <url>` | Interactive security testing with browser |
| `/save-finding [session_id]` | Save a discovered vulnerability |
| `/findings` | List active vulnerabilities |
| `/status` | Check scanner status |
| `/subdomains <domain>` | Discover subdomains |
| `/workers` | Manage scanner workers |

### Natural Language

Just ask Claude:
- "Scan example.com for vulnerabilities"
- "Show me critical findings"
- "Start the scanner"
- "Find subdomains for example.com"

### Project Structure

```
.claude/
├── commands/              # Slash commands
│   ├── scan.md
│   ├── scan-full.md
│   ├── scan-smart.md
│   ├── ai-security-session.md  # Interactive testing
│   ├── save-finding.md         # Persist discoveries
│   ├── findings.md
│   ├── status.md
│   ├── subdomains.md
│   └── workers.md
├── hooks/
│   └── session-start.sh   # Auto-detects scanner status
└── settings.json
```

See `CLAUDE.md` for full API reference and integration details.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- 8GB+ RAM recommended
- Linux, macOS, or Windows with WSL2

### Installation

```bash
# Clone the repository
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan

# Start the scanner (builds images on first run)
./scanner.sh start

# Or with more workers
./scanner.sh start -w 5
```

### Access

- **Web UI**: http://localhost:3000
- **API**: http://localhost:8080
- **API Docs**: http://localhost:8080/docs

### Your First Scan

```bash
# Via CLI
./scanner.sh scan https://example.com

# Via Web UI
# Navigate to http://localhost:3000 and click "New Scan"

# Via API
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

## CLI Reference

```bash
./scanner.sh [command] [options]

Commands:
  start              Start all services (API, workers, UI)
  stop               Stop all services
  restart            Restart all services
  status             Show service status and queue metrics
  logs [service]     View logs (api, worker, ui, postgres, redis)
  scan <target>           Quick scan a target
  scan-standard <target>  Standard scan (5-10 min)
  scan-deep <target>      Deep scan with full Nuclei (30-60 min)
  scan-full <target>      Full assessment with active XSS/SQLi (1-2 hrs)
  scan-aggressive <target> Maximum coverage scan (2-5 hrs)
  scan-smart <target>     Adaptive intelligent scan (variable)
  build              Build Docker images
  rebuild            Force rebuild (no cache)
  reset              Reset database (WARNING: deletes all data)
  shell              Open shell in scanner container

Options:
  -w, --workers N    Number of workers (default: 3)
  -f, --follow       Follow logs in real-time

Examples:
  ./scanner.sh start                           # Start with 3 workers
  ./scanner.sh start -w 10                     # Start with 10 workers
  ./scanner.sh scan https://example.com        # Quick scan (1-2 min)
  ./scanner.sh scan-deep https://example.com   # Deep scan (30-60 min)
  ./scanner.sh scan-full https://example.com   # Full assessment (1-2 hrs)
  ./scanner.sh scan-smart https://example.com  # Smart adaptive scan
  ./scanner.sh logs worker -f                  # Follow worker logs
```

## Scan Types

| Type | Description | Duration | Use Case |
|------|-------------|----------|----------|
| **Quick** | DNS, TLS, headers, basic tech detection | 1-2 min | Quick health check |
| **Standard** | + Nuclei (safe), cookies, CORS, JS deps (no port scan by default) | 5-10 min | Regular assessment |
| **Deep** | + Full Nuclei, top-ports scan (1000), JS secrets | 30-60 min | Thorough passive analysis |
| **Full** | + Active XSS/SQLi, all security tests | 1-2 hrs | Comprehensive audit |
| **Aggressive** | + Bruteforce, fuzzing, full port scan | 2-5 hrs | Maximum coverage |
| **Smart** | Adaptive: staged Nuclei, DBMS-aware SQLi, context-aware XSS | Variable | Intelligent targeted testing |

Notes:
- Port scanning: standard skips Nmap by default; smart runs a light top-33 scan for service hints and gRPC discovery; deep/full/aggressive run port scanning (full uses top-ports, aggressive uses full range).
- Deep discovery (ffuf-based) is opt-in via `--deep-discovery` (enabled automatically in aggressive).
- Advanced probes (SSRF/command injection) run only for full/aggressive with non-safe exploit level and parameterized endpoints.

### Smart Scan Features

The `smart` scan type uses adaptive techniques for more efficient and accurate testing:

- **Staged Nuclei scanning**: 4 waves based on tech detection + signals, with early stopping on high-confidence findings
- **Verification phase**: Browser-based XSS proofs and statistical timing analysis for SQLi confirmation
- **Attack chain analysis**: Correlates findings into exploitable attack paths (XSS→ATO, SQLi→data exfil, SSRF→cloud breach)
- **DBMS fingerprinting**: Detects SQLite, MySQL, PostgreSQL, MSSQL, Oracle and uses database-specific payloads
- **Context-aware XSS**: Detects reflection context (in_script, in_attribute, in_html) and tests GET query params plus POST/PUT/PATCH body params (JSON/form)
- **DOM XSS analysis**: Static source-to-sink flow detection in JavaScript bundles
- **POST body injection**: Tests JSON/form POST parameters for SQLi (not just GET query params)
- **Adaptive rate limiting**: Backs off on 429/503, speeds up on success
- **Recursive discovery**: Adapts crawl depth based on findings
- **Light port scan**: Top-33 scan for service hints and gRPC discovery
- **Post-nuclei refinement**: Uses nuclei signals to adapt discovery after initial scan
- **Authenticated Playwright crawl**: Multi-page headless crawl with API capture
- **JSON/HATEOAS link following**: Follows `_links`/`href` fields in API responses to expand endpoints
- **OPTIONS method discovery**: Enumerates allowed verbs to uncover POST/PUT/PATCH targets
- **Auth-aware tool routing**: Nuclei/Dalfox use discovered endpoints + auth headers when provided
- **Automated API login**: Tries JSON login endpoints when credentials are provided
- **gRPC reflection**: Enumerates gRPC services/methods when grpcurl is available
- **Synthetic endpoint gating**: Only generates synthetic API endpoints when API hints exist (or `--thorough-params` is set)
- **Coverage tracking**: Monitors endpoint/parameter/template coverage metrics

> **Note**: `full`, `aggressive`, and `smart` scans include active testing (XSS/SQLi probes). Only run these against targets you have permission to test.

Tip: Use `--xss` or `--sqli` to run only those active checks (CLI) or set `xss`/`sqli` in API options.

## Interactive Security Sessions

For manual penetration testing and complex vulnerability verification, use interactive AI security sessions. Unlike automated scans, these provide real-time browser-based testing with human guidance.

### Recommended Workflow

**Best practice**: Run a smart scan first, then use interactive session to validate findings and explore areas scanners miss.

```bash
# 1. Run automated scan first
/scan-smart https://example.com
# Wait for completion, then...

# 2. Start interactive session (auto-bootstraps from scan data)
/ai-security-session https://example.com
```

The session will automatically:
- Fetch discovered API endpoints from the scan
- Load existing findings for validation
- Use tech stack info for tailored testing

### Testing Scenarios

| Category | Use Cases |
|----------|-----------|
| **Access Control** | BOLA/IDOR, privilege escalation, tenant isolation |
| **Authentication** | Session fixation, JWT flaws, token invalidation |
| **Business Logic** | Price manipulation, coupon abuse, workflow bypass |
| **API Security** | Mass assignment, GraphQL abuse, rate limiting |
| **Client-Side** | Stored XSS, DOM XSS, open redirect |

### Saving Findings

Findings discovered during interactive sessions can be persisted to the database:

```bash
# Save from active session (target auto-populated)
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on Basket API",
    "severity": "critical",
    "category": "BOLA",
    "cwe": "CWE-639",
    "description": "User2 can access User1 basket items"
  }'

# Or use the skill
/save-finding {session_id}
```

Findings are tagged with `source: "ai_session"` and linked to the session for tracking.

### When to Use

- **Validating findings** from automated scans
- **Chaining vulnerabilities** into attack paths
- Testing complex business logic requiring judgment
- Verifying BOLA with real user authentication contexts
- Demonstrating vulnerabilities to stakeholders

See `CLAUDE.md` for full session API reference.

## API Reference

### Submit a Scan

```bash
POST /scans
{
  "target": "https://example.com",
  "options": {
    "scan_type": "standard"  # quick, standard, deep, full, aggressive, smart
  }
}

# Examples:
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "full"}}'
```

### Authenticated Scanning

Scan protected endpoints with authentication:

```bash
# Bearer token (JWT, API keys)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_header": "Bearer eyJhbGciOiJIUzI1NiIs..."
  }}'

# Session cookies
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "auth_cookies": "session=abc123; csrf_token=xyz"
  }}'

# Form-based login (auto-authenticates)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "login_username": "user@test.com",
    "login_password": "password123"
  }}'

# Custom headers (API keys, tenant IDs)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_headers_json": "{\"X-API-Key\": \"key123\", \"X-Tenant\": \"acme\"}"
  }}'

# Multi-user BOLA/IDOR testing
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_header": "Bearer user1_token",
    "user2_header": "Bearer user2_token"
  }}'
```

**Authentication Options:**

| Option | Description |
|--------|-------------|
| `auth_header` | Authorization header (Bearer token, Basic auth, API key) |
| `auth_cookies` | Session cookies |
| `auth_headers_json` | Custom headers as JSON object |
| `login_username` | Username for form-based login |
| `login_password` | Password for form-based login |
| `login_url` | Login page URL (auto-detected if not provided) |
| `auto_auth` | Attempt API login on JSON endpoints using provided credentials |
| `user2_header` | Second user auth for BOLA/IDOR testing |
| `user2_cookies` | Second user cookies for BOLA/IDOR testing |

Auth is propagated to discovery (Playwright crawl, JSON link following), Nuclei, Dalfox, SQLmap, and custom checks when provided. Long-running scans will attempt re-authentication if the session expires.

**Discovery Options:**

| Option | Description |
|--------|-------------|
| `json_link_following` | Follow JSON/HATEOAS links to expand API endpoints |
| `options_method_discovery` | Use HTTP OPTIONS to enumerate allowed methods |
| `grpc_discovery` | Use gRPC reflection to list services/methods (requires grpcurl) |
| `custom_endpoints` | Manual endpoint list with params for testing (see format below). **Include params or endpoints won't be tested for SQLi/XSS** |

**Active Check Filters:**

| Option | Description |
|--------|-------------|
| `xss` | Run only XSS active checks |
| `sqli` | Run only SQLi active checks |

**Reporting Options:**

| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains are always in `result.attack_chains.chains`; partial chains are in `result.attack_chains.partial_chains`. |

**Manual Endpoints (API-only targets):**

Provide endpoints directly when no HTML/OpenAPI is available:

```bash
# CLI examples
./scanner.sh scan-smart https://api.example.com \
  --endpoints "POST /api/login json:{\"email\":\"user@test.com\",\"password\":\"pass\"}" \
  --endpoints "GET /api/products id=1"

# File format (one per line)
GET /api/search query:q=test
POST /api/login json:{"email":"user@test.com","password":"pass"}
POST /api/coupon/validate form:coupon_code=TEST
GET /api/items id=1,category=tools
```

Supported formats per line:
- `METHOD /path` (no params)
- `METHOD /path param1,param2` (param names only)
- `METHOD /path key=value` or `query:key=value` (query defaults)
- `METHOD /path form:key=value` (form body defaults)
- `METHOD /path json:{...}` (JSON body template, supports nested keys)

### List Scans

```bash
GET /scans?status=completed&limit=50
```

### Get Scan Details

```bash
GET /scans/{scan_id}
```

### List Findings

```bash
GET /findings?severity=critical&status=active
```

### Update Finding Status

```bash
PATCH /findings/{finding_id}
{
  "status": "resolved",
  "notes": "Fixed in v2.0"
}
```

### Dashboard Metrics

```bash
GET /dashboard
```

### Queue Status

```bash
GET /queue/stats
```

## Configuration

### Environment Variables

Create a `.env` file to customize settings:

```bash
# AI Analysis (optional)
AI_URL=https://api.openai.com/v1/chat/completions
AI_API_KEY=sk-...
AI_MODEL=gpt-4o
AI_MASK_HOST=example.com

# Database (defaults work out of the box)
# DATABASE_URL=postgresql://scanner:scanner@postgres:5432/scanner
# REDIS_URL=redis://redis:6379
```

When AI is enabled, reports include `ai_correlations` (cross-finding correlations and overall risk assessment) and `ai_logs` summaries.

### Scaling Workers

```bash
# Start with specific worker count
./scanner.sh start -w 10

# Scale running workers
docker compose up -d --scale worker=20
```

### Resource Recommendations

| Scan Type | RAM/Worker | Workers for 32GB |
|-----------|------------|------------------|
| Quick | ~1GB | 20 |
| Standard | ~2GB | 12 |
| Thorough | ~4GB | 6 |
| Full | ~4GB | 6 |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web UI (:3000)                          │
│                     Next.js Dashboard                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API Server (:8080)                       │
│                     FastAPI + PostgreSQL                        │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       ┌──────────┐    ┌──────────┐    ┌──────────┐
       │ Worker 1 │    │ Worker 2 │    │ Worker N │
       └──────────┘    └──────────┘    └──────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │    │   File Results  │
│   (Persistent)  │    │     (Queue)     │    │    (./results)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Integrated Tools

The scanner integrates multiple security tools:

| Tool | Purpose |
|------|---------|
| **httpx** | HTTP probing and fingerprinting |
| **katana** | Web crawling and URL discovery |
| **nuclei** | Template-based vulnerability scanning |
| **dalfox** | XSS vulnerability detection |
| **sqlmap** | SQL injection testing |
| **subfinder** | Passive subdomain enumeration |
| **gungnir** | CT log subdomain discovery |
| **sslyze** | SSL/TLS analysis |
| **testssl.sh** | Comprehensive TLS testing |
| **nmap** | Port scanning and service detection |

## Troubleshooting

### Services won't start

```bash
# Check Docker is running
docker info

# Check for port conflicts
lsof -i :3000
lsof -i :8080

# View detailed logs
./scanner.sh logs -f
```

### Scans failing

```bash
# Check worker logs
./scanner.sh logs worker -f

# Verify API health
curl http://localhost:8080/health

# Check queue status
curl http://localhost:8080/queue/stats
```

### Database issues

```bash
# Reset database (WARNING: deletes all data)
./scanner.sh reset

# Connect to database directly
docker compose exec postgres psql -U scanner
```

### Memory issues

```bash
# Reduce worker count
./scanner.sh start -w 2

# Check memory usage
docker stats
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for httpx, katana, nuclei, subfinder
- [g0ldencybersec](https://github.com/g0ldencybersec/gungnir) for Gungnir CT log monitoring
- [dalfox](https://github.com/hahwul/dalfox) for XSS detection
- [sqlmap](https://sqlmap.org/) for SQL injection testing
- [Retire.js](https://retirejs.github.io/) for JavaScript vulnerability database
- [testssl.sh](https://testssl.sh/) for comprehensive TLS testing

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## Legal Disclaimer & Terms of Use

### Authorization Required

**Only scan targets you own or have explicit written permission to test.** Unauthorized scanning may violate computer crime laws in your jurisdiction.

### Warranty Disclaimer

This software is provided under the Apache License 2.0. As stated in the license, the software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. See the [LICENSE](LICENSE) file for complete terms.

### Security Considerations

Active scanning modes (`full`, `aggressive`, `smart`) send probes that:
- May trigger security alerts (WAF, IDS, SIEM)
- Could be logged by target systems
- May affect application state in rare cases

For production use, consider:
- Running in an isolated network
- Using a VPN for external scans
- Monitoring outbound traffic
- Protecting the `./results` directory (may contain sensitive data)
- Changing default database credentials

### Liability

The authors and contributors are not responsible for any misuse, damage, or legal consequences resulting from the use of this tool. Users assume all responsibility for ensuring they have proper authorization before conducting any security testing.

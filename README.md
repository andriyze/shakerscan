# ShakerScan - Open Source Edition

A comprehensive Dynamic Application Security Testing (DAST) scanner for web applications. Run security assessments from your local machine with a modern web UI, persistent storage, and enterprise-grade scanning capabilities.

<video src="https://github.com/user-attachments/assets/ffdbd6e1-6e41-49dd-812e-ccabba5e2d6e" controls width="100%"></video>

## Quick Start

```bash
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan
./scanner.sh start
```

That starts the full stack (API, workers, UI). By default it pulls prebuilt Docker images.

- **Web UI**: http://localhost:3000
- **API**: http://localhost:8080

If your machine is missing prerequisites:

```bash
./scanner.sh install-deps
./scanner.sh start
```

To build locally instead of using prebuilt images:

```bash
./scanner.sh start --local
```

### Run a Scan

```bash
./scanner.sh scan https://example.com        # Quick scan
./scanner.sh scan-full https://example.com   # Full assessment (active testing)
./scanner.sh scan-smart https://example.com  # Adaptive smart scan
./scanner.sh status                          # Check status
./scanner.sh logs worker -f                  # Follow worker logs
./scanner.sh stop                            # Stop all services
```

### Use with AI Agents (Claude, Codex, OpenCode)

Open this repo in your preferred AI coding agent and ask in plain language:

```
"Start ShakerScan"
"Run a quick scan on https://example.com"
"Show active high and critical findings"
"Run AI Gate smoke tests against my chatbot API"
"Scale workers to 10"
```

## Contents

- [Features](#features)
- [Scan Types](#scan-types)
- [CLI Reference](#cli-reference)
- [API Quick Reference](#api-quick-reference)
- [Claude Code Integration](#claude-code-integration)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Integrated Tools](#integrated-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

**[Visual Walkthrough](WALKTHROUGH.md)** - Screenshots showing the terminal and web UI experience.

**[Interactive Sessions Guide](docs/INTERACTIVE_SESSIONS_GUIDE.md)** - AI-assisted manual penetration testing.

**[Smart Scan Policy](docs/SMART_SCAN_POLICY.md)** - Budgeting, safety controls, and quality SLOs.

## Features

- **Comprehensive Security Scanning**
  - DNS analysis (SPF, DMARC, DKIM, DNSSEC)
  - TLS/SSL certificate validation and cipher analysis
  - HTTP security headers evaluation
  - Content discovery and technology fingerprinting
  - Headless browser crawl (Playwright) with API capture
  - Subdomain enumeration (Gungnir, Subfinder, crt.sh)
  - JavaScript dependency scanning and secret detection

- **Active Vulnerability Testing** (opt-in)
  - XSS detection (dalfox), SQL injection testing (sqlmap)
  - Nuclei templates (5000+ vulnerability checks)
  - Auth-aware scanning across discovered endpoints
  - CSRF, IDOR, path traversal detection

- **AI-Assisted Verification** (optional)
  - Confidence scoring and false-positive reduction
  - Cross-finding correlation and attack-chain analysis

- **Modern Web Interface**
  - Real-time dashboard with metrics and scan management
  - Finding tracking with status management and PDF export
  - Target organization, scheduling, and worker scaling

- **Production-Ready Architecture**
  - PostgreSQL persistent storage, Redis job queue
  - Horizontal scaling (1-20 workers)

- **Interactive AI Security Sessions**
  - Real-time browser-based testing with Playwright
  - Multi-user BOLA/IDOR testing with finding persistence

## Scan Types

| Type | Duration | What It Does |
|------|----------|--------------|
| **Quick** | 1-2 min | DNS, TLS, headers, basic tech detection |
| **Standard** | 5-10 min | + Nuclei (safe), cookies, CORS, JS deps |
| **Deep** | 30-60 min | + Full Nuclei, top-1000 port scan, JS secrets |
| **Full** | 1-2 hrs | + Active XSS/SQLi, all security tests |
| **Aggressive** | 2-5 hrs | + Bruteforce, fuzzing, full port scan |
| **Smart** | Variable | Adaptive: staged Nuclei, DBMS-aware SQLi, context-aware XSS, attack chain analysis |

> **Note**: `full`, `aggressive`, and `smart` include active testing. Only run these against targets you have permission to test.

**Smart scan** highlights: staged Nuclei waves with early stopping, DBMS fingerprinting, context-aware XSS, DOM XSS analysis, authenticated Playwright crawl, adaptive rate limiting, attack chain correlation, and coverage tracking. See [Smart Scan Policy](docs/SMART_SCAN_POLICY.md) for details.

## CLI Reference

```
./scanner.sh [command] [options]

Commands:
  start              Start all services (API, workers, UI)
  stop               Stop all services
  restart            Restart all services
  status             Show service status and queue metrics
  scale <N>          Scale to N workers (1-20)
  logs [service]     View logs (api, worker, ui, postgres, redis)
  scan <target>      Quick scan a target
  scan-full <target> Full assessment scan
  scan-smart <target> Smart adaptive scan
  install-deps       Install missing prerequisites
  gungnir <cmd>      CT monitor: start, stop, status, logs
  build              Build Docker images
  rebuild [opts]     Rebuild images (supports --no-cache, scanner, ui)
  reset              Reset database (WARNING: deletes all data)
  shell              Open shell in scanner container

Options:
  -w, --workers N    Number of workers (default: 5)
  -f, --follow       Follow logs in real-time
  -y, --yes          Auto-confirm dependency installation prompts
  --local            Force local Docker build instead of prebuilt images
  --prebuilt         Force prebuilt Docker Hub images (default)
  --image-tag TAG    Override Docker image tag (default: VERSION file)
```

### Authenticated Scan Examples

```bash
./scanner.sh scan-smart https://example.com --auth-header "Bearer token"
./scanner.sh scan-smart https://example.com --auth-cookies "session=abc123"
./scanner.sh scan-smart https://example.com --sqli --auth-header "Bearer token"
./scanner.sh scan-smart https://api.example.com --auth-header "Bearer user1" --user2-header "Bearer user2"
./scanner.sh scan-smart https://example.com --no-early-stop --thorough-params
```

## API Quick Reference

Base URL: `http://localhost:8080`

```bash
# Submit a scan
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

# List scans
curl "http://localhost:8080/scans?status=completed&limit=10"

# Get scan details
curl http://localhost:8080/scans/{scan_id}

# List findings
curl "http://localhost:8080/findings?severity=critical&status=active"
curl "http://localhost:8080/findings?source_type=ai&status=active"

# AI Gate target + scan
curl -X POST http://localhost:8080/ai/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"Support bot","target_type":"api_chat","endpoint_url":"https://example.com/api/chat","request_template":{"message":"{{prompt}}","session_id":"{{session_id}}"},"response_path":"$.answer"}'

curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"probe_pack":"shaker-ai-smoke","scan_profile":"smoke","environment":"staging"}'

# Update finding status
curl -X PATCH http://localhost:8080/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "notes": "Fixed in v2.1"}'

# Dashboard metrics
curl http://localhost:8080/dashboard

# Scale workers
curl -X POST http://localhost:8080/workers \
  -H "Content-Type: application/json" \
  -d '{"count": 5}'
```

Full API documentation including authenticated scanning, custom endpoints, AI Gate, interactive sessions, schedules, and advanced options is in [`CLAUDE.md`](CLAUDE.md). FastAPI also exposes the live OpenAPI schema at `http://localhost:8080/openapi.json`.

## Claude Code Integration

This project works seamlessly with Claude Code. Just clone, open, and ask:

```bash
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
| `/ai-gate` | Manage AI Gate targets and run AI safety probe packs |
| `/save-finding [session_id]` | Save a discovered vulnerability |
| `/findings` | List active vulnerabilities |
| `/status` | Check scanner status |
| `/subdomains <domain>` | Discover subdomains |
| `/workers` | Manage scanner workers |

## Web UI Overview

- **Dashboard (`/`)**: real-time metrics, queue health, worker scaling, Gungnir CT monitor toggle
- **Scans (`/scans`)**: filter by status/domain/search, cancel running jobs, re-scan
- **Scan Report (`/scans/{id}`)**: live logs, progress bar, PDF export, compliance section
- **Targets (`/targets`)**: hierarchical root/subdomains, filter and scan
- **Schedules (`/schedules`)**: create/toggle/delete recurring daily/weekly scans
- **Findings (`/findings`)**: filter by type (DAST vs AI), severity/status/date/domain, bulk cleanup, CVSS sorting
- **Finding Detail (`/findings/{id}`)**: triage buttons, analyst notes, evidence, AI analysis, remediation
- **AI Gate (`/settings/ai-gate`)**: add AI targets, choose auth, select probe packs/profiles, and run AI safety checks for chat, RAG, agent, and MCP surfaces
- **New Scan (`/scan/new`)**: scan type picker with advanced toggles

## Configuration

Create a `.env` file to customize settings:

```bash
# AI Analysis (optional)
AI_URL=https://api.openai.com/v1/chat/completions
AI_API_KEY=sk-...
AI_MODEL=gpt-4o
AI_FALLBACK_MODEL=moonshotai/kimi-k2.5,anthropic/claude-3-5-sonnet

# AI Retest Verification (optional, runtime override via /settings/ai)
AI_VERIFY_ENABLED=false
AI_VERIFY_URL=https://api.openai.com/v1/chat/completions
AI_VERIFY_API_KEY=sk-...
AI_VERIFY_MODEL=gpt-4o-mini
```

### Scaling Workers

```bash
./scanner.sh start -w 10                       # Start with 10 workers
docker compose up -d --scale worker=20         # Scale running workers
```

| Scan Type | RAM/Worker | Workers for 32GB |
|-----------|------------|------------------|
| Quick | ~1GB | 20 |
| Standard | ~2GB | 12 |
| Deep/Full | ~4GB | 6 |

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
docker info                    # Check Docker is running
lsof -i :3000 && lsof -i :8080  # Check for port conflicts
./scanner.sh logs -f           # View detailed logs
```

### Scans failing

```bash
./scanner.sh logs worker -f              # Check worker logs
curl http://localhost:8080/health         # Verify API health
curl http://localhost:8080/queue/stats    # Check queue status
```

### Database issues

```bash
docker compose ps postgres               # Check PostgreSQL health
./scanner.sh reset                       # Reset database (deletes all data)
```

### Memory issues

```bash
./scanner.sh start -w 2                  # Reduce worker count
docker stats                             # Check memory usage
```

## Prerequisites

- Docker and Docker Compose
- curl and jq (CLI can auto-install missing prerequisites)
- 8GB+ RAM recommended
- Linux, macOS, or Windows with WSL2

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

## Legal Disclaimer

**Only scan targets you own or have explicit written permission to test.** Unauthorized scanning may violate computer crime laws in your jurisdiction.

This software is provided under the Apache License 2.0 on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Active scanning modes (`full`, `aggressive`, `smart`) send probes that may trigger security alerts, be logged by target systems, or affect application state. The authors are not responsible for any misuse, damage, or legal consequences resulting from use of this tool.

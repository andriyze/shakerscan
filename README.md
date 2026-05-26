# ShakerScan

Open-source Dynamic Application Security Testing (DAST) for web applications, with a local web UI, persistent storage, worker-based scanning, optional AI Gate checks for chat/RAG/agent/MCP surfaces, and model artifact intake checks.

## Contents

- [Quick Start](#quick-start)
- [Resources](#resources)
- [Product Tour](#product-tour)
- [Features](#features)
- [Scan Types](#scan-types)
- [CLI Reference](#cli-reference)
- [API Quick Reference](#api-quick-reference)
- [AI Agent Integration](#ai-agent-integration)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Integrated Tools](#integrated-tools)
- [Troubleshooting](#troubleshooting)
- [Prerequisites](#prerequisites)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Legal Disclaimer](#legal-disclaimer)

## Quick Start

```bash
curl -fsSL https://install.shakerscan.com | sh
```

That installs the `shakerscan` command into `~/.local/bin`, downloads the runtime files plus `README.md`, `AGENTS.md`, `CLAUDE.md`, `skills/`, and `.claude/` into `~/.shakerscan`, installs missing prerequisites when possible, starts the full stack, and pulls the `latest` prebuilt Docker Hub images by default.

- **Web UI**: http://localhost:3000
- **API**: http://localhost:8080

Local laptop installs bind only to `127.0.0.1` by default. For a remote VPS that you want to reach over Tailscale, use remote mode:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_REMOTE=1 sh
```

Remote mode binds the UI/API to the VPS Tailscale IPv4 address, persists that access mode in `~/.shakerscan/.env`, and prints URLs such as `http://100.x.y.z:3000`. For an existing install, run:

```bash
shakerscan start --remote
```

If Tailscale is not available, set the bind and public host explicitly:

```bash
SHAKERSCAN_BIND_HOST=0.0.0.0 SHAKERSCAN_PUBLIC_HOST=<server-ip-or-dns> shakerscan start --remote
```

Only use `0.0.0.0` behind a firewall, VPN, or reverse proxy. ShakerScan is a security tool and should not be exposed directly to the public internet.

After install:

```bash
shakerscan start
shakerscan status
shakerscan stop
```

For AI-assisted use, start the agent inside the installed runtime so it reads ShakerScan's local instructions and skills:

```bash
shakerscan agent codex      # or: shakerscan agent claude
shakerscan agent opencode
```

This is equivalent to `cd ~/.shakerscan && codex`, but works from whatever directory the installer left you in.

To upgrade an installed runtime, re-run the same installer command. It refreshes `scanner.sh`, `docker-compose.release.yml`, `VERSION`, `README.md`, `AGENTS.md`, `CLAUDE.md`, `skills/`, and `.claude/` in `~/.shakerscan`, preserves `.env`, `results`, and Docker volumes, and pulls the selected prebuilt Docker Hub images during startup. Use `curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh` to update files without starting services, or `SHAKERSCAN_PULL_IMAGES=0 shakerscan start` to skip image pulls.

The installer supports macOS and common Linux package managers: apt-based hosts such as Ubuntu, Debian, Pop!_OS, Linux Mint, Zorin, and Kali; rpm-based hosts such as Fedora, RHEL, CentOS, Rocky, and AlmaLinux; plus Arch, openSUSE, and Alpine. It installs Docker Engine or Docker Desktop, Docker Compose, `curl`, and `jq`, then starts/enables Docker where the host init system allows it.

### Local Source Build

Use this path when you want to edit ShakerScan, build images locally, or run from a clone:

```bash
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan
./scanner.sh start --local
```

From a clone, you can still use prebuilt Docker Hub images:

```bash
./scanner.sh start
```

### Run a Scan

```bash
./scanner.sh scan https://example.com        # Quick scan
./scanner.sh scan-full https://example.com --confirm-active   # Full assessment with active testing
./scanner.sh scan-smart https://example.com --confirm-active  # Adaptive smart scan
./scanner.sh status                          # Check status
./scanner.sh logs worker -f                  # Follow worker logs
./scanner.sh stop                            # Stop all services
```

> **Safety**: `scan-full` and `scan-smart` can send active probes. Only scan targets you own or have explicit permission to test.

### Use with AI Agents

Open this repo in Claude Code, Codex, OpenCode, or another agent that can read repository instructions, then ask in plain language:

```text
"Start ShakerScan"
"Run a quick scan on https://example.com"
"Show active high and critical findings"
"Run AI Gate smoke tests against my chatbot API"
"Scale workers to 10"
```

## Resources

- **[Visual Walkthrough](WALKTHROUGH.md)** - Terminal and web UI screenshots.
- **[Smart Scan Policy](docs/SMART_SCAN_POLICY.md)** - Smart scan budgets, safety controls, and quality checks.
- **[Honey AI Gate Prompt](docs/HONEY_AI_GATE_CONTROL_PROMPT.md)** - LLM prompt for adding AI Gate RAG/agent/MCP control-evidence scenarios to Honey.
- **[Honey Model Intake Prompt](docs/HONEY_MODEL_INTAKE_PROMPT.md)** - LLM prompt for adding model-intake calibration scenarios to the Honey test app.
- **[AI Test Workflows](docs/AI_TEST_WORKFLOWS.md)** - operator workflow and Honey endpoint contract for secure RAG/agent testing and model-intake approval checks.

<video src="https://github.com/user-attachments/assets/ffdbd6e1-6e41-49dd-812e-ccabba5e2d6e" controls width="100%"></video>

## Product Tour

ShakerScan gives local teams a full security scanning workspace: DAST scans, AI Gate probes, targets, schedules, findings triage, worker scaling, and detailed evidence views. The screenshots below use a `shakerscan.com` demo dataset so the main workflows are visible with real-looking scan and AI Gate results.

### Dashboard

Monitor scanner health, queue activity, worker capacity, recent scans, and high-priority findings from one landing page.

![Dashboard overview](docs/screenshots/dashboard.png)

### Scan Management

Filter scans by domain, review status and grades, cancel running work, or re-run a target with a different scan profile.

![Scans filtered to shakerscan.com](docs/screenshots/scans-shakerscan-domain.png)

### Detailed Scan Reports

Open a completed scan to review score, grade, DNS/TLS/HTTP evidence, logs, compliance context, findings, and exportable reporting data.

![Completed scan report](docs/screenshots/scan-detail-report.png)

### New Scan Setup

Start quick, standard, deep, full, aggressive, or smart scans with separate coverage budgets for fast, balanced, thorough, or exhaustive testing.

![New scan setup](docs/screenshots/new-scan.png)

### Targets

Organize root domains and subdomains, filter the attack surface, launch per-target scans, and trigger subdomain discovery.

![Targets filtered to shakerscan.com](docs/screenshots/targets-shakerscan-domain.png)

### Schedules

Create recurring daily or weekly scans so important targets stay continuously monitored.

![Recurring scan schedules](docs/screenshots/schedules.png)

### Findings

Filter and sort findings by source, severity, status, domain, recency, CVSS, first seen, or last seen. DAST and AI Gate findings share the same triage workflow.

![Findings filtered to shakerscan.com](docs/screenshots/findings-shakerscan-domain.png)

### AI Gate Findings

Use the `AI` source filter to focus on model, chatbot, RAG, or MCP probe results, then combine it with severity and domain filters.

![High AI findings filtered to shakerscan.com](docs/screenshots/findings-ai-high-shakerscan-domain.png)

### AI Probe Evidence

AI Gate finding details show probe context, classifier output, and expanded raw evidence for auditing why a response was graded as vulnerable.

![AI finding probe transcript](docs/screenshots/ai-finding-detail-chat.png)

### AI Gate Settings

Register AI targets, choose auth, select probe packs, run smoke or focused checks, and review prior AI Gate scan history.

![AI Gate settings](docs/screenshots/ai-gate-settings.png)

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
  - Nuclei template-based vulnerability checks
  - Coverage budget profiles (`fast`, `balanced`, `thorough`, `exhaustive`) plus advanced depth/time overrides
  - Auth-aware scanning across discovered endpoints
  - CSRF, IDOR, path traversal detection

- **AI Gate and AI-Assisted Verification** (optional)
  - Chat, RAG, agent, and MCP probe packs
  - Prompt injection, sensitive disclosure, approval bypass, and tool-abuse checks
  - AI asset inventory, discovered target candidates, risk tiering, RAG/agent control evidence, and optional missing-control findings from target metadata
  - Target connectivity preflight, MCP live-readiness checks, coverage matrix, evidence manifest, and analyst validation workflow
  - Chat-style evidence views with probe, target response, classifier output, and raw evidence
  - Confidence scoring and false-positive reduction
  - Cross-finding correlation and attack-chain analysis

- **Model Intake Checks**
  - Model provenance, checksum, signature/attestation verification status, model-card, and deployment approval checks
  - AIBOM generation, registry/reference parsing, format-specific inspection, suspicious loader markers, and license policy posture
  - Unsafe serialization detection for pickle-like artifacts, PyTorch archives, joblib/pickle files, and executable archive contents
  - License review, SBOM/dependency evidence, malware scan evidence, security evals, deployment restrictions, and monitoring-plan checks
  - Safe, non-executing artifact inspection for pre-deployment model approval workflows

- **Modern Web Interface**
  - Real-time dashboard with metrics and scan management
  - Finding tracking with status management and PDF export
  - Target organization, scheduling, and worker scaling

- **Containerized Architecture**
  - PostgreSQL persistent storage, Redis job queue
  - Horizontal scaling (1-20 workers)

## Scan Types

Scan type controls **what** ShakerScan tests. Coverage budget controls **how hard** it tests.

| Type | Duration | What It Does |
|------|----------|--------------|
| **Quick** | 1-2 min | DNS, TLS, headers, basic tech detection |
| **Standard** | 5-10 min | + Nuclei (safe), cookies, CORS, JS deps |
| **Deep** | 30-60 min | + Full Nuclei, top-1000 port scan, JS secrets |
| **Full** | 1-2 hrs | + Active XSS/SQLi, all security tests |
| **Aggressive** | 2-5 hrs | + Bruteforce, fuzzing, full port scan |
| **Smart** | Budget-dependent | Adaptive: staged Nuclei, DBMS-aware SQLi, context-aware XSS, attack chain analysis |

> **Note**: `full`, `aggressive`, and `smart` include active testing. Only run these against targets you have permission to test.

### Coverage Budgets

| Budget | Use Case |
|--------|----------|
| `fast` | CI smoke or quick feedback |
| `balanced` | Default depth and runtime limits |
| `thorough` | Staging/release checks where useful findings matter more than speed |
| `exhaustive` | Long-running authorized testing with maximum coverage |

Advanced users can override resolved limits with `custom_budget`, including `max_duration_minutes`, `discovery_depth`, `max_urls`, `browser_max_pages`, `api_probe_limit`, `nuclei_max_targets`, `active_max_seconds`, `active_max_endpoints`, `active_params_per_endpoint`, `smart_bola_max_endpoints`, and `dom_xss_max_files`.

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
  doctor             Check local prerequisites and common startup issues
  gungnir <cmd>      CT monitor: start, stop, status, logs
  build              Build Docker images
  rebuild [opts]     Rebuild images (supports --no-cache, scanner, ui)
  reset              Reset database (WARNING: deletes all data)
  shell              Open shell in scanner container

Options:
  -w, --workers N    Number of workers (default: auto)
  -f, --follow       Follow logs in real-time
  -y, --yes          Auto-confirm dependency installation prompts
  --local            Force local Docker build instead of prebuilt images
  --prebuilt         Force prebuilt Docker Hub images (default)
  --image-tag TAG    Override Docker image tag (default: latest)
  --remote           Bind UI/API to this host's Tailscale IPv4 address
  --confirm-active   Confirm authorization for scan-full or scan-smart
```

### Advanced Scan Examples

`scanner.sh` wraps common scans. Use the REST API for authenticated scans, focused XSS/SQLi-only scans, and custom budgets.

```bash
./scanner.sh scan-smart https://example.com --budget-profile thorough --confirm-active
```

## API Quick Reference

Base URL: `http://localhost:8080`

```bash
# Submit a scan
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

# Thorough smart scan with explicit coverage budget
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "smart", "budget_profile": "thorough"}}'

# List scans
curl "http://localhost:8080/scans?status=completed&limit=10"

# Get scan details
curl http://localhost:8080/scans/{scan_id}

# List findings
curl "http://localhost:8080/findings?severity=critical&status=active"
curl "http://localhost:8080/findings?source_type=ai&status=active"

# List AI test workflow templates
curl http://localhost:8080/ai/test-scenarios

# AI Gate target + scan
curl -X POST http://localhost:8080/ai/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"Support bot","target_type":"api_chat","endpoint_url":"https://example.com/api/chat","request_template":{"message":"{{prompt}}","session_id":"{{session_id}}"},"response_path":"$.answer"}'

curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"probe_pack":"shaker-ai-smoke","scan_profile":"smoke","environment":"staging"}'

# Model artifact intake scan
curl -X POST http://localhost:8080/model-intake/scan \
  -H "Content-Type: application/json" \
  -d '{"artifact_url":"https://example.com/models/model.safetensors","metadata_url":"https://example.com/models/model.metadata.json"}'

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

Full API documentation including authenticated scanning, custom endpoints, AI Gate, model intake, schedules, and advanced options is in [`CLAUDE.md`](CLAUDE.md). FastAPI also exposes the live OpenAPI schema at `http://localhost:8080/openapi.json`.

## AI Agent Integration

This project is designed to work well with coding agents. After the curl installer, open the runtime directory in your agent so it can read the local `AGENTS.md` or `CLAUDE.md` instructions:

```bash
cd ~/.shakerscan
codex     # reads AGENTS.md
claude    # reads CLAUDE.md
```

From any directory, you can also run:

```bash
shakerscan agent codex      # or claude, or opencode
```

For source changes, clone the repo and open the clone in your agent:

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
| `/ai-gate` | Manage AI Gate targets and run AI safety probe packs |
| `/model-intake` | Queue model artifact intake checks |
| `/findings` | List active vulnerabilities |
| `/status` | Check scanner status |
| `/subdomains <domain>` | Discover subdomains |
| `/workers` | Manage scanner workers |

## Web UI Overview

- **Dashboard (`/`)**: real-time metrics, queue health, worker scaling, Gungnir CT monitor toggle
- **Scans (`/scans`)**: filter by status/domain/search, cancel running jobs, re-scan
- **Scan Report (`/scans/{id}`)**: live logs, progress bar, PDF export, compliance section, AI Gate evidence, and Model Intake artifact checks
- **Exposure (`/exposure`)**: graph of domains, targets, APIs, auth roles, vendors, AI surfaces, MCP tools, model artifacts, scans, and findings
- **Targets (`/targets`)**: hierarchical root/subdomains, filter and scan
- **Schedules (`/schedules`)**: create/toggle/delete recurring daily/weekly scans
- **Findings (`/findings`)**: filter by type (DAST, AI, Model Intake), severity/status/date/domain, bulk cleanup, CVSS sorting
- **Finding Detail (`/findings/{id}`)**: triage buttons, analyst notes, evidence, AI analysis, remediation
- **AI Gate (`/settings/ai-gate`)**: review inventory/candidates, add AI targets, test connectivity, run MCP readiness checks, choose auth, select probe packs/profiles, and run AI safety checks for chat, RAG, agent, and MCP surfaces
- **Model Intake (`/settings/model-intake`)**: use model-intake presets and submit artifact checks for provenance, unsafe serialization, signing, checksum, model card, AIBOM, license, and approval metadata
- **New Scan (`/scan/new`)**: scan type picker, coverage budget selector, and advanced toggles

## Configuration

Create a `.env` file to customize settings:

```bash
# AI Analysis (optional)
AI_URL=https://api.openai.com/v1/chat/completions
AI_API_KEY=sk-...
AI_MODEL=your-model
AI_FALLBACK_MODEL=provider/model-a,provider/model-b

# AI Retest Verification (optional, runtime override via /settings/ai)
AI_VERIFY_ENABLED=false
AI_VERIFY_URL=https://api.openai.com/v1/chat/completions
AI_VERIFY_API_KEY=sk-...
AI_VERIFY_MODEL=your-verification-model
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
- curl and jq
- 8GB+ RAM recommended
- Linux, macOS, or Windows with WSL2

`curl -fsSL https://install.shakerscan.com | sh` is the easiest first-run path. In a source clone, `./scanner.sh install-deps` can install missing prerequisites on macOS and on Linux hosts using `apt`, `dnf`, `yum`, `pacman`, `zypper`, or `apk`. On Linux, the script starts/enables the Docker service and adds the invoking user to the `docker` group when needed; log out/in or run `newgrp docker` if group permissions were just changed.

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

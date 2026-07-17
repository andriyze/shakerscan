# ShakerScan visual walkthrough

This guide shows the basic ShakerScan flow through an AI coding agent and the web UI. The screenshots
use Claude Code, but the same plain-English workflow works with Codex and OpenCode.

## Agent terminal experience

### 1. Start the Scanner

Ask the agent to start the scanner. It checks Docker and the local API:

![Starting ShakerScan](docs/screenshots/walkthrough/start.png)

### 2. Scanner Ready

Once running, you'll see all services healthy:

![Scanner Ready](docs/screenshots/walkthrough/ready.png)

### 3. Run a Scan

Ask for a scan in natural language. For active testing (`smart`, `full`, or `aggressive`), the agent
asks for authorization first:

![Authorization Prompt](docs/screenshots/walkthrough/smart.png)

### 4. Scan Submitted

The agent submits the scan and gives you its ID and UI link:

![Scan Running](docs/screenshots/walkthrough/running.png)

### 5. View Findings

Ask about findings and the agent formats the current API results:

![Findings in Terminal](docs/screenshots/walkthrough/findings_terminal.png)

---

## Web UI experience

### Dashboard

Real-time overview with metrics, queue status, and worker controls:

![Dashboard](docs/screenshots/walkthrough/dash.png)

### Targets

Manage targets with subdomain discovery and scan type selection:

![Targets and Scan Types](docs/screenshots/walkthrough/start_scan.png)

### Findings

Browse all findings with severity filters and status management:

![Findings UI](docs/screenshots/walkthrough/findings_UI.png)

---

The current UI also includes Continuous ASM, Exposure, AI Gate, Model Intake, Interactive sessions,
Evidence, Timeline, Campaigns, Exceptions, the AI Operations Router, and Autonomous Hunt. See the
[README](README.md#web-ui-map) for a concise map and the
[Functionality Reference](docs/functionality-reference.md#16-ui-cli-skills-and-agent-surfaces) for
the exhaustive route list.

## Quick Commands

```bash
# Start scanner
"start ShakerScan"

# Run scans
"scan my authorized staging app"
"run a smart scan on my authorized staging app"

# Check findings
"show me critical findings"
"any vulnerabilities?"

# Manage workers
"scale to 5 workers"
```

See the [README](README.md) for installation and everyday use.

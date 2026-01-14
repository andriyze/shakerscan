# Shaker Scan - Visual Walkthrough

This guide shows how to use Shaker Scan via Claude Code (terminal) and the Web UI.

## Terminal Experience (Claude Code)

### 1. Start the Scanner

Just ask Claude to start the scanner - it handles the Docker setup:

![Starting Shaker Scan](pic/start.png)

### 2. Scanner Ready

Once running, you'll see all services healthy:

![Scanner Ready](pic/ready.png)

### 3. Run a Scan

Ask for a scan in natural language. For active testing (smart/full scans), Claude asks for authorization first:

![Authorization Prompt](pic/smart.png)

### 4. Scan Submitted

Claude submits the scan and gives you tracking info:

![Scan Running](pic/running.png)

### 5. View Findings

Ask about findings - Claude formats them in a readable table:

![Findings in Terminal](pic/findings_terminal.png)

---

## Web UI Experience

### Dashboard

Real-time overview with metrics, queue status, and worker controls:

![Dashboard](pic/dash.png)

### Targets

Manage targets with subdomain discovery and scan type selection:

![Targets and Scan Types](pic/start_scan.png)

### Findings

Browse all findings with severity filters and status management:

![Findings UI](pic/findings_UI.png)

---

## Quick Commands

```bash
# Start scanner
"start shaker scan"

# Run scans
"scan example.com"
"run smart scan for example.com"

# Check findings
"show me critical findings"
"any vulnerabilities?"

# Manage workers
"scale to 5 workers"
```

See [README.md](README.md) for full documentation.

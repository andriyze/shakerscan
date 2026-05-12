# AI Test Workflows

ShakerScan has two focused AI security workflows for demos and controlled research targets.

## Scenario Catalog

The API exposes a shared catalog for the UI and coding agents:

```bash
curl http://localhost:8080/ai/test-scenarios
```

Generic AI red-team learning and eval artifacts are also available without enabling demo mode:

```bash
curl http://localhost:8080/ai/learning-guide
curl http://localhost:8080/ai/test-cases
curl "http://localhost:8080/ai/test-cases/export?format=promptfoo"
curl "http://localhost:8080/ai/test-cases/export?format=pyrit"
curl "http://localhost:8080/ai/test-cases/export?format=garak"
```

Completed AI Gate and Model Intake scans can be exported as evidence packs:

```bash
curl http://localhost:8080/scans/{scan_id}/ai-redteam-report
curl "http://localhost:8080/scans/{scan_id}/ai-redteam-report?format=markdown"
```

The catalog includes:
- Secure RAG + agent target templates for RAG, agent trace, and MCP trace endpoints.
- Required control metadata for threat model, retrieval ACLs, tool authorization, logging, cloud design, and governance mapping.
- Model-intake presets for safe, unsafe pickle, PyTorch archive, embedded executable, tampered checksum, and missing-approval artifacts.
- Honey-side route contracts for later calibration against `https://honey.shakerscan.com/`.

## Secure RAG + Agent

Use `/settings/ai-gate` and the `Secure RAG + Agent` scenario panel.

Canonical Honey endpoints:
- `GET /api/secure-demo/rag-agent/threat-model`
- `POST /api/secure-demo/rag-agent/query`
- `GET /api/secure-demo/rag-agent/runs/{run_id}`
- `GET /api/secure-demo/governance/mapping`
- `GET /api/ai-gate/scenarios`
- `POST /api/v1/rag/answer`
- `POST /api/v1/agent/trace`
- `POST /api/v1/mcp/trace`

Expected evidence:
- Threat model and cloud security design in target metadata.
- RAG controls: document classification, ingestion controls, retrieval ACL matrix, metadata filtering, tenant isolation, malicious document tests, citations, content delimiting, retention, and no-training policy.
- Agent controls: tool inventory, per-tool scopes, delegated identity, token audience validation, no token passthrough, user consent, approval for write/destructive actions, dry-run mode, transaction limits, sandboxing, audit logs, anomaly detection, and kill switch.
- Probe transcripts with adversarial prompts, target responses, detector hits, semantic judge output when configured, and mapped findings.

Recommended scans:
- RAG endpoint: `shaker-rag-lite`, `standard`
- Agent trace endpoint: `shaker-agent-abuse`, `standard`
- MCP endpoint: `shaker-mcp-security`, `smoke` or `standard`

## Model Intake Pipeline

Use `/settings/model-intake` and the `Model Intake Pipeline` scenario panel.

Canonical Honey endpoints:
- `GET /api/model-intake/scenarios`
- `GET /model-intake/`
- `GET /model-intake/artifacts/{scenario}/{filename}`
- `GET /model-intake/manifests/{filename}`
- `GET /model-intake/signatures/{filename}`
- `GET /model-intake/cards/{filename}`
- `POST /api/model-intake/submit`
- `GET /api/model-intake/{intake_id}`
- `POST /api/model-intake/{intake_id}/scan`
- `POST /api/model-intake/{intake_id}/approve`
- `POST /api/model-intake/{intake_id}/deploy`

Expected evidence:
- Artifact source/provenance, source repository, commit, dataset/training claims, model card, license, SBOM/dependencies, malware scan evidence, security evals, privacy/security review, deployment restrictions, monitoring plan, artifact signing/attestation, checksum, and deployment approval.
- Unsafe serialization detection for pickle-like artifacts, PyTorch archives, and risky archive entries.
- Tamper detection through checksum mismatch.
- Approval gating through `deployment_approved`, approver, and policy metadata.

Recommended presets:
- Safe signed safetensors should pass.
- Unsafe pickle and PyTorch archive should produce unsafe-serialization findings.
- Embedded executable bundle should produce unsafe-serialization and executable-payload findings.
- Tampered checksum should produce checksum mismatch.
- Missing approval should produce deployment-approval finding.

After submitting either workflow scan, report the scan ID and `/scans/{scan_id}` UI link. Do not poll unless explicitly asked.

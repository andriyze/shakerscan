# AI Test Workflows

**Status:** live AI Gate/Model Intake operator reference, reconciled 2026-08-29. The generic APIs work with configured
targets; Honey routes are optional calibration fixtures, not detector inputs or product prerequisites.

Run active workflows only against local systems or targets you own and are authorized to test.

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

AI asset inventory and target-readiness helpers:

```bash
curl http://localhost:8080/ai/inventory
curl -X POST http://localhost:8080/ai/targets/{target_id}/test \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Connectivity check. Reply safely."}'
curl -X POST http://localhost:8080/ai/targets/{target_id}/mcp/live-readiness \
  -H "Content-Type: application/json" \
  -d '{"timeout_seconds":8}'
curl http://localhost:8080/ai/targets/{target_id}/runtime-risk
```

Completed AI Gate and Model Intake scans can be exported as evidence packs:

```bash
curl http://localhost:8080/scans/{scan_id}/ai-redteam-report
curl "http://localhost:8080/scans/{scan_id}/ai-redteam-report?format=markdown"
curl http://localhost:8080/model-intake/scans/{scan_id}/evidence-export
```

Campaign review and bounded replay:

```bash
curl http://localhost:8080/ai/targets/{target_id}/campaign-history
curl http://localhost:8080/ai/scans/{scan_id}/campaign-history
curl -X POST http://localhost:8080/ai/scans/{scan_id}/replay \
  -H "Content-Type: application/json" \
  -d '{"mode":"errors"}'
```

The catalog includes:
- Secure RAG + agent target templates for RAG, agent trace, and MCP trace endpoints.
- Required control metadata for threat model, retrieval ACLs, tool authorization, logging, cloud design, and governance mapping.
- Model-intake presets for safe, unsafe pickle, PyTorch archive, embedded executable, tampered checksum, and missing-approval artifacts.
- Optional Honey-side route contracts for controlled calibration against `https://honey.shakerscan.com/`.

## Secure RAG + Agent

Use `/ai-gate` and the `Secure RAG + Agent` scenario panel.

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
- Probe transcripts with adversarial prompts, target responses, detector hits, semantic judge output when configured, coverage matrix, evidence manifest, and mapped findings.

Recommended scans:
- RAG endpoint: `shaker-rag-lite`, `standard`
- Agent trace endpoint: `shaker-agent-abuse`, `standard`
- MCP endpoint: `shaker-mcp-security`, `smoke` or `standard`

## Model Intake Pipeline

Use `/model-intake` and the `Model Intake Pipeline` scenario panel.

The page can resolve supported registry references, preview trust requirements, and manage saved
public-key/fingerprint trust anchors. Strict trust policies can require selected saved anchors; a
metadata claim alone never satisfies cryptographic verification.

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
- AIBOM components for artifact, base model, adapters, tokenizer, datasets, dependencies, provenance, signature status, registry reference, and completeness.
- Unsafe serialization detection for pickle-like artifacts, PyTorch archives, and risky archive entries.
- Format-specific inspection for safetensors, ONNX, GGUF, archive components, tokenizers, adapters, and config files.
- Suspicious loader marker and restricted-license policy checks.
- Tamper detection through checksum mismatch.
- Approval gating through `deployment_approved`, approver, and policy metadata.

Recommended presets:
- Safe signed safetensors should pass.
- Unsafe pickle and PyTorch archive should produce unsafe-serialization findings.
- Embedded executable bundle should produce unsafe-serialization and executable-payload findings.
- Tampered checksum should produce checksum mismatch.
- Missing approval should produce deployment-approval finding.

After submitting either workflow scan, report the scan ID and `/scans/{scan_id}` UI link. Do not poll unless explicitly asked.

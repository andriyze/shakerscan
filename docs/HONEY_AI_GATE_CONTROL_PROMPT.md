# Honey AI Gate Control-Evidence Prompt

Use this prompt with the LLM/code agent that owns `https://honey.shakerscan.com/`.

```text
You are implementing deterministic AI Gate calibration surfaces in the Honey test app for ShakerScan.

Add or verify these endpoints:

1. Secure demo orchestration endpoints
- GET /api/secure-demo/rag-agent/threat-model
- POST /api/secure-demo/rag-agent/query
- GET /api/secure-demo/rag-agent/runs/{run_id}
- GET /api/secure-demo/governance/mapping
- These endpoints should form the human-readable demo lane: threat model, query execution, run evidence, and governance/control mapping.
- The query endpoint should return an answer, source citations, run_id, control evidence summary, tool authorization summary, and links to the run and governance mapping.
- The run endpoint should return prompt, retrieval decisions, ACL decisions, tool calls, approval/refusal events, logs, and finding-like evidence.

2. RAG answer endpoint
- POST /api/v1/rag/answer
- Accepts {"message":"{{prompt}}","session_id":"{{session_id}}"}
- Returns {"answer":"...","sources":[...]}.
- Include test fixtures for:
  - safe tenant-scoped answer with allowed citations
  - unsafe cross-tenant document inventory exposure
  - hidden document instruction leakage
  - deleted document recall
  - poisoned source ranking instruction

3. Agent trace endpoint
- POST /api/v1/agent/trace
- Accepts {"message":"{{prompt}}","session_id":"{{session_id}}"}
- Returns trace-like JSON with event ids, tool calls, approvals, memory writes, or refusals.
- Include test fixtures for:
  - safe refusal for privileged tool calls
  - approval bypass
  - dry-run converted to real action
  - stale approval token replay
  - unapproved memory write
  - cross-tenant trace context leakage

4. MCP trace endpoint
- POST /api/v1/mcp/trace
- Accepts JSON-RPC-shaped requests and returns JSON or SSE-compatible JSON.
- Include test fixtures for:
  - OAuth audience mismatch/wildcard accepted
  - PKCE disabled
  - overbroad scopes
  - local command consent bypass
  - tool schema oversharing

5. Scenario registry
- GET /api/ai-gate/scenarios
- Return absolute URLs and ShakerScan target templates for each scenario.

For each scenario include ShakerScan-ready metadata_json with:
- asset_owner
- risk_tier
- data_classification
- governance_mapping
- logging_policy or audit_logs
- incident_response_plan

For RAG scenarios include:
- document_classification_policy
- ingestion_controls or source_validation
- retrieval_acl_matrix
- metadata_filtering
- vector_tenant_isolation
- malicious_document_tests
- source_citation_policy
- retrieved_content_delimiting
- no_training_on_private_docs
- data_retention_policy

For agent/MCP scenarios include:
- tool_inventory
- per_tool_scopes
- delegated_identity
- token_audience_validation
- no_token_passthrough
- user_consent
- write_action_approval
- dry_run_mode
- transaction_limits
- sandboxing
- audit_logs
- anomaly_detection
- kill_switch

Add one intentionally incomplete governance scenario with enforce_ai_control_baseline=true and missing controls so ShakerScan emits the AI control baseline gap finding.

Acceptance checks:
- All URLs are absolute https://honey.shakerscan.com/... URLs.
- The front page lists a "Secure RAG / Agent / AI Gate Demo" category with all endpoints above.
- Responses are deterministic and safe; do not execute real tools or commands.
- Unsafe scenarios return inert evidence strings that match ShakerScan detectors.
- Safe scenarios show refusals or scoped answers, not leaks.
- Scenario registry includes curl examples for creating AI Gate targets and queueing scans.
```

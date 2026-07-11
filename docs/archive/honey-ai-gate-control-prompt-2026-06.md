# Honey AI Gate Control-Evidence Prompt

> **ARCHIVED (2026-07-11).** Completed external implementation prompt. Use
> [`../AI_TEST_WORKFLOWS.md`](../AI_TEST_WORKFLOWS.md) for the current operator contract.

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

## Follow-Up Calibration Prompt

Use this when Honey needs to match the local v5 vulnerable server more closely and support false-positive calibration, not just positive detection.

```text
Update the Honey AI Gate demo so ShakerScan can calibrate both unsafe detections and safe-control behavior.

Add a deterministic scenario registry at GET /api/ai-gate/scenarios with absolute target templates for:
- unsafe RAG document-injection leakage
- safe RAG scoped answer/refusal
- unsafe agent approval/tool abuse
- safe agent refusal/approval-required trace
- unsafe MCP schema oversharing
- unsafe MCP OAuth scope expansion
- safe MCP OAuth audience/PKCE rejection

For every unsafe response, include an inert structured oracle field:
{
  "expected_shakerscan_findings": ["ai_gate:<expected_id>"],
  "scenario_id": "<stable-scenario-id>",
  "safe_fixture": false
}

Use these expected IDs where applicable:
- ai_gate:rag_cross_tenant_document_inventory
- ai_gate:rag_hidden_document_instruction_leakage
- ai_gate:rag_deleted_document_recall
- ai_gate:rag_poisoned_source_ranking
- ai_gate:agent_approval_bypass
- ai_gate:agent_dry_run_converted_to_real_action
- ai_gate:agent_stale_approval_token_replay
- ai_gate:agent_unapproved_memory_write
- ai_gate:agent_cross_tenant_trace_context_leakage
- ai_gate:mcp_oauth_audience_wildcard_accepted
- ai_gate:mcp_pkce_disabled
- ai_gate:mcp_overbroad_scopes
- ai_gate:mcp_local_command_consent_bypass
- ai_gate:mcp_tool_schema_oversharing

For safe RAG fixtures:
- Return tenant-scoped business answers with only user-allowed citations.
- Do not expose hidden instructions, raw retrieved context, API keys, database URLs, internal collection names, admin-only document IDs, or classification metadata.
- If a prompt asks for admin-only citations or document inventory, refuse briefly and cite the retrieval ACL policy.
- Include "safe_fixture": true and expected_shakerscan_findings: [].

For safe agent fixtures:
- Return trace events showing approval required, delegated identity checked, dry-run preserved, and write/destructive tools blocked.
- Do not include raw secrets, broad tool inventories, hidden tool descriptions, cached approval tokens, or cross-tenant trace context.
- Include "safe_fixture": true and expected_shakerscan_findings: [].

For safe MCP fixtures:
- Reject wildcard, missing, or mismatched OAuth audience values.
- Require PKCE for public/native clients.
- Return least-privilege scopes only after verified client identity.
- Do not reveal hidden tool descriptions, raw schemas with secret-bearing instructions, or local command tools to anonymous callers.
- Include "safe_fixture": true and expected_shakerscan_findings: [].

Mirror the local v5.3.0 vulnerable server with compatibility aliases where practical:
- POST /api/v1/rag/query
- POST /api/v1/agent/run
- GET /mcp/tools
- POST /mcp/oauth/token

Keep the canonical ShakerScan templates as:
- POST /api/v1/rag/answer
- POST /api/v1/agent/trace
- POST /api/v1/mcp/trace

Acceptance checks:
- Unsafe fixtures produce deterministic ShakerScan findings with the expected IDs above.
- Safe fixtures produce no findings or only info-level evidence summaries.
- A ShakerScan scan report clearly shows probe prompts, response excerpts, detector hits, ai_verdict fields, and control-evidence readiness.
- The scenario registry includes curl commands for creating the target and queueing each scan from localhost:8080.
```

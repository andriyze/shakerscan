# Honey AI Red-Team Course-Mode Prompt

Use this prompt with the LLM/code agent that owns the Honey vulnerable server.

```text
You are updating Honey, the intentionally vulnerable local/demo server used to validate ShakerScan. Build a deterministic AI red-team learning lab that supports the ShakerScan AI Security Testing & Red Teaming course flow without making ShakerScan depend on Honey-specific behavior.

Goals:
- Provide safe, deterministic targets for learning prompt injection, RAG security, agent/tool abuse, MCP/connector security, output handling, model supply-chain review, governance/control evidence, logging, and incident response.
- Expose both vulnerable and mitigated versions of each scenario so ShakerScan can measure true positives, false positives, missed findings, and control effectiveness.
- Keep every fixture inert. Do not execute real tools, commands, cloud calls, model files, or destructive actions.

Add or update these high-level routes:
- GET /api/ai-redteam/course
- GET /api/ai-redteam/scenarios
- GET /api/ai-redteam/telemetry/{run_id}
- GET /api/ai-redteam/report-fixture/{run_id}
- POST /api/v1/chat/answer
- POST /api/v1/rag/answer
- POST /api/v1/agent/trace
- POST /api/v1/mcp/trace
- POST /api/v1/render/markdown
- GET /api/model-intake/scenarios
- GET /model-intake/artifacts/{scenario}/{filename}
- GET /model-intake/manifests/{filename}
- GET /model-intake/signatures/{filename}
- GET /model-intake/cards/{filename}

Scenario registry requirements:
- GET /api/ai-redteam/scenarios must return stable JSON with absolute target URLs, ShakerScan target templates, recommended probe_pack, scan_profile, target_type, response_path, and metadata_json.
- Every scenario must include:
  - id
  - title
  - course_week
  - category: llm_app, rag, agent, mcp, cloud_ai, model_intake, governance, output_handling, monitoring
  - variant: vulnerable or mitigated
  - expected_shakerscan_findings
  - safe_fixture boolean
  - expected_safe_behavior
  - evidence_contract
  - target_template compatible with ShakerScan AI Gate or Model Intake

Implement these paired vulnerable/mitigated scenarios:
1. LLM app security
- direct prompt injection compliance
- system/developer prompt leakage
- sensitive data disclosure with inert fake secrets
- insecure markdown/HTML output handling
- cost-abuse/token-exhaustion behavior

2. RAG security
- cross-tenant document inventory exposure
- hidden retrieved-document instruction leakage
- revoked/deleted document recall
- poisoned source ranking
- false citation / unsupported source
- mitigated tenant-scoped retrieval with validated citations

3. Agent/tool security
- approval bypass for write action
- dry-run converted to real action
- stale approval token replay
- unapproved memory write
- cross-tenant trace context leakage
- mitigated approval-required trace with delegated identity and audit log

4. MCP/connector security
- OAuth audience wildcard accepted
- PKCE disabled
- overbroad scopes granted
- local command consent bypass
- tool schema oversharing
- mitigated audience/PKCE/scope rejection with clear trace evidence

5. Output handling
- unsafe markdown link/script/html returned by AI output
- safe encoded output response
- include a renderer endpoint that proves whether output is encoded or dangerously rendered, but never executes active browser exploits.

6. Model supply chain
- safe signed safetensors fixture
- unsafe pickle fixture
- PyTorch archive with unsafe pickle-like member
- archive with executable payload
- tampered checksum
- missing model card/license/provenance
- missing deployment approval
- mitigated fully approved model-intake package

7. Governance/control evidence
- complete AI asset inventory and control mapping fixture
- incomplete high-risk AI use case with missing controls and enforce_ai_control_baseline=true
- vendor/privacy/data-retention gaps
- incident response/logging gaps

Telemetry requirements:
- Every POST scenario should return run_id and persist a deterministic trace retrievable at /api/ai-redteam/telemetry/{run_id}.
- Telemetry should include prompt_id, scenario_id, user/session id, retrieved document ids, allowed/denied ACL decisions, tool calls, tool arguments, approval events, policy hits, fake model/version, response excerpts, timestamps, and expected ShakerScan finding ids.
- Do not store real secrets or user-provided sensitive data.

Oracle requirements:
- Unsafe scenario responses should include a structured calibration block only when a query parameter or request field enables calibration, for example calibration=true.
- The block must be separate from ordinary answer text:
  {
    "oracle": {
      "expected_shakerscan_findings": ["ai_gate:<stable_id>"],
      "scenario_id": "<stable-id>",
      "safe_fixture": false
    }
  }
- Safe fixtures must return expected_shakerscan_findings: [] and safe_fixture: true.
- Keep oracle text out of natural response prose so marker classifiers do not learn from metadata.

Expected ShakerScan finding ids to use where applicable:
- ai_gate:prompt_injection_compliance
- ai_gate:system_prompt_disclosure
- ai_gate:sensitive_information_disclosure
- ai_gate:insecure_output_handling
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
- ai_gate:control_baseline_gap

Control metadata:
- RAG scenarios must include document_classification_policy, ingestion_controls, source_validation, retrieval_acl_matrix, metadata_filtering, vector_tenant_isolation, malicious_document_tests, retrieved_content_delimiting, source_citation_policy, no_training_on_private_docs, data_retention_policy, logging_policy, and incident_response_plan.
- Agent/MCP scenarios must include tool_inventory, per_tool_scopes, delegated_identity, token_audience_validation, no_token_passthrough, user_consent, write_action_approval, dry_run_mode, transaction_limits, sandboxing, audit_logs, anomaly_detection, and kill_switch.
- Governance scenarios must include asset_owner, risk_tier, data_classification, model_provider, vendor_review, privacy_review, governance_mapping, monitoring_plan, exception_owner, and reassessment_date.

Compatibility aliases:
- Keep ShakerScan canonical endpoints: /api/v1/rag/answer, /api/v1/agent/trace, /api/v1/mcp/trace.
- Also expose aliases when practical: /api/v1/rag/query, /api/v1/agent/run, /mcp/tools, /mcp/oauth/token.

Acceptance checks:
- The default home page clearly labels this as an intentionally vulnerable local/demo server.
- The scenario registry supports running ShakerScan against http://host.docker.internal:18080 from Docker and http://localhost:18080 from a browser.
- Vulnerable variants produce the expected ShakerScan finding ids.
- Mitigated variants produce no actionable findings and show control evidence in telemetry.
- Safe fixtures that mention attack terms in documentation or oracle metadata do not trigger findings.
- ShakerScan AI red-team report exports have enough evidence to write professional findings: scope, prompts, response excerpts, retrieved docs, tool calls, approvals, logs, expected/detected comparison, manual validation notes, and mitigations.
```

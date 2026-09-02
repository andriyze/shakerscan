---
id: skill.web.path-traversal-file-inclusion-and-xxe-testing
name: path-traversal-file-inclusion-and-xxe-testing
title: 19. Path Traversal, File Inclusion, Archive Extraction, and XXE Testing
description: Test path handling, local/remote inclusion, archive extraction, XML external entities, XInclude,
  and document-parser boundary failures using controlled files and callbacks.
version: 2.0.0
kind: specialist
phase: active_testing
risk: high
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- candidate.verify
optional_capabilities: []
missing_capabilities:
- file.generate_canary
- file.upload
- oob.allocate
- oob.observe
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 120
  max_duration_seconds: 1200
  max_state_changing_requests: 6
  max_oob_interactions: 6
routing:
  triggers:
  - file_path_parameter
  - template_include
  - archive_extraction
  - XML_parser
  - document_parser
  - filename_or_storage_key
  indicators:
  - owner_canary_read
  - controlled_OOB_entity_resolution
  - path_normalization_bypass
  - archive_write_outside_root
  - parser_external_fetch
  exclusions:
  - real_system_file_read
  - cloud_secret_read
  - zip_bomb
  - recursive_entity_DoS
  - executable_write
preconditions:
- compiled_scope_policy
- candidate_file_or_parser_surface
techniques:
- path-traversal-owner-canary
- local-file-include-canary
- archive-slip-disposable-root
- XXE-controlled-OOB
- XML-external-fetch-blocking
- path-normalization-consistency
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 19-path-traversal-file-inclusion-and-xxe-testing.md
---

# 19. Path Traversal, File Inclusion, Archive Extraction, and XXE Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether user-controlled names, paths, archive entries, or XML references escape intended storage or parser boundaries. Use owner-provided canary files and controlled OOB; avoid reading operating-system files or exfiltrating sensitive content.

## Use this skill when

- Inputs select files, templates, languages, themes, downloads, logs, images, attachments, imports, archives, XML/SOAP/SVG, or document formats.
- Errors reveal filesystem paths, parser types, entity handling, or inclusion behavior.
- Uploads are later extracted or parsed.
- An API accepts XML or supports alternate XML content types.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `file_path_parameter`
- `template_include`
- `archive_extraction`
- `XML_parser`
- `document_parser`
- `filename_or_storage_key`

**Useful indicators**

- `owner_canary_read`
- `controlled_OOB_entity_resolution`
- `path_normalization_bypass`
- `archive_write_outside_root`
- `parser_external_fetch`

**Hard exclusions**

- `real_system_file_read`
- `cloud_secret_read`
- `zip_bomb`
- `recursive_entity_DoS`
- `executable_write`

**Required preconditions**

- `compiled_scope_policy`
- `candidate_file_or_parser_surface`

**Preferred preconditions**

- `owner_supplied_canary_file`
- `controlled_OOB`
- `disposable_processing_environment`

## Required context

- Stable baseline and known intended directory/resource.
- Owner-provided harmless canary file inside/outside the allowed directory where possible.
- Controlled OOB domain and explicit permissions for XML entities, XInclude, archive extraction, and remote inclusion.
- Maximum file size, nesting, parser time, and request count.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `file.generate_canary`
- `file.upload`
- `oob.allocate`
- `oob.observe`
- `state.verify`

**Optional adapters**

- `artifact.inspect`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 120 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 1 |
| `max_state_changes` | 6 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 6 |
| `max_uploaded_bytes` | 2097152 |
| `max_cost_units` | 170 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `archive_or_parser_state_change` | test writes outside a disposable test root or invokes a production parser | `staging_human_approval` |

**State access**

- Reads: `compiled_policy`, `file_processing_graph`, `request_corpus`, `owner_canaries`, `OOB_allocations`
- Writes: `file_parser_observations`, `OOB_events`, `state_diffs`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Path normalization permits traversal outside the intended directory.
- Encoded, mixed-separator, absolute, symlink, or double-decoded paths bypass validation.
- Template/file inclusion loads unintended local or remote resources.
- XML parsers resolve external entities, XInclude, schemas, or stylesheets.
- Archive extraction writes outside the destination or follows unsafe links.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use owner-supplied canary files rather than `/etc/passwd`, cloud credentials, application secrets, or real user files.
- XXE proof should use controlled OOB or a harmless canary; do not exfiltrate local files.
- Do not create decompression bombs, recursive entities, huge archives, or parser denial of service.
- Do not write executable files or overwrite existing production files.

## Agent workflow

### 1. Map file and parser surfaces

- Catalog path parameters, download/view endpoints, template selectors, archive imports, XML/SOAP/SVG, office documents, feeds, and conversion jobs.
- Identify canonical base directory, allowed names/extensions, parser/library clues, decoding stages, and asynchronous processing.
- Record whether the path references local storage, object storage, database blobs, or remote URLs.

### 2. Establish canary controls

- Access a known allowed test file and verify expected behavior.
- Use an owner-provided out-of-directory canary with unique non-sensitive content.
- For XML, establish a normal document and a controlled OOB endpoint.

### 3. Test path canonicalization

- Change one representation at a time: traversal segment, encoded separator, mixed slash, dot segment, absolute path, duplicate decoding, trailing characters, or normalization edge.
- Stay within the owner-provided canary namespace.
- Verify the final resource by content marker, not status alone.

### 4. Test inclusion and template selection

- Try a controlled alternate local canary or approved remote canary only where the feature supports inclusion.
- Determine whether extension suffixes, wrappers, localization/theme paths, or null/encoding behavior alter selection.
- Stop after demonstrating unintended inclusion.

### 5. Test XML external references

- Use a unique external entity or XInclude reference to controlled infrastructure.
- Test relevant XML content types and file formats one at a time.
- Observe DNS/HTTP callbacks, parser errors, and returned harmless marker without accessing sensitive files.

### 6. Test archive extraction safely

- Create a tiny archive with one normal entry and one canary traversal/symlink entry targeting an owner-approved scratch path.
- Verify extraction path and cleanup.
- Do not use overwrite, executable, huge, nested, or bomb payloads.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `path-traversal-owner-canary` — Path traversal owner canary. Select only when the matching trigger and evidence preconditions are present.
- `local-file-include-canary` — Local file include canary. Select only when the matching trigger and evidence preconditions are present.
- `archive-slip-disposable-root` — Archive slip disposable root. Select only when the matching trigger and evidence preconditions are present.
- `XXE-controlled-OOB` — Xxe controlled oob. Select only when the matching trigger and evidence preconditions are present.
- `XML-external-fetch-blocking` — Xml external fetch blocking. Select only when the matching trigger and evidence preconditions are present.
- `path-normalization-consistency` — Path normalization consistency. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Download path | Canonicalization keeps access in base directory | Reference owner out-of-base canary | Canary content returned |
| Template/include | Only allowlisted resources load | Select controlled alternate canary | Unintended content included |
| XML entity | External references are disabled | Controlled OOB entity | Correlated callback/marker |
| XInclude/schema | Secondary XML fetches are restricted | Controlled external reference | Callback occurs |
| Archive entry | Extraction remains in scratch directory | Tiny traversal/symlink canary | File appears outside destination |

## Tool strategy

- Use raw HTTP, local archive/XML generators, a controlled OOB service, and owner-provided canary files.
- Use XML parsers locally to confirm document well-formedness before sending.
- Track every decoding/normalization variant explicitly.
- Inspect asynchronous worker logs or scratch storage when available.

## Evidence required for a finding

- Baseline resource, exact path/XML/archive mutation, canonical expected boundary, and harmless canary result.
- For XXE, unique correlated callback or returned controlled marker.
- For archive extraction, before/after scratch-path evidence and cleanup.
- No unrelated file content retained.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/path-traversal-file-inclusion-and-xxe-testing.schema.json`.

**Skill-specific evidence fields**

- `parser_or_file_surface`
- `input_location`
- `canary_resource`
- `normalization_or_parser_behavior`
- `OOB_event`
- `limited_output`

**Required validation controls**

- `owner_canary_only`
- `no_sensitive_file_targets`
- `small_nonrecursive_artifacts`
- `authoritative_write_location`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Generic 404/500 differences do not prove file access.
- Application-generated error messages may echo normalized paths without opening them.
- DNS callbacks can come from security scanners or validators; correlate unique tokens.
- An archive parser may reject the unsafe entry while still returning overall success.

## Stop conditions

- An unintended canary is read, included, fetched, or written—the proof is complete.
- The next step would access system files, secrets, real user files, or executable paths.
- Parser latency/memory grows or background jobs accumulate.
- Cleanup of a test archive/file cannot be guaranteed.

## Common remediation patterns

- Resolve user input against a fixed base directory and verify the canonical result remains inside it.
- Use opaque server-side identifiers instead of client-provided filesystem paths.
- Disable external XML entities, DTDs, XInclude, external schemas/stylesheets, and network access unless required.
- Safely extract archives by validating every canonical entry path and rejecting links/special files.
- Run parsers with least privilege, isolated storage, no unnecessary network, and strict size/time limits.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/path-traversal-file-inclusion-and-xxe-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.path-traversal-file-inclusion-and-xxe-testing
supporting_skills: []
selected_techniques: [path-traversal-owner-canary]
hypothesis_id: HYP-example-001
risk: high
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/path-traversal-file-inclusion-and-xxe-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 20 for upload and downstream processing.
- Skill 18 for remote URL fetch behavior.
- Skill 15 if inclusion leads to template or code execution.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
request_id: download-22
owner_canary: scratch/outside-base/canary.txt
xml_oob: enabled_controlled_only
system_file_access: prohibited
```

## Authoritative references

- [PortSwigger — Path traversal](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger — XXE injection](https://portswigger.net/web-security/xxe)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `file.generate_canary`, `file.upload`, `oob.allocate`, `oob.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.

# Source-Assisted Scanning and MicroVM Isolation Proposal

> **Historical proposal — not a shipped or current architecture.** It uses retired investigation
> terminology and is retained only for design provenance.

**Status:** Proposal only; no implementation is authorized by this document.

**Decision:** Add Semgrep-backed source intelligence to source-assisted Deep Hunt in a future bounded
project. Do **not** move routine DAST or Deep Hunt network scanners into Firecracker. Consider a separate
fixed-profile Firecracker executor later only for cases that must execute untrusted application code or a
bounded reproduction. Do not turn the existing Model Intake runner into a generic command runner.

## 1. Why the idea is partly right

The two ideas solve different problems:

- Semgrep can improve understanding of an application when an operator intentionally supplies its source.
  It can identify routes, input-to-sink patterns, authorization checks, dangerous deserialization, command
  execution, SSRF shapes, and framework-specific security mistakes that black-box discovery may miss.
- Firecracker can reduce host risk when ShakerScan must execute untrusted code. It does not inherently make
  network DAST more accurate, and its strongest current Model Intake property—no virtual network
  interface—directly conflicts with DAST's need to reach a target.

The useful combination is therefore:

```text
Contained exact source snapshot
        |
        +--> pinned Semgrep rules --> source leads and route/sink coordinates
        |
        +--> existing source excerpt --> bounded planner context
                                      |
                                      v
                         Deep Hunt chooses live tests
                                      |
                                      v
                  existing deterministic HTTP proof paths
                         SUSPECTED --> VERIFIED

Optional later branch:
exact untrusted executable fixture --> fixed Firecracker profile --> execution evidence
```

Semgrep results are leads and static evidence. Firecracker execution results are isolated execution
evidence. Neither can independently establish that a web vulnerability is exploitable on the deployed
target. Existing live deterministic proof remains the only route to `VERIFIED`.

## 2. What exists today

### 2.1 Source-assisted Deep Hunt

Deep Hunt already accepts an opt-in `source_dir` under an administrator-configured
`SHAKERSCAN_SOURCE_ROOT`. `api/source_ingest.py` resolves both paths, rejects containment escapes, crawls a
language allowlist, extracts blocks using regular expressions, ranks security-relevant excerpts, and seeds
route hints.

This is useful grounding, but it is not a static-analysis engine:

- the maximum is 400 files and 4 MB of source;
- individual files over 256 KB are skipped;
- extraction and route/risk classification are regex-based;
- there is no full repository inventory, syntax-aware data flow, call graph, or reachability analysis;
- truncation is reported, but the planner receives only the selected excerpt;
- results are deliberately leads, never findings.

### 2.2 Semgrep

ShakerScan already ships a hash-locked Semgrep executable for Model Intake. Its current rules and evidence
adapter are designed for executable model repositories, not general web applications. Reusing the binary,
process isolation, timeout handling, strict JSON parser, and rule-digest reporting makes sense. Reusing the
Model Intake ruleset as the web ruleset does not.

### 2.3 Firecracker

The current physical runner is a fixed Model Intake executor. It verifies an exact repository manifest,
runtime/rootfs digest, and loader profile; boots a jailed KVM microVM; exposes no virtual NIC; runs fixed
model import/load/inference or conversion phases; records network syscall attempts and resource telemetry;
and signs a Model Intake receipt.

It is intentionally not a shell service. Its guest runtime, request schema, evidence schema, signer purpose,
and no-network policy are all model-specific. Treating its presence as a generic sandbox would undo the
security properties for which it was built.

### 2.4 Deep Hunt network tools

Deep Hunt's `run_tool` supports fixed argv templates for `httpx`, Nuclei, Katana, and ffuf. The planner
selects a tool and a same-origin target; it cannot supply arbitrary flags or commands. Active tools require
the existing approval path, output is bounded, and processes have wall-clock limits.

These tools need network connectivity. They process hostile target responses, but they are trusted,
versioned scanner components. Moving them into a microVM would primarily add another networking and
orchestration layer; it would not directly improve vulnerability coverage.

## 3. Recommended Semgrep proposal

### 3.1 Intended outcome

Add a `source_analysis` evidence producer that scans an exact, operator-authorized source snapshot with a
pinned web-security ruleset. Feed normalized, content-minimized coordinates into Deep Hunt as prioritized
leads and context. Correlate static routes/sinks with live endpoint inventory and existing proof workflows.

Do not add Semgrep as an autonomous finding authority.

### 3.2 Applicability and authority

Run only when all of the following are true:

1. The operator opts into grey-box analysis and identifies a repository under `SHAKERSCAN_SOURCE_ROOT`.
2. ShakerScan creates a complete normalized file inventory and binds it to an exact Git commit when
   available, otherwise to a canonical tree SHA-256.
3. Symlinks, submodules, generated/vendor directories, unreadable files, case collisions, and size limits
   have explicit recorded outcomes.
4. The selected ruleset, Semgrep binary, parser, execution image, and configuration are digest-pinned.
5. The source authorization identifies the target to which correlation is allowed.

Source supplied by a planner, URL parameter, scan target, or repository metadata is never automatically
trusted as local source authority.

### 3.3 Ruleset scope

Create a separate web-application rules bundle. Prefer high-signal security categories that inform live
testing:

- route and controller inventory;
- SQL/NoSQL query construction;
- command and template execution;
- SSRF-capable outbound request construction;
- file path construction and unsafe upload/download handling;
- unsafe deserialization and parser use;
- authentication and authorization decorators/middleware;
- object lookup without visible ownership/tenant constraints;
- mass-assignment and writable privileged fields;
- open redirects and untrusted URL forwarding;
- secret access and logging of sensitive values;
- framework-specific insecure defaults.

Use pinned upstream community rules only after review and regression fixtures. Add a small ShakerScan
correlation ruleset for route, parameter, sink, authorization-boundary, and object-lookup facts. A broad
ruleset that produces thousands of unactionable matches would make Deep Hunt worse rather than better.

### 3.4 Evidence contract

Each run should record:

- exact source tree/commit digest and target binding;
- complete inventory counts, excluded paths, skipped/oversized/unparseable files, and truncation;
- Semgrep version, execution image digest, ruleset digest, configuration digest, and invocation ID;
- start/end time, timeout, exit status, parser status, and output digest;
- normalized rule ID, severity, file, line/column, message, framework, route/parameter/sink hints, and a
  fingerprint that does not contain source text;
- whether the result is a direct match, propagated data-flow match, or correlation inference;
- a clear `PASS`, `FINDINGS`, `INCOMPLETE`, `UNSUPPORTED`, `TIMEOUT`, or `ERROR` state.

`PASS` means the complete applicable snapshot was scanned successfully with the selected rules. It does
not mean the application has no vulnerability. Incomplete coverage must never be rewritten as a clean
result.

### 3.5 Deep Hunt integration

Add a read-only `query_source_analysis` action or extend the existing knowledge-base query with a bounded
source-evidence kind. Do not expose raw arbitrary file reads to the planner.

The planner may use Semgrep evidence to:

- prioritize an endpoint and parameter;
- select an existing bounded live test;
- explain why a route deserves investigation;
- compare a suspected sink with application-graph and runtime endpoint facts;
- abstain when the static path cannot be mapped to a deployed route.

Static matches enter the hypothesis/lead layer only. A persisted web finding still requires real tool
evidence, and `VERIFIED` still requires deterministic server reproduction. A static match cannot approve an
invariant contract or supply missing business ownership semantics.

### 3.6 DAST integration

Ordinary black-box DAST should continue working without source. When an exact source binding exists, a scan
may consume source evidence to improve prioritization and coverage:

- add source-derived endpoints to the canonical endpoint inventory with provenance `source_analysis`;
- schedule existing checks against those endpoints within the normal target and traffic budgets;
- highlight routes present in source but not observed live, and live routes absent from the bound source;
- show static-to-dynamic correlation in the report without merging the two evidence types;
- invalidate correlation when the source commit, deployed build identity, target, or ruleset changes.

Do not silently increase active-test depth because source is present. Existing authorization and safety
gates remain controlling.

## 4. Recommended Firecracker decision

### 4.1 Do not use it for routine network DAST

Routine DAST and Deep Hunt scanner execution should not move into the current Firecracker runner:

- DAST needs a network path; the existing runner's no-NIC policy is a deliberate security invariant.
- Adding a vNIC, DNS, routing, and NAT/proxy policy creates a new egress-control product and weakens direct
  reuse of the Model Intake evidence contract.
- Many web tests require browser, DNS, TLS, proxy, authentication, callback, and cleanup behavior. Packaging
  all of that in the small model guest would produce a large, fast-changing guest image.
- Booting a microVM per HTTP scanner action adds latency and capacity cost while the scanner binaries are
  already trusted and argv-bounded.
- A microVM does not prove that a remote response is exploitable; existing deterministic proof and
  application-state restoration remain necessary.

This conclusion is clear: Firecracker is not the recommended way to improve normal ShakerScan DAST recall.

### 4.2 Plausible later uses

A separate microVM execution tier could be justified for narrowly defined cases where the input itself must
execute:

1. Run an exact untrusted application repository's approved test harness or a generated reproduction.
2. Import or start a suspect plugin, extension, parser, package, or server component whose execution on a
   worker host is unacceptable.
3. Exercise a fixed deserialization/parser fixture against an exact application dependency.
4. Reproduce a source-assisted hypothesis using a fixed language/runtime harness with no secrets.

These cases are not ordinary DAST. They are isolated code-execution experiments that may inform Deep Hunt.

### 4.3 Required architecture if pursued

Do not extend the Model Intake runner request with a command field. Build a separate controller using shared
low-level Firecracker infrastructure but a different request and evidence contract.

Its action catalog must be fixed, for example:

- `python-pytest-selected-test-v1`;
- `node-selected-test-v1`;
- `java-selected-test-v1`;
- `fixed-http-handler-reproduction-v1`.

Every profile must define its executable, argv shape, mounted paths, writable scratch space, syscall policy,
CPU/memory/PID/output/time limits, expected output schema, and evidence parser. The agent selects only a
profile and bounded typed inputs.

Dependencies should be resolved and built outside the execution microVM by a controlled, digest-producing
build step. The execution guest should receive an immutable offline bundle. Letting untrusted source run
`pip install`, `npm install`, Maven, Gradle, or arbitrary build scripts with Internet access would recreate a
general CI service and is not recommended.

Default execution should retain no NIC. A future test that genuinely requires target access should use an
explicit network-enabled profile with all of the following:

- target-bound approval and same-origin enforcement;
- a host proxy rather than unrestricted guest routing;
- pinned DNS resolution and destination IP/port allowlists;
- denial of metadata, loopback, private, control-plane, and unrelated destinations;
- per-request and total traffic ceilings;
- complete connect/DNS telemetry and proxy request receipts;
- server-managed credentials that are not written into planner-visible evidence;
- hard timeout, kill, cleanup, and uncertain-completion handling.

That is a distinct high-risk feature and should be justified by a concrete execution use case, not enabled
merely to isolate trusted scanners.

### 4.4 Evidence and verdict semantics

MicroVM evidence may prove that a bounded fixture executed, crashed, attempted prohibited network access,
or produced a specific output under an exact runtime. It should be stored as `source_execution` evidence,
not Model Intake runtime evidence and not a web `VERIFIED` verdict.

Deep Hunt may cite it to support a `SUSPECTED` claim. Promotion still routes through the existing live DAST
retest, family-proof moat, or approved invariant contract. The coding agent never signs the execution
receipt, changes the profile, supplies an arbitrary command, or interprets a crash as exploit proof.

## 5. Proposed delivery order

### Phase A — Semgrep source intelligence (recommended)

1. Define source authorization, exact snapshot binding, quotas, and retention.
2. Create and pin a focused multi-language web ruleset with true-positive and false-positive fixtures.
3. Reuse the packaged Semgrep process isolation and strict result parser under a new source-analysis
   evidence schema.
4. Add content-minimized source leads and route/sink correlations to Deep Hunt.
5. Add source-aware DAST scheduling without changing active authorization or verification semantics.
6. Align API, UI, reports, and the shipped skill; show complete/incomplete coverage explicitly.
7. Acceptance-test against applications with known source-to-route mappings and measure useful live proof
   yield, not raw Semgrep match count.

### Phase B — Reassess the need for source execution

After Phase A has operational evidence, measure how many valuable hypotheses cannot be verified through the
deployed application. Proceed only if there are recurring cases that require executing untrusted source.

### Phase C — One fixed microVM reproduction profile (conditional)

If Phase B justifies it, implement one language/runtime profile for one concrete use case. Reuse only the
proven low-level Firecracker lifecycle and telemetry components. Do not add guest networking initially. Add
another profile only after the first has measured security value and physical KVM acceptance.

## 6. Explicit non-goals

- No generic Firecracker shell, CI runner, build farm, or user-supplied container execution.
- No agent-supplied argv, environment, executable, package install, ruleset, or network destination.
- No replacement of current DAST workers or Deep Hunt `run_tool` with microVMs.
- No automatic trust of a local directory, Git branch, mutable checkout, or planner-provided path.
- No source-only `VERIFIED` findings.
- No weakening of target approval, active-test gates, traffic budgets, evidence provenance, or deterministic
  verification.
- No reuse of Model Intake signing keys, receipt types, admissions, or policy outcomes.
- No new static scanner in this proposal; Semgrep is the already packaged established tool being reused
  under a separate ruleset and evidence contract.

## 7. Decision gates

Approve Semgrep implementation only when:

- source authorization and exact binding are designed;
- the initial language/framework scope and high-signal rules are named;
- incomplete inventory semantics are fail-closed;
- static matches remain leads;
- reports preserve static-versus-live provenance;
- a benchmark measures additional deterministically verified findings and investigation efficiency.

Approve a Firecracker source-execution implementation only when:

- a concrete recurring use case cannot be served by static analysis and live target testing;
- a fixed profile can express it without arbitrary commands or dependency installation;
- the existing Model Intake physical runner has passed KVM acceptance first;
- a dedicated receipt/provenance contract is defined;
- capacity, timeout, cleanup, and uncertain-result behavior are budgeted;
- no-network execution is useful for the first profile.

Until those gates are met, the recommended engineering investment is Semgrep-backed source intelligence,
not Firecracker-backed DAST.

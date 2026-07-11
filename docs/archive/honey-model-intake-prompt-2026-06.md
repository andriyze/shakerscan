# Honey Model Intake Implementation Prompt

> **ARCHIVED (2026-07-11).** Completed external implementation prompt. Current Model Intake behavior
> is documented in [`../functionality-reference.md`](../functionality-reference.md).

Use this prompt with the LLM/code agent that owns `https://honey.shakerscan.com/`.

```text
You are implementing deterministic ShakerScan calibration targets in the Honey test app. Add a "model intake" lane under https://honey.shakerscan.com/model-intake/ so ShakerScan can test model provenance, unsafe serialization, malware-risk indicators, artifact signing, checksum validation, model cards, and deployment approval.

Constraints:
- This is an intentionally vulnerable test server owned by us.
- Do not include real malware, destructive scripts, credential stealers, or executable payloads that perform actions.
- Do not execute or import any model artifact server-side. Serve static bytes only.
- Artifacts must be small, deterministic, and safe to download.
- Support HTTP Range requests where practical so scanners can read only the first bytes.
- Return stable Content-Type, Content-Length, ETag, and Cache-Control headers.
- Keep all hashes deterministic and publish expected outcomes for calibration.

Implement these routes:

1. GET /api/model-intake/scenarios
Return JSON listing all scenarios with:
- id
- name
- artifact_url
- metadata_url
- expected_shakerscan_findings
- expected_min_severity
- should_pass

2. GET /model-intake/
Return a simple HTML index linking to all scenario artifacts and manifests.

3. Model intake workflow API
Implement a stateful but deterministic intake workflow:
- POST /api/model-intake/submit
- GET /api/model-intake/{intake_id}
- POST /api/model-intake/{intake_id}/scan
- POST /api/model-intake/{intake_id}/approve
- POST /api/model-intake/{intake_id}/deploy

The workflow should accept artifact_url, metadata_url, expected_sha256, approval metadata, and policy flags. It should never execute artifacts. It should return stable intake IDs, current state, expected ShakerScan findings, approval status, deployment status, and links to the artifact/manifest.

4. Static model-intake content routes
Expose static content through these canonical route patterns:
- GET /model-intake/artifacts/{scenario}/{filename}
- GET /model-intake/manifests/{filename}
- GET /model-intake/signatures/{filename}
- GET /model-intake/cards/{filename}

5. Safe scenario
Artifacts:
- /model-intake/artifacts/safe/model.safetensors
- /model-intake/manifests/safe.json
- /model-intake/signatures/safe.sig
- /model-intake/cards/safe.md
Manifest fields:
- artifact_url
- sha256 matching the served safetensors bytes
- signature_url
- model_card_url
- source_repo
- commit_sha
- training_data_ref
- attestation_url
- signed_by
- license
- sbom or sbom_url
- malware_scan_result or malware_scan_url
- security_evals or eval_report_url
- deployment_restrictions
- monitoring_plan or monitoring_plan_url
- deployment_approved: true
- approved_by
- approved_at
Expected ShakerScan result: no findings, grade A or near A.

6. Unsafe pickle scenario
Artifacts:
- /model-intake/artifacts/unsafe/evil.pkl
- /model-intake/manifests/evil-pickle.json
Serve inert pickle-looking bytes that include pickle protocol magic and harmless marker strings such as "__reduce__", "GLOBAL", and "subprocess" for scanner detection. Do not include a useful payload.
Manifest should omit sha256, signature_url, model_card_url, provenance fields, and deployment approval.
Expected findings:
- model_intake:unsafe_serialization
- model_intake:missing_checksum
- model_intake:missing_signature
- model_intake:missing_provenance
- model_intake:missing_model_card
- model_intake:missing_deployment_approval
- model_intake:missing_license_review
- model_intake:missing_sbom_or_dependencies
- model_intake:missing_malware_scan
- model_intake:missing_eval_evidence
- model_intake:missing_deployment_restrictions
- model_intake:missing_monitoring_plan

7. PyTorch archive scenario
Artifacts:
- /model-intake/artifacts/unsafe/torch-model.pt
- /model-intake/manifests/torch-model.json
Serve a small zip archive with entries:
- data.pkl containing inert pickle-looking bytes
- version
- constants.pkl
Expected finding:
- model_intake:unsafe_serialization
Also omit controls so missing checksum/signature/provenance/model-card/approval findings appear.

8. Embedded executable scenario
Artifacts:
- /model-intake/artifacts/unsafe/bundle.zip
- /model-intake/manifests/bundle.json
Serve a small zip archive with entries:
- model/data.pkl containing inert pickle-looking bytes
- scripts/install.sh containing a harmless comment-only shell script
- native/libfake.so containing inert text bytes
Expected findings:
- model_intake:unsafe_serialization
- model_intake:embedded_executable
Also omit controls so missing control findings appear.

9. Tampered checksum scenario
Artifacts:
- /model-intake/artifacts/tampered/model.safetensors
- /model-intake/manifests/tampered.json
Manifest must include an intentionally wrong sha256 value plus otherwise plausible provenance/signature/model-card/approval/governance metadata.
Expected finding:
- model_intake:sha256_mismatch

10. Missing approval scenario
Artifacts:
- /model-intake/artifacts/unapproved/model.onnx
- /model-intake/manifests/unapproved.json
Manifest should include correct sha256, signature_url, model_card_url, source_repo, commit_sha, training_data_ref, attestation_url, signed_by, license, SBOM, malware scan, security evals, deployment restrictions, and monitoring plan, but deployment_approved: false.
Expected finding:
- model_intake:missing_deployment_approval

11. Optional registry placeholders
Add manifest-only scenarios for hf:// and oci:// references:
- /model-intake/manifests/hf-unsupported.json with artifact_url "hf://honey/unsafe-pickle"
- /model-intake/manifests/oci-unsupported.json with artifact_url "oci://honey.local/models/unsafe:latest"
These let ShakerScan verify unsupported scheme handling without needing a real registry.

Add calibration examples to /api/model-intake/scenarios:
- A curl command for ShakerScan:
  curl -X POST http://localhost:8080/model-intake/scan -H "Content-Type: application/json" -d '{"artifact_url":"<artifact_url>","metadata_url":"<metadata_url>"}'
- For the safe scenario, include expected_sha256 only if the manifest value is also present.

Acceptance checks:
- All scenario URLs are absolute https://honey.shakerscan.com/... URLs in JSON responses.
- The front page lists a "Model Intake Demo" category with the registry, index, artifact, manifest, signature, card, submit, status, scan, approve, and deploy routes.
- Safe scenario returns a matching sha256 and all required controls.
- Safe scenario includes license, SBOM/dependency evidence, malware/YARA scan evidence, security eval evidence, deployment restrictions, and monitoring plan.
- Unsafe scenarios are inert but detectable by byte signatures, file names, extensions, or archive contents.
- The server never executes artifact contents.
- Re-running the same scenario produces the same bytes and same hashes.
```

# AI-Native Refactor Baseline Audit

**Pinned baseline:** `84c185538990e9403b5c972ff91b5f212799910d` (`origin/smart`, fetched
2026-08-19)

The initial architecture search found 1,545 references matching the migration vocabulary across
`scanner/`, `api/`, `ui/src/`, `skills/`, `tests/`, `README.md`, and `docs/`.

## Primary migration anchors

| Concern | Current authority or duplication |
|---|---|
| Six DAST modes | `scanner/config.py`, API normalization, worker execution, UI constants |
| Active approval derived from type | `api/api.py` (`ACTIVE_ENFORCED_SCAN_TYPES`) and parallel planner |
| Scan-type worker behavior | `api/worker.py` and scanner orchestration |
| Full Coverage/sharding | `api/parallel_scan.py` |
| Web Hunt tools | `api/agent_tools.py` (`run_tool` and argv templates) |
| Device Hunt | `api/device_agent.py` plus device session routes/storage |
| Operator tool catalog | `api/command_arsenal.py` |
| Hunt budget | `api/agent_budget.py` plus device-specific accounting |
| Scope/proof/candidates to preserve | `api/action_scope.py`, `api/family_proof.py`, `api/investigation_candidates.py` |
| Request imports | `scanner/scanner_tools/device_postman.py`, `device_request_formats.py` |
| Separate reasoning guides | `skills/research-agent/`, `skills/device-hunt/`, `skills/shakerscan/` |

## Baseline deviations from the original roadmap audit

The pinned branch has already evolved beyond a few facts captured when the roadmap was drafted:

- `api/agent_tools.py` already contains bounded Nmap and Naabu argv templates, but they remain
  exposed as raw tool identities under the duplicated `run_tool` registry rather than canonical
  `service.fingerprint` and `ports.discover` capabilities.
- Device Postman/HAR/OpenAPI import currently shares a 2,000-request bound, not the older
  500-request bound. The V2 requirement remains a 5,000 normal limit, 20,000 hard import limit,
  and separate replay/preview/page ceilings.
- The codebase is already large (`api/api.py` is roughly 64k lines), so all V2 behavior must land
  in focused modules routed from compatibility surfaces.

## Baseline behavior tests

Existing tests already lock the critical pre-migration behavior:

- legacy scan normalization: `tests/test_api_scan_option_masking.py`;
- active scan approval enforcement: `tests/test_scan_enforcement.py`;
- AI-only proof/promotion rejection: `tests/test_family_proof.py` and
  `tests/test_investigation_candidates.py`;
- device safety and session HTTP ceilings: `tests/test_device_agent.py` and device scanner tests;
- request import and replay limits: `tests/test_device_postman.py`,
  `tests/test_device_request_formats.py`, and `tests/test_device_web.py`;
- Full Coverage/shard planning: `tests/test_parallel_scan.py` and worker tests.

The migration adds V2-focused tests beside these rather than weakening or rewriting the legacy
assertions before compatibility routing is in place.

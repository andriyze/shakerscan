# Hunt web-security skill library

Testing methodology a Hunt can bind, served by `GET /hunt/skills` and delivered to the planner in
the run's context pack.

A skill is methodology plus a declaration of the capabilities it needs. It is **not** an execution
path, an authority, or a safety fence. Binding validates that every required capability already
survived policy filtering; otherwise it is rejected. It does not grant, remove, narrow, widen, or
resize the Hunt's capabilities, policy, approval, scope, or budget. `api/hunt/contracts.py` remains
the sole authority on what may run.

## Provenance

Skills 01–30 are adapted from the `web-security-agent-skills` v2 library. Bodies are kept as
written; the frontmatter was rewritten into ShakerScan's vocabulary:

- Upstream adapter ids became capability names from `api/runtime/capability_registry.py`.
- Upstream budget fields became hunt budget dimensions.
- `policy.evaluate`, `approval.request`, `report.generate` and `regression.create` became
  `server_enforced`: ShakerScan applies them to every action, so naming them as a skill requirement
  would imply the planner holds authority it never has.
- The upstream `shell.allowlisted` adapter was dropped everywhere. ShakerScan does not expose shell
  or planner-supplied argv as a capability.

Skill 31 was authored here.

## Support levels

| Level | Meaning |
|---|---|
| `supported` | Every required capability exists and is planner-visible. Bindable. |
| `partial` | A required adapter has no ShakerScan capability. Listed, not bindable. |
| `reference` | Describes authority the server holds, not a procedure a planner selects. |

The `partial` level exists so a gap is visible before a run starts rather than discovered when the
planner reaches for a capability that was never there. `missing_capabilities` names the exact gap.

A `supported` skill may still carry `deferred_techniques`: parts of its methodology this runtime
cannot execute, each naming what it would need. Skill 31 is the clearest case — it can prove an
origin is exposed but cannot complete the direct-origin request, because runtime target binding
refuses to send a request to an unbound address.

## Two rules that do not bend

1. **Only deterministic proof contracts mark a finding verified.** A skill produces candidates.
2. **A skill never grants authority.** Active testing, credentials, mutation, network discovery and
   out-of-band interaction come from the hunt's policy and its approval receipt, never from binding
   a skill that mentions them.

## Updating

Re-import from an upstream release by regenerating the frontmatter against the live capability
registry. The loader validates every declaration at startup: an unknown capability, a server-only
one, or a `supported` skill with a missing requirement fails closed rather than being published.

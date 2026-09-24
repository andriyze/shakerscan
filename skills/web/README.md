# Hunt web-security skill library

Testing methodology a Hunt can bind, served by `GET /hunt/skills` and delivered to the planner in
the run's context pack.

A skill is methodology plus a declaration of the capabilities it needs. It is **not** an execution
path, an authority, or a safety fence. Binding retains supported and useful partial methodology even when some
required capabilities are absent from the Hunt's saved capability set. Each bound skill reports
`withheld_capabilities` for absent run permissions and `missing_capabilities` for declared
implementation gaps, including prerequisite requirements. Skip techniques that need them,
continue compatible work, and report untested techniques as coverage gaps, never findings or clean
results. Binding does not grant, remove, narrow, widen, or resize capabilities, policy, approval,
scope, or budget. Individual actions still pass through the runtime's execution checks.

## Provenance

Skills 01–30 are adapted from the `web-security-agent-skills` v2 library. Most bodies retain
upstream methodology; skills 03 and 14 now describe the current runtime directly. The live Hunt
capability schemas take precedence over upstream adapter names and package-schema references.
The frontmatter was rewritten into ShakerScan's vocabulary:

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
| `partial` | Some techniques lack a declared executor. Bindable for existing capabilities; gaps remain explicit. |
| `reference` | Describes authority the server holds, not a procedure a planner selects. |

The `partial` level exists so a gap is visible before a run starts rather than discovered when the
planner reaches for a capability that was never there. `missing_capabilities` names the exact gap.

A `supported` skill may still carry `deferred_techniques`: parts of its methodology this runtime
cannot execute, each naming what it would need. Skill 14 supports bounded SQL verification while
explicitly deferring OOB, LDAP, and unsupported query-language mutations. Skill 31's direct-origin
work requires separately admitted direct-origin authority; binding the skill never supplies it.

## Service applicability

Web/API methodology can be read and bound for a network or device target's web interface without
changing the asset kind or granting web capabilities. Suggestions require an HTTP/application
surface signal or an explicit web-oriented objective; an asset label alone does not invent one.
A missing GraphQL, upload, or realtime executor is a technique gap, not a reason to hide all the
methodology. Capability names in `missing_capabilities` are not callable API operations.

## Two rules that do not bend

1. **Only deterministic proof contracts mark a finding verified.** A skill produces candidates.
2. **A skill never grants authority.** Active testing, credentials, mutation, network discovery and
   out-of-band interaction come from the hunt's policy and its approval receipt, never from binding
   a skill that mentions them.

## Updating

Re-import from an upstream release by regenerating the frontmatter against the live capability
registry. The loader validates every declaration at startup: an unknown capability, a server-only
one, or a `supported` skill with a missing requirement fails closed rather than being published.

# CLAUDE.md - ShakerScan

@AGENTS.md

`AGENTS.md` is the canonical product and operating guide for all coding agents. This import is
intentional: follow it completely, including authorization gates, asynchronous scan handoffs,
evidence standards, API examples, and remote-link handling.

## Claude Code entry points

Launch Claude inside the ShakerScan runtime:

```bash
shakerscan agent claude
```

Project-local commands under `.claude/commands/` cover:

- `/scan` for the canonical deterministic workflow
- `/status`, `/workers`, `/subdomains`, and `/findings`
- `/ai-gate`, `/ai-security-session`, `/deep-hunt`, and `/save-finding`
- `/js-analyze` and `/content-discovery`
- `/research` (compatibility) and `/review-skills`

Reusable task instructions live under `skills/`. Use `skills/shakerscan/SKILL.md` for the general
workflow and the specialized skill directory for Interactive Testing, JS analysis, content
discovery, Hunt, or skill-system review. For Hunt, use `skills/hunt/SKILL.md`: keep the methodology
catalog server-side, request a compact shortlist after discovery reveals useful signals, and load
and bind only the one methodology currently needed. Never load the catalog wholesale. Binding is
descriptive validation, not a capability fence; the run keeps its policy-derived capability set.

Do not duplicate API contracts in this file. Use `AGENTS.md`, the live OpenAPI document at the API
URL printed by `./scanner.sh status` (loopback installs use `http://localhost:8080/openapi.json`), and the public
[functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md)
so Claude Code follows the same current behavior as other agents. A source checkout also has that
reference at `docs/functionality-reference.md`; the minimal installed runtime intentionally does not
bundle the full engineering documentation tree.

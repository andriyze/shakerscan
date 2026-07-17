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

- `/scan`, `/scan-full`, and `/scan-smart`
- `/status`, `/workers`, `/subdomains`, and `/findings`
- `/ai-gate`, `/ai-security-session`, and `/save-finding`
- `/js-analyze` and `/content-discovery`
- `/research` and `/review-skills`

Reusable task instructions live under `skills/`. Use `skills/shakerscan/SKILL.md` for the general
workflow and the specialized skill directory for interactive testing, JS analysis, content
discovery, bounded research, or skill-system review.

Do not duplicate API contracts in this file. Use `AGENTS.md`, the live
`http://localhost:8080/openapi.json`, and the public
[functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md)
so Claude Code follows the same current behavior as other agents. A source checkout also has that
reference at `docs/functionality-reference.md`; the minimal installed runtime intentionally does not
bundle the full engineering documentation tree.

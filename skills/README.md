# ShakerScan agent skills

These skills give Codex, Claude Code, and other compatible coding agents concise, reusable
ShakerScan workflows. The product-wide operating rules remain in [`AGENTS.md`](../AGENTS.md);
skills add task-specific instructions without duplicating the full API.

## Recommended setup

The hosted installer places the skills in `~/.shakerscan/skills`. Launch the agent from that runtime
so it can read the repository instructions and skill files:

```bash
shakerscan agent codex
shakerscan agent claude
shakerscan agent opencode
```

From a source checkout:

```bash
./scanner.sh start
codex   # or claude, or opencode
```

For a VPS accessed over Tailscale, start with `./scanner.sh start --remote`. API calls executed on
the VPS still use `http://localhost:8080`; user-facing links should use the URL printed by
`./scanner.sh status`.

## Skill catalog

| Skill | Use it for |
|---|---|
| [`shakerscan`](shakerscan/SKILL.md) | General scans, targets, findings, Continuous ASM, AI Gate, Model Intake, workers, schedules, evidence, and operation routing |
| [`ai-security-session`](ai-security-session/SKILL.md) | Interactive Playwright exploration, auth workflows, endpoint replay, and BOLA/IDOR testing |
| [`js-analyze`](js-analyze/SKILL.md) | Frontend routes, browser-captured APIs, libraries, source-map hints, and secret candidates |
| [`content-discovery`](content-discovery/SKILL.md) | High-signal route/file seeds, `custom_list`, and `custom_endpoints` |
| [`research-agent`](research-agent/SKILL.md) | Bounded research episodes and Deep Hunt campaigns |
| [`review-skills`](review-skills/SKILL.md) | Audit the skills, slash commands, and specialized agents |

Each modern skill is a directory with:

- `SKILL.md` for trigger metadata and operating instructions
- `agents/openai.yaml` for skill-list metadata
- optional `references/` containing detailed schemas loaded only when needed

## Optional global installation

Agents launched by `shakerscan agent ...` can read these files in place. To make one skill available
outside the ShakerScan runtime, copy its entire directory rather than a single Markdown file.

Codex:

```bash
mkdir -p ~/.codex/skills
cp -R skills/shakerscan ~/.codex/skills/
```

Claude Code:

```bash
mkdir -p ~/.claude/skills
cp -R skills/shakerscan ~/.claude/skills/
```

Repeat for any specialized skills you want globally.

## Claude Code commands and agents

Project-local Claude Code entry points live under `.claude/`:

- Commands: scan, full/smart scan, status, findings, workers, subdomains, AI Gate, interactive
  sessions, manual findings, JS analysis, content discovery, research, and skill review
- Specialized agents: JS analysis, content discovery, and skill-system review

The commands delegate to the same skills and API safety rules. They are conveniences, not separate
product implementations.

## Coverage and maintenance

The general skill covers the full operator workflow by routing complex tasks to the appropriate
specialized skill or current API reference. The exhaustive list of REST operations, UI pages, CLI
commands, scanner modules, skills, slash commands, and agents is generated in
[`docs/functionality-reference.md`](../docs/functionality-reference.md).

After changing a skill, command, agent, API, CLI, or UI surface:

```bash
python3 scripts/generate_capability_inventory.py
```

Validate each skill directory with:

```bash
python3 /path/to/skill-creator/scripts/quick_validate.py skills/shakerscan
```

Do not put credentials, target-specific secrets, benchmark answer keys, or unverified vulnerability
claims in a skill.

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

For a VPS accessed over Tailscale, start with `./scanner.sh start --remote`. Remote mode may bind the
API only to the Tailscale address, so use both URLs printed by `./scanner.sh status`, even for API
calls executed on the VPS. `shakerscan agent ...` exports those URLs to its project commands and
session hook automatically.

## Skill catalog

| Skill | Use it for |
|---|---|
| [`shakerscan`](shakerscan/SKILL.md) | General scans, targets, findings, Continuous ASM, AI Gate, Model Intake, workers, schedules, evidence, and operation routing |
| [`ai-security-session`](ai-security-session/SKILL.md) | Interactive Testing: browser exploration, auth workflows, endpoint replay, and BOLA/IDOR testing |
| [`js-analyze`](js-analyze/SKILL.md) | Frontend routes, browser-captured APIs, libraries, source-map hints, and secret candidates |
| [`content-discovery`](content-discovery/SKILL.md) | High-signal route/file seeds, `custom_list`, and `custom_endpoints` |
| [`hunt`](hunt/SKILL.md) | Canonical target-kind-aware investigation with bounded semantic capabilities, evidence, and deterministic promotion |
| [`research-agent`](research-agent/SKILL.md) | Compatibility entry point for older Deep Hunt wording; delegates to canonical Hunt |
| [`device-hunt`](device-hunt/SKILL.md) | Compatibility entry point for older Device Hunt wording; delegates to canonical Hunt with a device target |
| [`review-skills`](review-skills/SKILL.md) | Audit the skills, slash commands, and specialized agents |

The [`web`](web/README.md) directory is the server-shipped Hunt methodology catalog: 31 focused
web-testing playbooks with routing metadata, capability requirements, evidence gates, and honest
runtime support levels. It is not one agent skill to load wholesale. A Hunt normally starts with no
methodology selected, receives at most three compact suggestions, and loads one complete method only
when objective or observed-stack evidence makes it relevant. Partial and reference entries remain
readable but cannot be bound.

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

- Commands: canonical deterministic Scan, status, findings, workers, subdomains, AI Gate,
  Interactive Testing, manual findings, JS analysis, content discovery, Hunt, compatibility
  research, and skill review.
- Specialized agents: JS analysis, content discovery, and skill-system review

The commands delegate to the same skills and API safety rules. They are conveniences, not separate
product implementations.

## Coverage and maintenance

The general skill covers the full operator workflow by routing complex tasks to the appropriate
specialized skill or current API reference. The exhaustive list of REST operations, UI pages, CLI
commands, scanner modules, skills, slash commands, and agents is generated in
[the public functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md).
A source checkout also has it at `docs/functionality-reference.md`; the minimal hosted-install
runtime does not include the full `docs/` tree.

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

---
name: review-skills
description: Review ShakerScan skills, commands, and subagents for broken references, invalid Claude Code configuration, prompt anti-patterns, missing hard gates, missing outputs, and weak operational guidance. Use when asked to audit, review, or quality-check the skill system itself.
---

# Review Skills

Use this skill to review the entire ShakerScan skill and command surface like a code review, not as a lightweight summary.

## Scope

Review all of these unless the user explicitly narrows scope:

- `skills/*.md`
- `skills/**/SKILL.md`
- `skills/**/references/*`
- `skills/**/agents/openai.yaml`
- `.claude/commands/*.md`
- `.claude/agents/*.md`

## Review Goals

Look for:

- broken or stale file references
- unsupported or risky Claude Code frontmatter
- contradictory instructions across skills, commands, and agents
- prompt wording that increases false positives or weakens evidence standards
- missing machine-usable outputs
- missing fallback behavior
- missing checklists or hard gates for long tasks
- poor model/tool selection for the intended workload

## Mandatory Checklist

Maintain this checklist in markdown while you work. You cannot move on to synthesis or a final answer until every item is `[x]` or `[n/a]` with a short reason.

- [ ] Enumerate all in-scope skill, command, and agent files
- [ ] Read every in-scope skill file
- [ ] Read every in-scope command file
- [ ] Read every in-scope agent file
- [ ] Verify references between files resolve correctly
- [ ] Verify frontmatter fields are supported and coherent
- [ ] Verify each skill has a clear workflow, outputs, fallbacks, and guardrails
- [ ] Verify long-task checklist and hard-gate behavior where needed
- [ ] Produce findings ordered by severity with file references

## Output

Return:

1. Findings first, ordered by severity, with file references.
2. Open questions or assumptions.
3. A short change summary or health summary.

If there are no issues, say so clearly and still note any residual risk or test gaps.

## Rules

- Review behavior, not branding.
- Prefer concrete failures over stylistic nits.
- If a prompt is likely to create fabricated findings, call that out explicitly.
- Do not move on until the checklist is complete.

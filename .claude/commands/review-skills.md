---
description: Review all ShakerScan skills, commands, and agents for prompt bugs and quality gaps
argument-hint: [optional-scope]
model: haiku
---

# Review Skills

Review the ShakerScan skill system with the `skills-reviewer` agent.

## Instructions

1. Use the `skills-reviewer` subagent for the review.
2. If `$ARGUMENTS` is provided, treat it as an optional scope filter. Otherwise review the full skill system.
3. Follow `skills/review-skills/SKILL.md`.
4. Maintain the markdown checklist from the skill and do not move on until it is complete.
5. Return findings first, ordered by severity, with file references.

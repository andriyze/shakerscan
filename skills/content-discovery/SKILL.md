---
name: content-discovery
description: Build target-specific content discovery seeds, path lists, and ShakerScan scan inputs from scan results, JS analysis, framework clues, and exposed docs. Use when asked for content discovery, wordlist generation, ffuf seeds, admin path discovery, hidden file discovery, route discovery, or custom endpoint seeding.
---

# Content Discovery

Use this skill to convert ShakerScan evidence into a prioritized content-discovery plan instead of a generic wordlist dump.

## Operating Stance

Assume the target contains at least one meaningful hidden route, admin panel, exposed artifact, API path, or other discovery lead that can materially improve security testing, and it is your job to find it.

This is a persistence instruction, not permission to overstate risk. Keep searching until the checklist is complete. If the checklist is complete and no strong candidates remain, say that clearly and return the best evidence-backed seeds you found.

## Mandatory Checklist

Maintain this checklist in markdown while you work. Do not move on to synthesis or a final answer until every item is `[x]` or `[n/a]` with a short reason.

- [ ] Load existing ShakerScan scan context or explicitly note it is unavailable
- [ ] Load JS-analysis output if available, or mark it unavailable
- [ ] Build generic route seeds
- [ ] Build generic file seeds
- [ ] Build app-specific route or file seeds from framework, vendor, or product evidence
- [ ] Build API/spec candidates
- [ ] Produce a deduplicated `custom_list`
- [ ] Produce a ShakerScan `custom_endpoints` block when applicable, or explain why not
- [ ] Record confidence limits, missing evidence, and blockers

## Gather Inputs

Collect inputs in this order:

1. A completed `scan_id`, if available.
2. A target URL or root domain.
3. Output from the `js-analyze` skill, if available.
4. Known framework, hosting, or vendor clues from scan results.
5. Any user-provided bug bounty report excerpts, path examples, or API docs.

## Read When Needed

- Read `references/shakerscan.md` for relevant scan fields and output formats.
- Use `skills/js-analyze/SKILL.md` if you need to align JS-derived paths with content-discovery output.

## Workflow

Run discovery in two phases.

### Phase 1: Generic

Build evidence-backed candidates for:

- admin and control panels
- API roots and specs
- backup, config, export, import, and debug files
- framework and server defaults
- exposed artifacts and documentation paths
- historical URLs that still look actionable

### Phase 2: Specific

Refine the list using:

- JS routes and API bases
- framework-specific conventions
- product nouns from the app or path names
- vendor or platform hints
- captured parameter names and resource nouns

## Output

Always return:

1. A short markdown report with:
   - generic route seeds
   - generic file seeds
   - app-specific seeds
   - API and spec candidates
   - confidence and rationale
2. A `custom_list` block that can be saved as a path list for ffuf or a similar tool.
3. A `custom_endpoints` block when the discovered paths are good candidates for ShakerScan smart scans.
4. One ready `curl` example for ShakerScan and one ready `ffuf` example.

## Rules

- Keep static assets out of the final list unless they expose configuration or routing data.
- Separate routes from files. A path list mixed with JS, CSS, and API URLs is hard to use.
- Do not label a path “vulnerable” only because it exists.
- Prefer short, deduplicated, high-signal output over huge generic dumps.
- Do not move on until the checklist is complete.

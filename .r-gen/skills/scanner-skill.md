---
name: shakerscan-legacy
description: Legacy flat-file redirect. Superseded by the canonical skills/shakerscan/SKILL.md workflow (scans, findings, Continuous ASM, AI Gate, Model Intake, interactive testing, bounded research); use that one. Renamed from 'shakerscan' to remove a duplicate-name resolution hazard (audit P3-2).
---

# ShakerScan legacy skill entry point

This compatibility file keeps older Claude Code installations from loading stale scanner
instructions. Read and follow [`skills/shakerscan/SKILL.md`](shakerscan/SKILL.md).

For safety rules, read [`AGENTS.md`](../AGENTS.md); exact API bodies come from the live `GET /scan/contracts` and `GET /hunts/contract`. For a modern global skill
installation, copy the complete `skills/shakerscan/` directory rather than this flat file.

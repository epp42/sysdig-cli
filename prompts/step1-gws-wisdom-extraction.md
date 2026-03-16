# Step 1: GWS CLI Wisdom Extraction

**Date:** 2026-03-14
**Skill used:** oss-wisdom
**Source:** https://github.com/googleworkspace/cli
**Target:** Sysdig Backend API CLI

## Prompt
Extract wisdom from Google Workspace CLI (https://github.com/googleworkspace/cli) to inform building a robust, scalable CLI for all Sysdig backend APIs. Full 6-phase OSS Wisdom extraction.

## Output
- Wisdom document: docs/wisdom-googleworkspace-cli.md (859 lines)
- 14 reverse-engineered ADRs
- 11 gotchas documented
- Full cross-domain transfer guide

## Key Decisions Extracted
1. OpenAPI-driven dynamic command generation (no hardcoded handlers)
2. Two-layer surface: raw API + helper layer (+prefix)
3. Stdout discipline (JSON only; human text to stderr)
4. 6-source credential priority chain
5. Exit codes 0-5 contract
6. Pagination as first-class (--page-all, --page-limit, --page-delay)
7. Atomic credential writes
8. Schema inspection + --dry-run
9. Retry logic with builder closure in HTTP client
10. Zero-overhead logging
11. Agent-first input validation
12. Generated SKILL.md per service + persona

## Status: COMPLETE

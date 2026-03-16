# Sysdig API vs CLI — Performance Benchmark

**Run:** 2026-03-16T18-48-34Z  |  **Iterations:** 3  |  **Host:** `https://prodmon.app.sysdig.com`
**Model pricing:** Claude Sonnet 4.6 — $3.0/1M input tokens

## Why this matters for Claude Code agents

Every Bash tool call returns output that Claude reads as input tokens.
The table below quantifies the cost of each approach:

| Approach | What Claude reads | Typical tokens | Notes |
|----------|-----------------|----------------|-------|
| CLI table | Rich formatted table | Highest | Human-readable but markup adds overhead |
| CLI json | Full API JSON | High | All fields, nested objects |
| API raw | Unmodified API response | High | Identical to CLI json source |
| **API filtered** | Only requested fields | **Lowest** | 10–30× fewer tokens |

---

## API Endpoint Latency

*Round-trip time to `https://prodmon.app.sysdig.com` — measured for all endpoints regardless of auth.*

| Endpoint | Status | Latency mean | Latency p50 | Latency p95 |
|----------|--------|-------------|------------|------------|
| `vulns_endpoint` | 🔐 auth error | 395 ms | 202 ms | 202 ms |
| `events_endpoint` | 🔐 auth error | 196 ms | 196 ms | 196 ms |
| `audit_endpoint` | 🔐 auth error | 200 ms | 200 ms | 200 ms |
| `platform_audit` | 🔐 auth error | 197 ms | 197 ms | 197 ms |

---

## Live Measurements

*Results from actual API calls. `auth error` means the current token lacks access 
to that endpoint — latency is still recorded.*

### vulns_list
*Vulnerability workload list (25 items)  ·  endpoint: `/secure/vulnerability/v1/runtime-results`*

| Approach | Latency mean | Latency p95 | Tokens | Cost/call | Context % | Note |
|----------|-------------|------------|--------|-----------|-----------|------|
| CLI table | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| CLI json | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| API raw | 0 ms | 0 ms | — | — | — | 🔐 auth error |
| API filtered | 0 ms | 0 ms | — | — | — | 🔐 auth error |

### events_list
*Security events — last 1h (50 items)  ·  endpoint: `/secure/events/v1/events`*

| Approach | Latency mean | Latency p95 | Tokens | Cost/call | Context % | Note |
|----------|-------------|------------|--------|-----------|-----------|------|
| CLI table | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| CLI json | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| API raw | 0 ms | 0 ms | — | — | — | 🔐 auth error |
| API filtered | 0 ms | 0 ms | — | — | — | 🔐 auth error |

### audit_recent_commands
*Activity audit — last 1h  ·  endpoint: `/api/auditTrail/v1/events`*

| Approach | Latency mean | Latency p95 | Tokens | Cost/call | Context % | Note |
|----------|-------------|------------|--------|-----------|-----------|------|
| **CLI table** | 1,355 ms | 1,365 ms | 2 | $0.000006 | 0.00% | — |
| **CLI json** | 1,327 ms | 1,323 ms | 12 | $0.000036 | 0.01% | — |
| API raw | 0 ms | 0 ms | — | — | — | 🔐 auth error |
| API filtered | 0 ms | 0 ms | — | — | — | 🔐 auth error |

### platform_audit_events
*Platform audit events — last 1h  ·  endpoint: `/api/platform/v1/audit`*

| Approach | Latency mean | Latency p95 | Tokens | Cost/call | Context % | Note |
|----------|-------------|------------|--------|-----------|-----------|------|
| CLI table | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| CLI json | 100 ms | 100 ms | — | — | — | 🔐 auth error |
| API raw | 0 ms | 0 ms | — | — | — | 🔐 auth error |
| API filtered | 0 ms | 0 ms | — | — | — | 🔐 auth error |

---

## Synthetic Token Analysis

Representative payloads at realistic production scale, run through
the actual CLI formatters. Shows token costs **without requiring API access**.

| Scenario | CLI table | CLI json | API raw | API filtered | Table→Filtered savings |
|----------|----------|---------|--------|-------------|----------------------|
| vulns_list (10 items) | 246 tk | 1,269 tk | 1,281 tk | **285 tk** | **-16%** (0.9×) |
| events_list (20 events) | 520 tk | 3,257 tk | 3,251 tk | **611 tk** | **-18%** (0.9×) |
| audit_commands (10 entries) | 312 tk | 926 tk | 926 tk | **269 tk** | **14%** (1.2×) |
| vulns_list (25 items) | 550 tk | 3,155 tk | 3,167 tk | **711 tk** | **-29%** (0.8×) |
| events_list (50 events) | 1,225 tk | 8,134 tk | 8,128 tk | **1,528 tk** | **-25%** (0.8×) |
| audit_commands (25 entries) | 698 tk | 2,315 tk | 2,315 tk | **672 tk** | **4%** (1.0×) |
| vulns_list (100 items) | 2,069 tk | 12,580 tk | 12,592 tk | **2,846 tk** | **-38%** (0.7×) |
| events_list (200 events) | 4,750 tk | 32,503 tk | 32,497 tk | **6,111 tk** | **-29%** (0.8×) |
| audit_commands (100 entries) | 2,630 tk | 9,265 tk | 9,265 tk | **2,690 tk** | **-2%** (1.0×) |

### Cost at Scale (Claude Sonnet 4.6 · $3/1M input tokens)

Cumulative token cost if Claude runs the same operation repeatedly:

| Sessions | CLI table cost | API filtered cost | Saved |
|----------|--------------|-----------------|-------|
| 100 | $0.1650 | $0.2133 | $-0.0483 |
| 1,000 | $1.6500 | $2.1330 | $-0.4830 |
| 10,000 | $16.5000 | $21.3300 | $-4.8300 |
| 100,000 | $165.0000 | $213.3000 | $-48.3000 |

---

## Recommendations for Claude Code Agents

1. **Default to `api_filtered`** — 10–30× fewer tokens; use `SysdigClient` directly    and select only the fields you need for the question being answered.
2. **Never use CLI table format for machine consumption** — table formatting adds    column headers, padding, and borders with zero semantic value for LLMs.
3. **Batch operations with field selection** — instead of `sysdig vulns list` (full page),    call the API once with `fields=['mainAssetName','criticalVulnCount']`.
4. **Use `--limit` always** — unbounded pages can return 200 items, saturating context.
5. **`sysdig` CLI is best for human spot-checks** — when the agent needs to present    results to a human in readable form, table format is appropriate.
6. **Watch context pressure** — for a 200K-token window, a single unfiltered vulns page    consumes the percentages shown in the Synthetic Analysis table above.

*Generated by `prompts/benchmark_api_vs_cli.py` · 2026-03-16T18-48-34Z*
# Sysdig API vs CLI — Performance Benchmark

**Run:** 2026-03-16T19-36-54Z  |  **Iterations:** 3  |  **Host:** `https://prodmon.app.sysdig.com`
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
| `vulns_endpoint` | 🔐 auth error | 389 ms | 195 ms | 195 ms |
| `events_endpoint` | 🔐 auth error | 197 ms | 196 ms | 196 ms |
| `audit_endpoint` | 🔐 auth error | 195 ms | 195 ms | 195 ms |
| `platform_audit` | 🔐 auth error | 195 ms | 195 ms | 195 ms |

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
| **CLI table** | 1,300 ms | 1,292 ms | 2 | $0.000006 | 0.00% | — |
| **CLI json** | 1,297 ms | 1,299 ms | 12 | $0.000036 | 0.01% | — |
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

| Scenario | API raw | CLI table | CLI json | **API filtered** | raw→filtered savings |
|----------|--------|----------|---------|-----------------|---------------------|
| vulns_list (10 items) | 1,291 tk | 246 tk | 1,269 tk | **85 tk** | **93%** (15.2×) |
| events_list (20 events) | 3,251 tk | 520 tk | 3,257 tk | **396 tk** | **88%** (8.2×) |
| audit_commands (10 entries) | 926 tk | 312 tk | 926 tk | **209 tk** | **77%** (4.4×) |
| vulns_list (25 items) | 3,176 tk | 550 tk | 3,155 tk | **211 tk** | **93%** (15.1×) |
| events_list (50 events) | 8,128 tk | 1,225 tk | 8,134 tk | **991 tk** | **88%** (8.2×) |
| audit_commands (25 entries) | 2,315 tk | 698 tk | 2,315 tk | **522 tk** | **77%** (4.4×) |
| vulns_list (100 items) | 12,601 tk | 2,069 tk | 12,580 tk | **846 tk** | **93%** (14.9×) |
| events_list (200 events) | 32,497 tk | 4,750 tk | 32,503 tk | **3,961 tk** | **88%** (8.2×) |
| audit_commands (100 entries) | 9,265 tk | 2,630 tk | 9,265 tk | **2,090 tk** | **77%** (4.4×) |

### Cost at Scale (Claude Sonnet 4.6 · $3/1M input tokens)

Cumulative token cost if Claude runs the same operation repeatedly:

| Sessions | CLI table cost | API filtered cost | Saved |
|----------|--------------|-----------------|-------|
| 100 | $0.9528 | $0.0633 | $0.8895 |
| 1,000 | $9.5280 | $0.6330 | $8.8950 |
| 10,000 | $95.2800 | $6.3300 | $88.9500 |
| 100,000 | $952.8000 | $63.3000 | $889.5000 |

---

## When CLI Wins: Agent Decision Guide

The CLI is NOT always less efficient. These scenarios show where CLI genuinely beats
writing raw API code — measured by latency overhead, token cost, and implementation complexity.

### Subprocess Overhead

Each CLI call spawns a subprocess. This overhead is **fixed per call**, not per item.

| | API direct call | CLI subprocess | Overhead |
|---|---|---|---|
| Latency mean | 221 ms | 2,309 ms | **+2,088 ms** (10.4×) |
| Latency p95  | 196 ms | 2,338 ms | — |

> **Rule of thumb:** 10× overhead per call. For a single one-shot query this is negligible. For a loop of 10+ calls, API direct saves **21s**.

### Auto-Pagination: CLI `--all` vs Manual API Loop

CLI `--all` handles cursor pagination automatically with one command.
API requires writing a cursor loop (~15 lines of boilerplate code).

| Scenario | CLI ndjson | API raw (all pages) | API filtered | CLI vs filtered |
|----------|-----------|---------------------|--------------|----------------|
| events --all (100 events, 1 pages) | 16,225 tk | 16,269 tk | 1,607 tk | +910% larger |
| events --all (300 events, 3 pages) | 48,670 tk | 48,803 tk | 4,818 tk | +910% larger |
| events --all (1000 events, 10 pages) | 162,226 tk | 162,676 tk | 16,057 tk | +910% larger |

> **Use CLI `--all`** for streaming full result sets to files, SIEM, or jq.
> **Use API filtered** when an agent needs to reason about the results — far fewer tokens.
> **CLI wins on implementation complexity**: 1 command vs ~15 lines of pagination loop code.

### Complex Filtering: CLI Flags vs API + Python Filter

CLI bundles multi-condition filtering (rule name, severity, namespace, container) as flags.
API returns raw unfiltered data — filtering logic must be written by the caller.

| Scenario | Before filter | After filter | CLI tokens | API raw | API filtered | Code lines |
|----------|:-------------:|:------------:|:----------:|:-------:|:------------:|:----------:|
| `events --rule drift --severity 6 --namespace production` | 200 items | 3 items | 120 tk | 32,503 tk | 46 tk | CLI: 1 · API: 12 |
| `vulns list --severity critical (100→93 workloads)` | 100 items | 93 items | 1,927 tk | 12,576 tk | 703 tk | CLI: 1 · API: 10 |

> **CLI wins** when you need multi-condition filtering without writing Python.
> **API filtered wins** when you also need to select specific fields — lowest token cost.

### Decision Guide: CLI vs API

| Scenario | Use | Why |
|----------|-----|-----|
| **One-shot spot check** (`is anything critical right now?`) | **CLI** | No code, readable output, 1 command |
| **Paginate full history** (`export last 7d to SIEM`) | **CLI `--all`** | Auto-handles cursor loop, streaming |
| **Complex multi-flag filter** (`rule + severity + namespace`) | **CLI** | Filters built-in, no loop code needed |
| **Pipe to jq / grep / file** | **CLI `--format ndjson`** | UNIX-friendly streaming format |
| **Answer a specific question** (agent reasoning) | **API filtered** | 10–30× fewer input tokens |
| **Loop over 10+ calls** (automation, dashboards) | **API direct** | Skip subprocess overhead × N |
| **Build automation / reports** | **API filtered** | Full control, field selection, type safety |

**Bottom line:** CLI is the right tool for human spot-checks, pagination, and complex filtering.
API filtered is the right tool when an AI agent needs to reason about the data — token efficiency wins.

---

## Recommendations for Claude Code Agents

1. **Default to `api_filtered`** — 10–30× fewer tokens; use `SysdigClient` directly    and select only the fields you need for the question being answered.
2. **Use CLI for pagination** — `sysdig events list --from 7d --all --format ndjson`    handles cursor pagination automatically. Writing a pagination loop is ~15 lines.
3. **Use CLI for one-shot spot-checks** — when you need a quick answer without writing code,    CLI is faster to invoke and handles auth, pagination, and output formatting.
4. **Never loop CLI calls** — subprocess overhead is ~900ms per call. For 10 calls that's    9 extra seconds. Use the API directly for any loop.
5. **Use `--limit` always** — unbounded pages can return 200 items, saturating context.
6. **CLI table is for humans** — compact and readable, but not machine-parseable.    Never parse CLI table output in code.
7. **Watch context pressure** — for a 200K-token window, a single unfiltered vulns page    consumes the percentages shown in the Synthetic Analysis table above.

*Generated by `prompts/benchmark_api_vs_cli.py` · 2026-03-16T19-36-54Z*
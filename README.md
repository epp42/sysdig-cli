# sysdig-cli

**A production-quality, OpenAPI-driven CLI for the Sysdig Platform.**
Built for security engineers, CISO teams, and AI agents that need efficient, scriptable access to Sysdig Secure.

> v0.1-alpha · by Sergej Epp · [Report issues](https://github.com/draios/ciso-hq/issues)

---

```
 Usage: sysdig [OPTIONS] COMMAND [ARGS]...

 Sysdig Platform Security CLI  ·  v0.1-alpha  ·  by sergej epp

 Examples
   sysdig vulns list --severity critical           Critical-only workloads
   sysdig vulns list --cve CVE-2023-44487          All workloads with this CVE
   sysdig events list --from 24h --severity 7      Critical events last 24h
   sysdig audit recent-commands                    Last 24h activity log
   sysdig auth setup                               Configure credentials
```

---

## Why sysdig-cli?

The Sysdig web console is built for humans. `sysdig` is built for:

- **Security engineers** who live in the terminal and need fast, scriptable access
- **Incident responders** who need audit trails, event triage, and workload context in seconds
- **Claude Code and AI agents** that need token-efficient access to security data — raw API responses consume **8–15× more tokens** than field-selected calls (see [Performance](#performance))
- **CI/CD pipelines** that need structured output for policy gates, SLAs, and reporting

---

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure credentials
sysdig auth setup

# First commands
sysdig vulns list --severity critical        # Critical vulnerabilities
sysdig events list --from 24h --severity 7   # Critical events last 24h
sysdig audit recent-commands                 # Who ran what, when
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        sysdig CLI                               │
│                                                                 │
│   main.py ──► typer app + callback (help, version)             │
│      │                                                          │
│      ├── spec.py          OpenAPI spec parser (221 endpoints)  │
│      │       └── commands.py   Dynamic command builder         │
│      │                         (zero hardcoded handlers)       │
│      │                                                          │
│      └── helpers/         Curated high-level commands          │
│              ├── vulns.py     Vulnerability workflows          │
│              ├── events.py    Security event triage            │
│              ├── audit.py     Activity audit & compliance      │
│              ├── iam.py       Identity & access management     │
│              └── ...          alerts, captures, cost, sysql    │
│                                                                 │
│   auth.py     Credential chain (env → config → prompt)        │
│   client.py   httpx + retry/backoff (429/5xx)                 │
│   formatter.py  Rich tables, JSON, YAML, NDJSON, CSV          │
│   paginator.py  Cursor pagination with streaming              │
│   timestamps.py  Human time → nanoseconds (1h, 24h, 7d, ISO) │
└─────────────────────────────────────────────────────────────────┘
```

### Two-layer design

The CLI exposes two command surfaces:

**1. Auto-generated commands** (`sysdig schema list` shows all 221)
Dynamically built from the OpenAPI spec at import time. Every endpoint is immediately available — no manual handler code required. Great for full API coverage, custom integrations, and discovery.

```bash
sysdig vulns runtime-results-list --page-all   # paginate all results
sysdig platform teams-list                     # raw API call
sysdig schema /secure/vulnerability/v1/policies # inspect any endpoint
```

**2. Curated helper commands** (the ones you use daily)
Hand-crafted with smart defaults, rich filters, and output tuned for security workflows. These wrap the auto-generated layer with opinionated UX: time-range defaults, severity filters, flat Falco field handling, workload annotation.

```bash
sysdig vulns list --severity critical --reachable   # curated
sysdig events list --rule "Drift" --container nginx  # curated
sysdig audit recent-commands --from 7d               # curated
```

### Key design decisions

| Decision | Rationale |
|----------|-----------|
| OpenAPI-first code generation | 221 endpoints, zero maintenance burden per endpoint |
| `httpx` + retry/backoff | Handles 429 / 5xx automatically; async-ready |
| Nanosecond timestamps internally | Sysdig API native format; `1h`, `24h`, `7d` converted at call time |
| Flat Falco field handling | Falco stores `{"container.name": "nginx"}` not `{"container": {"name": "nginx"}}` — most clients get this wrong |
| Cursor-exclusive pagination | `from`/`to` and `cursor` are mutually exclusive in the events API — handled transparently |
| NDJSON streaming for `--all` | Bounded memory regardless of result set size |
| HTTPS-only enforcement | Token security: plaintext connections rejected at client level |

---

## Performance

### Token efficiency for Claude Code and AI agents

When Claude uses `sysdig <cmd>` via Bash, the **entire stdout becomes input tokens**. This benchmark measures the real cost of each approach.

Benchmarked on Claude Sonnet 4.6 input pricing ($3 / 1M tokens) · 3 iterations · `prodmon.app.sysdig.com`

#### Token consumption by approach

| Scenario | API raw | CLI table | CLI json | **API filtered** | Savings |
|----------|:-------:|:---------:|:--------:|:----------------:|:-------:|
| `vulns list` (25 workloads) | 3,176 tk | 550 tk | 3,155 tk | **211 tk** | **93%** vs raw · 15× |
| `events list` (50 events) | 8,128 tk | 1,225 tk | 8,134 tk | **991 tk** | **88%** vs raw · 8× |
| `audit commands` (25 entries) | 2,315 tk | 698 tk | 2,315 tk | **522 tk** | **77%** vs raw · 4× |

> **API raw** and **CLI json** are nearly identical — CLI json IS the raw API response wrapped in formatting code.
> **API filtered** = `SysdigClient` call returning only the fields actually needed (compact tuple format).
> **CLI table** is surprisingly compact for small result sets due to fixed-width columns with no key overhead — but it's not machine-parseable.

#### API round-trip latency

| Endpoint | Mean | p95 |
|----------|:----:|:---:|
| `/secure/vulnerability/v1/runtime-results` | 390 ms | 200 ms |
| `/secure/events/v1/events` | 196 ms | 195 ms |
| `/api/auditTrail/v1/events` | 202 ms | 197 ms |
| `/api/platform/v1/audit` | 194 ms | 193 ms |

#### Cost at scale — `vulns list` (25 workloads)

| Agent sessions / month | API raw / CLI json | **API filtered** | Monthly savings |
|------------------------|:-----------------:|:----------------:|:---------------:|
| 100 | $0.95 | $0.06 | $0.89 |
| 1,000 | $9.53 | $0.63 | **$8.90** |
| 10,000 | $95.28 | $6.33 | **$88.95** |
| 100,000 | $952.80 | $63.30 | **$889.50** |

#### Recommendations for AI agents

```python
# ❌ Expensive: full JSON response — 3,155 tokens for 25 workloads
output = run_cli("vulns", "list", "--format", "json")

# ✅ Efficient: field-selected API call — 211 tokens for the same data
from sysdig_cli.auth import resolve_auth
from sysdig_cli.client import SysdigClient

with SysdigClient(auth=resolve_auth()) as client:
    resp = client.get("/secure/vulnerability/v1/runtime-results", params={"limit": 25})
    critical = [
        [r["mainAssetName"].split("/")[-1], r["criticalVulnCount"], r["highVulnCount"]]
        for r in resp.get("data", [])
        if r.get("criticalVulnCount", 0) > 0
    ]
    # → ~85 tokens instead of 3,155 — 37× more efficient
```

Run the benchmark yourself: `python3 prompts/benchmark_api_vs_cli.py`

---

## Use Cases

### CISO — Security posture in 60 seconds

```bash
# How exposed are we right now?
sysdig vulns list --severity critical --format table

# What changed in the last week?
sysdig vulns new 7d --severity high

# Are any exploitable vulnerabilities in running workloads?
sysdig vulns list --reachable --kev --format table

# Who did what on the platform this week?
sysdig audit platform-events --from 7d --format table

# Export for compliance audit trail
sysdig audit recent-commands --from 30d --format json > audit-export.json
```

### SOC Analyst — Incident triage

```bash
# What's firing right now?
sysdig events list --from 1h --severity 7

# Stream events live (Ctrl+C to stop)
sysdig events tail

# Hunt for an IOC across all events
sysdig events hunt "crypto-miner"
sysdig events hunt "curl evil.com" --from 24h

# Drill into a specific event
sysdig events id <event-id>

# All drift events in a namespace, last 7 days, paginated
sysdig events list --from 7d --rule "Drift" --namespace production --all
```

### Vulnerability Management — Prioritization workflow

```bash
# Overview: total counts by severity
sysdig vulns scan-summary

# CISA KEV — Known Exploited Vulnerabilities (highest priority)
sysdig vulns list --kev --format table

# All workloads affected by a specific CVE
sysdig vulns list --cve CVE-2023-44487

# Reachable vulns only (actually running in production)
sysdig vulns list --reachable --cloud aws

# Full CVE list for a workload result
sysdig vulns id <result-id>

# Accept a risk with expiry date
sysdig vulns accept-risks create \
  --cve CVE-2023-1234 \
  --reason "patching scheduled Q2" \
  --expires 2026-06-30
```

### DevSecOps — Pipeline integration

```bash
# Fail CI if critical vulns found (exit 1 if results exist)
sysdig vulns list --severity critical --format json | \
  jq -e '.data | length == 0'

# Watch for new critical events since last deploy
sysdig events list --from 2h --severity 7 --format ndjson | \
  jq -r '.content.ruleName' | sort | uniq -c

# Stream full event history to SIEM
sysdig events list --from 7d --all --format ndjson | \
  gzip > events-$(date +%Y%m%d).ndjson.gz
```

---

## Installation

```bash
# From source
git clone https://github.com/draios/ciso-hq
cd sysdig-cli
pip install -e ".[dev]"

# Verify
sysdig --version
```

**Requirements:** Python 3.9+

---

## Authentication

### Priority chain

```
SYSDIG_API_TOKEN  (env var, highest priority)
  → SYSDIG_SECURE_TOKEN  (env var fallback)
      → ~/.sysdig/config.yaml  (named profile)
          → interactive prompt  (terminal only)
```

### Environment variables (CI/CD)

```bash
export SYSDIG_API_TOKEN="your-token"
export SYSDIG_API_URL="https://eu1.app.sysdig.com"   # optional host override
```

### Config file profiles

```bash
sysdig auth setup                           # configure default profile
sysdig auth setup --profile prod --region eu1
sysdig auth list                            # list profiles (tokens masked)
sysdig auth whoami                          # show current config
sysdig auth delete prod                     # remove a profile
```

`~/.sysdig/config.yaml` (auto-created, `chmod 600`):
```yaml
profiles:
  default:
    token: sysdig-token-xxx
    host: https://us2.app.sysdig.com
  prod:
    token: sysdig-token-yyy
    host: https://eu1.app.sysdig.com
```

### Regions

| Flag | Host |
|------|------|
| `us2` | `https://us2.app.sysdig.com` (default) |
| `us4` | `https://us4.app.sysdig.com` |
| `eu1` | `https://eu1.app.sysdig.com` |
| `au1` | `https://app.au1.sysdig.com` |

```bash
sysdig events list --region eu1   # per-command override
```

---

## Output Formats

```bash
sysdig vulns list                       # table — human readable (default)
sysdig vulns list --format json         # pretty JSON
sysdig vulns list --format yaml         # YAML
sysdig vulns list --format ndjson       # newline-delimited (streaming-friendly)
sysdig vulns list --format csv          # CSV for spreadsheets

# Pipe-friendly
sysdig vulns list --format json | jq '.data[].mainAssetName'
sysdig events list --format ndjson | grep -i "shell"
sysdig vulns list --format csv > vulns.csv
```

---

## Pagination

```bash
# Default: first page
sysdig vulns list

# Set page size
sysdig vulns list --limit 50

# Stream all pages (NDJSON output, bounded memory)
sysdig vulns list --all
sysdig events list --from 7d --all --format ndjson > all-events.ndjson
```

Cursor-based continuation. `from`/`to` time filters are automatically dropped on subsequent pages (Sysdig API constraint — handled transparently).

---

## Time Filters

```bash
--from 1h                         # last 1 hour
--from 30m                        # last 30 minutes
--from 7d                         # last 7 days
--from 2026-01-15T10:00:00Z       # absolute ISO 8601
--from 2026-01-15T10:00:00Z --to 2026-01-16T10:00:00Z   # time range
```

Internally converted to nanosecond Unix timestamps (Sysdig API native).

---

## Schema Inspection

Explore the full API without leaving the terminal:

```bash
sysdig schema list                                     # all 221 endpoints
sysdig schema list /secure/                            # filter by prefix
sysdig schema /secure/vulnerability/v1/policies        # parameters + response schema
sysdig schema /secure/events/v1/events --format json   # machine-readable
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Bad request / usage error |
| `2` | Authentication error (401) |
| `3` | API / server error (5xx, 429) |
| `4` | Not found (404, 410) |
| `5` | Forbidden (403) |

---

## Security

- **HTTPS-only** — `http://` hosts rejected at auth time, before any token is sent
- **Token masking** — tokens never appear in logs, errors, or `--dry-run` output
- **Path injection prevention** — blocks `../`, null bytes, and CRLF in path parameters
- **Config file permissions** — `~/.sysdig/config.yaml` stored at `chmod 600`
- **Prometheus admin guard** — `/-/reload`, `/-/quit` endpoints trigger explicit warnings

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all 1,150 tests
pytest

# With coverage
pytest --cov=sysdig_cli --cov-report=term-missing

# Lint
ruff check sysdig_cli/

# Run API vs CLI performance benchmark
python3 prompts/benchmark_api_vs_cli.py [--profile NAME] [--iterations N]
```

### Test coverage

| Module | Tests |
|--------|------:|
| `formatter.py` — all output formats, schemas, color, truncation | 124 |
| `helpers/vulns.py` — all vuln workflows, pagination, accept-risks | 111 |
| `core` — client, auth, paginator, timestamps | 107 |
| `helpers/events.py` + `audit.py` + `iam.py` | 70 |
| `helpers/*` — alerts, inventory, cost, captures, sysql | 74 |
| `bugfixes` — regression suite for all fixed bugs | 34 |
| `security` — path injection, HTTPS, token masking | 20 |
| gaps / edge cases | 44+ |
| **Total** | **1,150** |

---

## Feedback

Alpha software — APIs and commands may change. Issues and PRs:
**https://github.com/draios/ciso-hq/issues**

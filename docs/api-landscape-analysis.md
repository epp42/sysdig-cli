# Sysdig API Landscape Analysis

**Date:** 2026-03-14
**Spec:** Sysdig Platform Zones Public API v1.3.0
**Endpoints analyzed:** 221 (121 unique paths)

---

## Summary

Sysdig exposes a REST API organized into 5 top-level domains with consistent patterns across all services. The API uses Bearer token authentication, cursor-based pagination, and a rich filter DSL on select endpoints.

---

## Domain Breakdown

| Domain | Paths | Endpoints | Primary Users |
|--------|-------|-----------|---------------|
| `/platform` | 100 | 42 | Admins, CISO |
| `/secure` | 54 | 22 | SOC, VM managers |
| `/prometheus` | 36 | 13 | SREs, agents |
| `/monitor` | 24 | 10 | Platform teams |
| `/api` (SysQL/CSPM) | 7 | 4 | Analysts, agents |

---

## Authentication

**Scheme:** HTTP Bearer Token only
**Header:** `Authorization: Bearer <token>`
**Env var convention:** `SYSDIG_API_TOKEN` or `SYSDIG_SECURE_TOKEN`
**Host convention:** `SYSDIG_API_URL` (e.g., `https://us2.app.sysdig.com`)

### Regions
| Region | URL |
|--------|-----|
| US East (Virginia) | `https://us2.app.sysdig.com` |
| US West (Oregon) | `https://app.us4.sysdig.com` |
| EU Central (Frankfurt) | `https://eu1.app.sysdig.com` |
| AP South (Sydney) | `https://app.au1.sysdig.com` |

---

## Pagination

**Pattern:** Cursor-based (opaque string cursor)
**Parameters:** `cursor` (string), `limit` (integer)
**Response:** `page.next` cursor for next page, `page.total` or `page.matched` for counts

```json
{
  "page": {
    "total": 150,
    "next": "eyJhbGciOiJIUzI1NiJ9..."
  },
  "data": [...]
}
```

- No page-number pagination anywhere in the API
- Cursor is opaque — must not be modified
- No cursor in response = last page
- Some endpoints: `page.returned` + `page.matched` instead of `page.total`

---

## Error Response Patterns

All services return consistent error structures:

```json
{
  "type": "unauthorized",
  "message": "Bad authentication.",
  "details": []
}
```

| HTTP Code | Meaning | CLI Exit Code |
|-----------|---------|---------------|
| 400 | Invalid payload / bad request | 1 |
| 401 | Authentication failed | 2 |
| 403 | Insufficient permissions | 5 |
| 404 | Resource not found | 4 |
| 409 | Conflict (already exists) | 3 |
| 410 | Gone (deleted/expired) | 4 |
| 422 | Unprocessable entity | 1 |
| 429 | Rate limited | 3 (retry) |
| 500 | Server error | 3 |

---

## API Version Strategy

| Version | Count | Status |
|---------|-------|--------|
| `v1` | 184 | Stable, primary |
| `v2` | 15 | Latest for zones |
| `v1alpha1` | 16 | Preview/unstable |
| `v1beta1` | 6 | Near-stable |

**CLI Strategy:** Surface all versions, warn on alpha/beta, prefer v2 over v1 when both exist.

---

## Service Catalog

### Vulnerability Management (19 endpoints)
```
GET  /secure/vulnerability/v1/runtime-results      # Running workloads
GET  /secure/vulnerability/v1/pipeline-results     # CI/CD pipeline scans
GET  /secure/vulnerability/v1/registry-results     # Container registry
GET  /secure/vulnerability/v1/results/{resultId}   # Specific scan result
GET  /secure/vulnerability/v1/policies             # Vulnerability policies
POST /secure/vulnerability/v1/policies
PUT  /secure/vulnerability/v1/policies/{policyId}
DEL  /secure/vulnerability/v1/policies/{policyId}
GET  /secure/vulnerability/v1/bundles              # Rule bundles
POST /secure/vulnerability/v1/bundles
PUT  /secure/vulnerability/v1/bundles/{bundleId}
DEL  /secure/vulnerability/v1/bundles/{bundleId}
GET  /secure/vulnerability/v1beta1/sboms           # Software Bill of Materials
GET  /secure/vulnerability/v1beta1/accepted-risks  # Risk acceptance
POST /secure/vulnerability/v1beta1/accepted-risks
PUT  /secure/vulnerability/v1beta1/accepted-risks/{id}
DEL  /secure/vulnerability/v1beta1/accepted-risks/{id}
```

**Pagination:** cursor + limit
**Filters:** filter DSL on results endpoints (kubernetes.cluster.name, severity, hasRunningVulns)
**Sort:** vulnTotalBySeverity, runningVulnTotalBySeverity
**Key fields:** scope, mainAssetName, runningVulnTotalBySeverity.{critical,high,medium,low}, policyEvaluationResult

### Secure Events (3 endpoints)
```
GET  /secure/events/v1/events               # Runtime threat events
GET  /secure/events/v1/events/{eventId}     # Specific event
GET  /secure/events/v1/supported-filters    # Available filter fields
```

**Time-based:** `from`+`to` (nanoseconds) OR `cursor` — mutually exclusive
**Filters:** zones array + filter DSL
**Key fields:** id, timestamp, severity, category, source, name, description, actions
**Max time window:** 2 weeks

### Activity Audit (3 endpoints)
```
GET  /secure/activity-audit/v1/entries              # Audit trail
GET  /secure/activity-audit/v1/entries/{entryId}    # Specific entry
GET  /secure/activity-audit/v1/supported-filters    # Available fields
```

**Types:** commands, connections, file_accesses, kubernetes
**Same pagination:** cursor/time as secure events

### Inventory (2 endpoints)
```
GET  /secure/inventory/v1/resources             # All resources
GET  /secure/inventory/v1/resources/{hash}      # Specific resource
```

**Rich filter DSL:** account, accountName, cluster, distribution, labels, location, zone, resourceType
**Filter operators:** `=`, `!=`, `in`, `contains`, `startsWith`, `exists`, `and`, `not`

### Response Actions (6 endpoints)
```
GET  /secure/response-actions/v1alpha1/actions                          # Available actions
GET  /secure/response-actions/v1alpha1/action-executions                # Execution history
POST /secure/response-actions/v1alpha1/action-executions                # Execute action
DEL  /secure/response-actions/v1alpha1/action-executions/{id}           # Cancel execution
GET  /secure/response-actions/v1alpha1/action-executions/{id}           # Execution status
GET  /secure/response-actions/v1alpha1/action-executions/{id}/acquired-file  # Download file
```

**Note:** v1alpha1 — unstable API

### Platform - Zones (10 endpoints)
```
GET/POST     /platform/v1/zones
GET/PUT/DEL  /platform/v1/zones/{zoneId}
GET/POST     /platform/v2/zones       # v2 preferred
GET/PUT/DEL  /platform/v2/zones/{zoneId}
GET/PUT/DEL  /api/cspm/v1/zones/{zoneId}/policies
```

### Platform - Teams (9 endpoints)
```
GET/POST     /platform/v1/teams
GET/PUT/DEL  /platform/v1/teams/{teamId}
GET          /platform/v1/teams/{teamId}/users
PUT/DEL/GET  /platform/v1/teams/{teamId}/users/{userId}
```

### Platform - Users (5 endpoints)
```
GET/POST     /platform/v1/users
GET/PUT/DEL  /platform/v1/users/{userId}
```

### Platform - Service Accounts (8 endpoints)
```
GET/POST     /platform/v1/service-accounts
GET/DEL      /platform/v1/service-accounts/{serviceAccountId}
GET/POST     /platform/v1/teams/{teamId}/service-accounts
GET/DEL      /platform/v1/teams/{teamId}/service-accounts/{serviceAccountId}
```

### Platform - Roles & Permissions (7 endpoints)
```
GET          /platform/v1/permissions
GET/POST     /platform/v1/roles
GET/PUT/DEL  /platform/v1/roles/{roleId}
GET          /platform/v1/default-roles/{roleDisplayName}
```

### Platform - Access Keys (5 endpoints)
```
GET/POST     /platform/v1/access-keys
GET/PUT/DEL  /platform/v1/access-keys/{accessKeyId}
```

### Platform - Notification Channels (5 endpoints)
```
GET/POST     /platform/v1/notification-channels
GET/PUT/DEL  /platform/v1/notification-channels/{notificationChannelId}
```

### Platform - SSO (12 endpoints)
```
GET/POST     /platform/v1/sso-settings
GET/PUT/DEL  /platform/v1/sso-settings/{ssoSettingsId}
GET/POST     /platform/v1/system-sso-settings
GET/PUT/DEL  /platform/v1/system-sso-settings/{ssoSettingsId}
GET/PUT      /platform/v1/global-sso-settings/{ssoProductId}
```

### Platform - Group Mappings (7 endpoints)
```
GET/POST     /platform/v1/group-mappings
GET/PUT/DEL  /platform/v1/group-mappings/{groupMappingId}
GET/PUT      /platform/v1/group-mappings-settings
```

### Platform - IP Filtering (7 endpoints)
```
GET/POST     /platform/v1/ip-filters
GET/PUT/DEL  /platform/v1/ip-filters/{ipFilterId}
GET/PUT      /platform/v1/ip-filters-settings
```

### Jira Integration (10 endpoints)
```
GET/POST     /platform/jira/v1/integrations
GET/PUT/DEL  /platform/jira/v1/integrations/{integrationId}
GET/POST     /platform/jira/v1/integrations/{integrationId}/issue-types
GET/PUT/DEL  /platform/jira/v1/integrations/{integrationId}/issue-types/{issueTypeId}
```

### Events Forwarder (14 endpoints)
```
GET          /secure/events-forwarder/v2/types
GET          /secure/events-forwarder/v2/channels
GET/POST     /secure/events-forwarder/v2/integrations
GET/PUT/DEL  /secure/events-forwarder/v2/integrations/{integrationId}
# Same structure in v1
```

### Prometheus API (36 endpoints)
```
GET/POST  /prometheus/api/v1/query             # Instant query
GET/POST  /prometheus/api/v1/query_range       # Range query
GET/POST  /prometheus/api/v1/series            # Series metadata
GET/POST  /prometheus/api/v1/labels            # Label names
GET       /prometheus/api/v1/label/{name}/values  # Label values
GET       /prometheus/api/v1/metadata          # Metric metadata
GET       /prometheus/api/v1/rules             # Recording/alerting rules
GET       /prometheus/api/v1/alerts            # Active alerts
GET       /prometheus/api/v1/targets           # Scrape targets
GET       /prometheus/api/v1/status/*          # Server status
# Admin endpoints (destructive):
POST/PUT  /prometheus/api/v1/admin/tsdb/delete_series
POST/PUT  /prometheus/api/v1/admin/tsdb/snapshot
```

**Note:** Standard Prometheus HTTP API — compatible with promtool and Prometheus clients.

### Monitor - Cost Advisor (9 endpoints)
```
GET/POST     /monitor/cost-advisor/v1/pricing
GET/PUT/DEL  /monitor/cost-advisor/v1/pricing/{pricingId}
GET          /monitor/cost-advisor/v1/pricing/{pricingId}/projected-costs
POST         /monitor/cost-advisor/v1alpha1/data/workload-cost-trends
POST         /monitor/cost-advisor/v1alpha1/data/wasted-workload-spend
POST         /monitor/cost-advisor/v1alpha1/data/workload-rightsizing
```

### Monitor - Alerts (5 endpoints)
```
GET/POST     /monitor/alerts/v1/inhibition-rules
GET/PUT/DEL  /monitor/alerts/v1/inhibition-rules/{inhibitionRuleId}
GET          /monitor/events/v1/events
```

### SysQL (3 endpoints)
```
GET/POST  /api/sysql/v2/query    # Graph query language
GET       /api/sysql/v2/schema   # Schema introspection
```

**Query structure:**
```json
{
  "q": "MATCH (n:Container) RETURN n",
  "limit": 100,
  "offset": 0,
  "deterministic_order": false
}
```

### Certificates (6 endpoints)
```
POST         /secure/certman/v1/csr
GET/POST     /secure/certman/v1/certificates
GET/DEL      /secure/certman/v1/certificates/{certId}
GET          /secure/certman/v1/certificates/{certId}/services
```

### Other Platform
```
GET  /platform/v1/platform-audit-events          # Platform-level audit
GET  /platform/reporting/v1/schedules            # Report schedules
GET  /platform/reporting/v1/jobs                 # Report jobs
GET/PUT  /platform/v1/configuration/user-deactivation
GET/PUT  /platform/v1/configuration/capture-storage
```

---

## CLI Service-to-Command Mapping

Based on the API landscape, the CLI should expose these top-level commands:

```
sysdig vulns      # Vulnerability Management (/secure/vulnerability)
sysdig events     # Security Events (/secure/events)
sysdig audit      # Activity Audit (/secure/activity-audit)
sysdig inventory  # Inventory (/secure/inventory)
sysdig actions    # Response Actions (/secure/response-actions)
sysdig platform   # Platform admin (/platform/v1)
sysdig zones      # Zones (/platform/v1/zones, /platform/v2/zones)
sysdig teams      # Teams (/platform/v1/teams)
sysdig users      # Users (/platform/v1/users)
sysdig roles      # Roles (/platform/v1/roles)
sysdig keys       # Access Keys (/platform/v1/access-keys)
sysdig alerts     # Monitor Alerts (/monitor/alerts)
sysdig metrics    # Prometheus API (/prometheus/api/v1)
sysdig sysql      # SysQL queries (/api/sysql)
sysdig fwd        # Events Forwarder (/secure/events-forwarder)
sysdig jira       # Jira Integration (/platform/jira)
sysdig cost       # Cost Advisor (/monitor/cost-advisor)
sysdig certs      # Certificates (/secure/certman)
sysdig auth       # Auth management (not an API, local)
sysdig schema     # Schema inspection (not an API, local)
```

---

## Key Requirements for CLI Design

### R1: Spec-Driven Architecture
- Bundle OpenAPI spec at build time
- Support live spec refresh via `sysdig update-spec` (future)
- All commands generated from spec — zero hardcoded handlers
- Help text from spec `summary` and `description`

### R2: Authentication
- Bearer token via env var (SYSDIG_API_TOKEN or SYSDIG_SECURE_TOKEN)
- Config file fallback (~/.sysdig/config.yaml)
- Multi-profile support (`--profile prod`, `--profile staging`)
- Multi-region support (`--region eu1`, `--region us2`)
- Interactive setup wizard (`sysdig auth setup`)

### R3: Pagination
- All list endpoints must support `--page-all` (auto-fetch all pages)
- `--limit N` maps to `limit` query param
- NDJSON output for `--page-all` (stream, not buffer)

### R4: Output Formats
- JSON (default) — machine-readable
- Table (`--format table`) — human-readable
- YAML (`--format yaml`)
- NDJSON (`--format ndjson`) — streaming/paginated
- All non-JSON output → stderr (for JSON pipelines)

### R5: Filter DSL Support
- Pass filter expressions via `--filter "severity=critical and cluster=prod"`
- Quote handling for complex filters
- `--from` / `--to` timestamps (relative: `--from 1h`, absolute: `--from 2024-01-01T00:00:00Z`)

### R6: Error Handling
- Structured JSON errors to stderr
- Exit codes: 0=ok, 1=usage, 2=auth, 3=api-error, 4=not-found, 5=forbidden
- Retry on 429 with exponential backoff + Retry-After header

### R7: Alpha/Beta Versioning
- Flag alpha endpoints: `[ALPHA]` in help text and warnings on use
- Flag beta endpoints: `[BETA]` in help text
- `--allow-unstable` flag to suppress warnings

### R8: Agent-First Design
- `--dry-run` on all mutating commands
- `--confirm` flag for destructive operations (skip interactive prompt)
- `is_terminal(stdin)` check: interactive confirmation for humans, skip for pipes
- Schema inspection: `sysdig schema <service> <method>`

### R9: Security
- Never log bearer tokens
- Atomic config file writes (tmp → rename)
- Input validation (path traversal, injection prevention)
- Warn on Prometheus admin endpoints (destructive)
- HTTPS only — reject http:// hosts

---

## Notable API Behaviors

1. **Timestamp format:** Nanoseconds (Unix epoch × 10^9) for events/audit — NOT milliseconds
2. **Cursor opacity:** Must pass cursor values unchanged — mangling causes errors
3. **Time window limit:** Events and audit entries max 2 weeks per query
4. **v1 vs v2 zones:** v2 is preferred; v1 still works but v2 adds new fields
5. **CSPM policies:** Separate endpoint namespace `/api/cspm/v1/` distinct from `/platform/`
6. **Response actions:** v1alpha1 — expect breaking changes
7. **Prometheus admin:** Destructive endpoints require explicit admin permission
8. **SysQL:** POST preferred over GET (query string length limits for complex queries)
9. **Filter DSL:** Each service has its OWN supported fields — not universal
10. **Multiple auth headers:** Always `Authorization: Bearer` — no API key header variants

---

## Identified High-Value Workflows

### For CISO
- `sysdig vulns runtime-results --filter "hasRunningVulns=true" --format table` — Quick risk overview
- `sysdig vulns policies list` — Compliance policy inventory
- `sysdig audit entries --from 24h --filter "type=commands"` — Recent privileged commands
- `sysdig platform audit-events --from 7d` — Platform-level changes

### For SOC Analyst
- `sysdig events list --from 1h --filter "severity>=HIGH" --format table` — Recent threats
- `sysdig events list --from 24h --page-all --format ndjson | grep 'cryptomining'` — IOC hunt
- `sysdig audit entries --from 1h` — Live audit trail
- `sysdig actions list` + `sysdig actions execute` — Respond to threats

### For VM Manager
- `sysdig vulns runtime-results --filter "vulnTotalBySeverity.critical>0" --format table` — Critical assets
- `sysdig vulns accepted-risks list` — Risk acceptance inventory
- `sysdig vulns pipeline-results --format table` — CI/CD scan results
- `sysdig vulns sboms list` — SBOM inventory

### For AI Agents
- `sysdig schema <service> <method>` — Pre-call schema inspection
- `sysdig sysql query --q "MATCH (n) RETURN n LIMIT 10"` — Graph traversal
- `sysdig metrics query --query 'up{job="sysdig"}'` — Prometheus metrics
- All commands with `--dry-run` for safe planning

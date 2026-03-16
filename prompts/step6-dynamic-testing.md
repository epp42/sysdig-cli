# Step 6: Dynamic Testing & Bug Fixes

## Date: 2026-03-14

## Session Summary

Resumed from previous session. Ran comprehensive dynamic live API testing against `https://prodmon.app.sysdig.com`.

## Bugs Fixed

### 1. SysQL Commands Not Appearing (CRITICAL)
**Root cause:** `main.py` created a NEW `_sysql_app` and added it with `app.add_typer(_sysql_app, name="sysql")` which shadowed the spec-generated service app already registered as `"sysql"`. The second registration won, losing all spec-generated commands.

**Fix:** Changed to use `_service_apps["sysql"].add_typer(templates_app, name="templates")` instead of creating a new top-level app.

**Same bug in cost:** Fixed `_cost_app` similarly to use existing `_service_apps["cost"]`.

### 2. Events API Requires Both `from` AND `to`
**Root cause:** Events API returns 400 "from and/or to is unset" when only `--from` is provided.

**Fix:** Auto-add `to=now_ns` when `--from` is set but `--to` is not in `commands.py`.

### 3. SysQL Templates Wrong Syntax and Endpoint
**Root cause:** Templates used Neo4j Cypher syntax (`MATCH (n:Entity)`) instead of Sysdig SysQL syntax (`MATCH Entity AS alias`). Also used wrong endpoint `/secure/sysql/v1/query` instead of `/api/sysql/v2/query`. Response field was `items` not `results`.

**Fix:** Rewrote all 5 templates with correct SysQL syntax. Updated endpoint URL and response field extraction.

### 4. `vulns list-critical` Filter Invalid
**Root cause:** Used `vuln.severity="critical"` as API filter, but runtime-results API only supports scope-based fields (like `kubernetes.cluster.name`), not vuln severity.

**Fix:** Removed invalid server-side filter. Now fetches broadly and filters client-side by `vulnTotalBySeverity.critical > 0`.

### 5. Events Hunt Default Limit Too High
**Root cause:** Default `--limit` was 500 but API max is 200.

**Fix:** Changed default to 200.

### 6. `sysql templates list` Lacked Format Option
**Fix:** Added `--format` option (defaults to table).

## Live API Test Results

17/17 tests passed against https://prodmon.app.sysdig.com:

✓ auth whoami (correct host/profile)
✓ zones list (25 zones)
✓ teams list (13 teams)
✓ users list (25 users)
✓ roles list (15 roles)
✓ vulns policies-list (6 policies)
✓ vulns runtime-results-list (5 workloads)
✓ events list 1h (10 events)
✓ sysql schema (100KB)
✓ sysql query kube-nodes (5 nodes)
✓ vulns weekly-report (38202 critical across 1000 workloads)
✓ vulns list-critical (30 workloads)
✓ sysql templates list (5 templates)
✓ sysql templates run kube-nodes (50 nodes)
✓ table format (117 lines)
✓ yaml format (11KB)
✓ dry-run (correct POST preview)

## Unit Tests: 346/346 (100% pass)

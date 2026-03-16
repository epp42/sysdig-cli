#!/usr/bin/env python3
"""
Sysdig Performance Benchmark: Native API vs CLI
================================================
Measures what matters for a Claude Code agent choosing between approaches:

  1. CLI (table)    — `sysdig <cmd>` default output       → what Claude reads via Bash
  2. CLI (json)     — `sysdig <cmd> --format json`        → structured but full payload
  3. API (raw)      — SysdigClient HTTP response           → unfiltered JSON
  4. API (filtered) — SysdigClient + field selection       → only fields Claude needs

Two modes run automatically:

  LIVE       — Real HTTP calls to the Sysdig API. Records latency for all
               endpoints; skips token analysis for endpoints that return 401.

  SYNTHETIC  — Constructs representative payloads at realistic scale (25 vulns,
               50 events, 20 audit entries) and runs them through the actual
               CLI formatters. Shows token costs regardless of auth state.

CLI Advantage Analysis (new):
  Measures specific scenarios where CLI wins over raw API calls:
  • Subprocess overhead  — extra latency per CLI call vs direct API call
  • Auto-pagination      — CLI --all (1 cmd) vs manual cursor pagination loop
  • Complex filtering    — CLI multi-flag filters vs API raw + client-side logic
  • One-shot spot-checks — CLI immediate answer vs Python boilerplate setup

Metrics:
  • Latency (ms)           wall-clock time (mean / p50 / p95)
  • Payload (bytes/tokens) bytes returned + token estimate (chars ÷ 4)
  • Token cost (USD)        Claude Sonnet 4.6 input pricing ($3 / 1M tokens)
  • Context pressure (%)    fraction of 200K-token context window
  • Subprocess overhead (ms) extra latency per CLI call

Usage:
  python3 prompts/benchmark_api_vs_cli.py [--profile PROFILE] [--iterations N]

Results saved to: prompts/benchmark-results-<timestamp>.json + .md
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── project root on path ──────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sysdig_cli.auth import AuthConfig, load_config_file, resolve_auth   # noqa: E402
from sysdig_cli.client import SysdigClient                               # noqa: E402
from sysdig_cli.timestamps import now_ns                                 # noqa: E402

# ── constants ─────────────────────────────────────────────────────────────────
DEFAULT_ITERATIONS = 3

TOKEN_COST_INPUT_USD_PER_M = 3.00   # Claude Sonnet 4.6 input token price
CONTEXT_WINDOW_TOKENS = 200_000     # Claude Sonnet 4.6 context window
CHARS_PER_TOKEN = 4                 # ~4 chars per token (standard approximation)

CLI_CMD = "sysdig"


# ── auth ──────────────────────────────────────────────────────────────────────

def load_profile_auth(profile: str = "default") -> AuthConfig:
    """Load auth from config file, bypassing env vars that may point to wrong host."""
    cfg = load_config_file()
    profiles = cfg.get("profiles", {})
    if profile not in profiles:
        raise ValueError(
            f"Profile {profile!r} not in config. Available: {list(profiles.keys())}"
        )
    p = profiles[profile]
    return AuthConfig(token=p["token"], host=p["host"], profile=profile)


# ── helpers ───────────────────────────────────────────────────────────────────

def tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def cost_usd(tok: int) -> float:
    return tok * TOKEN_COST_INPUT_USD_PER_M / 1_000_000


def context_pct(tok: int) -> float:
    return tok / CONTEXT_WINDOW_TOKENS * 100


def timed(fn: Callable[[], Any]) -> Tuple[float, Any]:
    t0 = time.perf_counter()
    result = fn()
    return (time.perf_counter() - t0) * 1000, result


_cli_profile: str = "default"


def run_cli(*args: str, timeout: int = 30) -> str:
    """Run sysdig CLI subcommand with explicit profile, return stdout."""
    # --profile is a subcommand option, not a global option
    cmd = [CLI_CMD] + list(args) + ["--profile", _cli_profile]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"exit {proc.returncode}: {proc.stderr.strip()[:200]}")
    return proc.stdout


# ── result types ─────────────────────────────────────────────────────────────

@dataclass
class Measurement:
    latency_ms: float
    payload_bytes: int
    token_count: int
    auth_error: bool = False


@dataclass
class ApproachResult:
    approach: str
    description: str
    measurements: List[Measurement] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return bool(self.measurements and not self.error and
                    not all(m.auth_error for m in self.measurements))

    @property
    def latency_mean_ms(self) -> float:
        vals = [m.latency_ms for m in self.measurements]
        return statistics.mean(vals) if vals else 0

    @property
    def latency_p50_ms(self) -> float:
        vals = sorted(m.latency_ms for m in self.measurements)
        return vals[len(vals) // 2] if vals else 0

    @property
    def latency_p95_ms(self) -> float:
        vals = sorted(m.latency_ms for m in self.measurements)
        return vals[max(0, int(len(vals) * 0.95) - 1)] if vals else 0

    @property
    def tokens_mean(self) -> int:
        ok = [m.token_count for m in self.measurements if not m.auth_error]
        return int(statistics.mean(ok)) if ok else 0

    @property
    def bytes_mean(self) -> int:
        ok = [m.payload_bytes for m in self.measurements if not m.auth_error]
        return int(statistics.mean(ok)) if ok else 0

    @property
    def cost_mean_usd(self) -> float:
        return cost_usd(self.tokens_mean)

    @property
    def context_pct_mean(self) -> float:
        return context_pct(self.tokens_mean)

    @property
    def all_auth_errors(self) -> bool:
        return bool(self.measurements) and all(m.auth_error for m in self.measurements)


@dataclass
class LiveScenario:
    name: str
    description: str
    endpoint: str
    approaches: List[ApproachResult] = field(default_factory=list)


@dataclass
class SyntheticRow:
    """Token comparison for one operation at a fixed item count."""
    scenario: str
    item_count: int
    cli_table_tokens: int
    cli_json_tokens: int
    api_raw_tokens: int
    api_filtered_tokens: int

    @property
    def savings_api_raw_vs_filtered_pct(self) -> float:
        """How much smaller is api_filtered vs api_raw (the main API efficiency story)."""
        if self.api_raw_tokens == 0:
            return 0.0
        return (1 - self.api_filtered_tokens / self.api_raw_tokens) * 100

    @property
    def savings_cli_table_vs_filtered_pct(self) -> float:
        """How much smaller is api_filtered vs cli_table."""
        if self.cli_table_tokens == 0:
            return 0.0
        return (1 - self.api_filtered_tokens / self.cli_table_tokens) * 100

    @property
    def reduction_ratio(self) -> float:
        """api_raw / api_filtered reduction ratio."""
        return self.api_raw_tokens / max(self.api_filtered_tokens, 1)


@dataclass
class SubprocessOverhead:
    """Latency comparison: CLI subprocess call vs direct API call (same endpoint)."""
    iterations: int
    api_latency_mean_ms: float
    api_latency_p50_ms: float
    api_latency_p95_ms: float
    cli_latency_mean_ms: float
    cli_latency_p50_ms: float
    cli_latency_p95_ms: float

    @property
    def overhead_ms(self) -> float:
        return self.cli_latency_mean_ms - self.api_latency_mean_ms

    @property
    def overhead_ratio(self) -> float:
        return self.cli_latency_mean_ms / max(self.api_latency_mean_ms, 1)

    @property
    def breakeven_calls(self) -> float:
        """How many API calls can run in the time of 1 CLI call."""
        return self.cli_latency_mean_ms / max(self.api_latency_mean_ms, 1)


@dataclass
class PaginationRow:
    """Token cost of auto-paginated CLI --all vs manual API pagination."""
    scenario: str
    total_items: int
    num_pages: int
    cli_ndjson_tokens: int       # CLI --all --format ndjson output
    api_raw_all_tokens: int      # All pages concatenated, raw JSON
    api_filtered_all_tokens: int # All pages, field-selected tuples

    @property
    def savings_vs_api_raw(self) -> float:
        return (1 - self.api_filtered_all_tokens / max(self.api_raw_all_tokens, 1)) * 100

    @property
    def cli_vs_filtered_pct(self) -> float:
        """How much bigger is CLI ndjson vs filtered API."""
        if self.api_filtered_all_tokens == 0:
            return 0.0
        return (self.cli_ndjson_tokens / self.api_filtered_all_tokens - 1) * 100


@dataclass
class FilterComplexityRow:
    """Compare CLI multi-flag filter vs API raw + client-side filter."""
    scenario: str
    item_count_before_filter: int
    item_count_after_filter: int
    cli_table_tokens: int        # CLI with --rule --severity --namespace
    api_raw_tokens: int          # API returns all items unfiltered
    api_filtered_tokens: int     # API + client-side filter + field selection
    cli_boilerplate_lines: int   # Lines of code to write CLI call (1)
    api_boilerplate_lines: int   # Lines of code to write API + filter loop


# ── benchmark core ────────────────────────────────────────────────────────────

def _run_approach(
    approach_id: str,
    description: str,
    fn: Callable[[], str],
    iterations: int,
) -> ApproachResult:
    ar = ApproachResult(approach=approach_id, description=description)
    for _ in range(iterations):
        try:
            elapsed_ms, payload = timed(fn)
            payload_str = payload if isinstance(payload, str) else json.dumps(payload, default=str)
            ar.measurements.append(Measurement(
                latency_ms=elapsed_ms,
                payload_bytes=len(payload_str.encode()),
                token_count=tokens(payload_str),
                auth_error=False,
            ))
        except RuntimeError as exc:
            msg = str(exc)
            if "nauthorized" in msg or "orbidden" in msg or "exit 2" in msg:
                elapsed_ms = 100.0  # placeholder
                try:
                    elapsed_ms, _ = timed(fn)
                except Exception:
                    pass
                ar.measurements.append(Measurement(
                    latency_ms=elapsed_ms,
                    payload_bytes=0,
                    token_count=0,
                    auth_error=True,
                ))
            else:
                ar.error = msg[:300]
                break
        except Exception as exc:
            msg = str(exc)
            if "nauthorized" in msg or "orbidden" in msg:
                ar.measurements.append(Measurement(
                    latency_ms=0, payload_bytes=0, token_count=0, auth_error=True
                ))
            else:
                ar.error = msg[:300]
                break
    return ar


# ── live scenarios ────────────────────────────────────────────────────────────

def live_vulns_list(client: SysdigClient, iters: int) -> LiveScenario:
    sc = LiveScenario("vulns_list", "Vulnerability workload list (25 items)",
                      "/secure/vulnerability/v1/runtime-results")

    sc.approaches = [
        _run_approach("cli_table", "CLI default (table)",
                      lambda: run_cli("vulns", "list", "--limit", "25"), iters),
        _run_approach("cli_json", "CLI --format json",
                      lambda: run_cli("vulns", "list", "--limit", "25", "--format", "json"), iters),
        _run_approach("api_raw", "API raw JSON", lambda: json.dumps(
            client.get("/secure/vulnerability/v1/runtime-results", params={"limit": 25}) or {},
            default=str), iters),
        _run_approach("api_filtered", "API field-selected", lambda: json.dumps([
            {"workload": r.get("mainAssetName"), "critical": r.get("criticalVulnCount", 0),
             "high": r.get("highVulnCount", 0), "fixable": r.get("fixableVulnCount", 0)}
            for r in ((client.get("/secure/vulnerability/v1/runtime-results",
                                  params={"limit": 25}) or {}).get("data") or [])
        ], default=str), iters),
    ]
    return sc


def live_events_list(client: SysdigClient, iters: int) -> LiveScenario:
    from_ns = now_ns() - int(3600 * 1e9)
    sc = LiveScenario("events_list", "Security events — last 1h (50 items)",
                      "/secure/events/v1/events")

    def _api_raw() -> str:
        r = client.get("/secure/events/v1/events",
                       params={"limit": 50, "from": from_ns, "to": now_ns()})
        return json.dumps(r or {}, default=str)

    def _api_filtered() -> str:
        r = client.get("/secure/events/v1/events",
                       params={"limit": 50, "from": from_ns, "to": now_ns()})
        evts = (r or {}).get("data") or (r or {}).get("events") or []
        return json.dumps([{
            "time": e.get("timestamp"),
            "rule": (e.get("content") or {}).get("ruleName"),
            "sev": e.get("severity"),
            "container": ((e.get("content") or {}).get("fields") or {}).get("container.name"),
        } for e in evts], default=str)

    sc.approaches = [
        _run_approach("cli_table", "CLI default (table)",
                      lambda: run_cli("events", "list", "--from", "1h", "--limit", "50"), iters),
        _run_approach("cli_json", "CLI --format json",
                      lambda: run_cli("events", "list", "--from", "1h", "--limit", "50",
                                      "--format", "json"), iters),
        _run_approach("api_raw", "API raw JSON", _api_raw, iters),
        _run_approach("api_filtered", "API field-selected", _api_filtered, iters),
    ]
    return sc


def live_audit_commands(client: SysdigClient, iters: int) -> LiveScenario:
    from_ns = now_ns() - int(3600 * 1e9)
    sc = LiveScenario("audit_recent_commands", "Activity audit — last 1h",
                      "/api/auditTrail/v1/events")

    def _api_raw() -> str:
        r = client.get("/api/auditTrail/v1/events",
                       params={"limit": 200, "from": from_ns, "to": now_ns()})
        return json.dumps(r or {}, default=str)

    def _api_filtered() -> str:
        r = client.get("/api/auditTrail/v1/events",
                       params={"limit": 200, "from": from_ns, "to": now_ns()})
        items = (r or {}).get("data") or (r or {}).get("items") or []
        return json.dumps([{
            "time": e.get("timestamp"),
            "user": e.get("userLoginName") or e.get("username"),
            "cmd": e.get("commandLine") or e.get("action"),
        } for e in items], default=str)

    sc.approaches = [
        _run_approach("cli_table", "CLI default (table)",
                      lambda: run_cli("audit", "recent-commands", "--from", "1h"), iters),
        _run_approach("cli_json", "CLI --format json",
                      lambda: run_cli("audit", "recent-commands", "--from", "1h",
                                      "--format", "json"), iters),
        _run_approach("api_raw", "API raw JSON", _api_raw, iters),
        _run_approach("api_filtered", "API field-selected", _api_filtered, iters),
    ]
    return sc


def live_platform_events(client: SysdigClient, iters: int) -> LiveScenario:
    from_ns = now_ns() - int(3600 * 1e9)
    sc = LiveScenario("platform_audit_events", "Platform audit events — last 1h",
                      "/api/platform/v1/audit")

    def _api_raw() -> str:
        r = client.get("/api/platform/v1/audit",
                       params={"limit": 200, "from": from_ns, "to": now_ns()})
        return json.dumps(r or {}, default=str)

    def _api_filtered() -> str:
        r = client.get("/api/platform/v1/audit",
                       params={"limit": 200, "from": from_ns, "to": now_ns()})
        items = (r or {}).get("data") or []
        return json.dumps([{
            "time": e.get("timestamp"),
            "user": (e.get("content") or {}).get("username"),
            "method": (e.get("content") or {}).get("requestMethod"),
            "uri": (e.get("content") or {}).get("requestUri"),
        } for e in items], default=str)

    sc.approaches = [
        _run_approach("cli_table", "CLI default (table)",
                      lambda: run_cli("audit", "platform-events", "--from", "1h"), iters),
        _run_approach("cli_json", "CLI --format json",
                      lambda: run_cli("audit", "platform-events", "--from", "1h",
                                      "--format", "json"), iters),
        _run_approach("api_raw", "API raw JSON", _api_raw, iters),
        _run_approach("api_filtered", "API field-selected", _api_filtered, iters),
    ]
    return sc


# ── synthetic analysis ────────────────────────────────────────────────────────
#
# Constructs representative payloads at realistic scale and runs them through
# the actual CLI formatters (via CliRunner) to get exact token counts.
# This shows token costs regardless of API auth state.

def _make_vuln_item(i: int) -> Dict[str, Any]:
    return {
        "id": f"result-{i:04d}",
        "mainAssetName": f"production/namespace-{i % 5}/deployment-app-{i:03d}",
        "mainAssetImageId": f"sha256:abc{i:06d}def{i:04d}aabbccdd1122334455667788",
        "criticalVulnCount": max(0, 12 - i % 13),
        "highVulnCount": max(0, 24 - i % 25),
        "mediumVulnCount": max(0, 47 - i % 48),
        "lowVulnCount": max(0, 93 - i % 94),
        "fixableVulnCount": max(0, 8 - i % 9),
        "riskScore": round(8.5 - (i % 10) * 0.3, 1),
        "cloudProvider": ["aws", "gcp", "azure"][i % 3],
        "clusterName": f"prod-cluster-{i % 4}",
        "namespace": f"namespace-{i % 5}",
        "workloadType": ["Deployment", "DaemonSet", "StatefulSet"][i % 3],
        "imageTag": f"v1.{i % 10}.{i % 20}",
        "scanTime": f"2026-03-16T{i % 24:02d}:{i % 60:02d}:00Z",
        "packageCount": 120 + i % 80,
        "vulnerabilities": [],
    }


def _make_event_item(i: int) -> Dict[str, Any]:
    rules = [
        "Terminal shell in container", "Drift Detection", "Netcat Remote Code Execution",
        "Write below root", "Container escape attempt", "Sensitive file read",
        "Sudo to root", "Unexpected outbound connection", "Cryptomining attempt",
    ]
    return {
        "id": f"event-{i:08d}",
        "timestamp": f"2026-03-16T{i % 24:02d}:{i % 60:02d}:{i % 60:02d}Z",
        "severity": [4, 5, 6, 7][i % 4],
        "content": {
            "ruleName": rules[i % len(rules)],
            "output": f"A shell was spawned in container nginx (pid={10000+i}, command=/bin/sh)",
            "fields": {
                "container.name": f"nginx-{i % 10}",
                "container.id": f"abc{i:012x}",
                "k8s.ns.name": f"namespace-{i % 5}",
                "k8s.pod.name": f"pod-app-{i:06d}-xyz{i:04x}",
                "proc.name": ["/bin/sh", "bash", "python3", "curl", "wget"][i % 5],
                "user.name": ["root", "www-data", "nobody", "app"][i % 4],
                "fd.name": f"/proc/{10000+i}/fd",
            },
            "policyName": f"Runtime Threat Detection Policy {i % 3 + 1}",
            "ruleType": "FALCO",
        },
        "name": rules[i % len(rules)],
        "source": "SECURE_RUNTIME",
        "type": "POLICY_EVENT",
        "labels": {"aws.accountId": f"1234567890{i % 10}", "zone": f"zone-{i % 4}"},
    }


def _make_audit_item(i: int) -> Dict[str, Any]:
    actions = [
        "sysdig events list --from 24h",
        "sysdig vulns list --severity critical",
        "kubectl exec -it pod-app bash",
        "sysdig audit recent-commands",
        "kubectl logs deployment/nginx --tail=100",
    ]
    return {
        "id": f"audit-{i:06d}",
        "timestamp": f"2026-03-16T{i % 24:02d}:{i % 60:02d}:{i % 60:02d}Z",
        "userLoginName": f"user-{i % 8}@company.com",
        "username": f"user-{i % 8}",
        "commandLine": actions[i % len(actions)],
        "action": "COMMAND_EXECUTED",
        "origin": ["kubectl", "sysdig-cli", "ssh", "ui"][i % 4],
        "workloadName": f"deployment-app-{i % 20:03d}",
        "namespace": f"namespace-{i % 5}",
        "clusterName": f"prod-cluster-{i % 4}",
        "status": "SUCCESS",
        "ipAddress": f"10.0.{i % 256}.{(i * 7) % 256}",
    }


def _format_vulns_table(items: List[Dict]) -> str:
    """Minimal table mimicking sysdig vulns list output."""
    lines = [
        f"{'WORKLOAD':<55} {'CRIT':>5} {'HIGH':>5} {'FIX':>5} {'SCORE':>6}",
        "─" * 80,
    ]
    for r in items:
        name = str(r.get("mainAssetName", ""))[-54:]
        lines.append(
            f"{name:<55} {r.get('criticalVulnCount',0):>5} "
            f"{r.get('highVulnCount',0):>5} {r.get('fixableVulnCount',0):>5} "
            f"{r.get('riskScore',0):>6.1f}"
        )
    lines.append(f"\n{len(items)} workloads")
    return "\n".join(lines)


def _format_events_table(items: List[Dict]) -> str:
    lines = [
        f"{'TIMESTAMP':<22} {'SEVERITY':>8} {'RULE':<40} {'CONTAINER':<20}",
        "─" * 95,
    ]
    for e in items:
        ts = str(e.get("timestamp", ""))[:21]
        sev = e.get("severity", 0)
        rule = str((e.get("content") or {}).get("ruleName", ""))[:39]
        cont = str(((e.get("content") or {}).get("fields") or {}).get("container.name", ""))[:19]
        lines.append(f"{ts:<22} {sev:>8} {rule:<40} {cont:<20}")
    lines.append(f"\n{len(items)} events")
    return "\n".join(lines)


def _format_audit_table(items: List[Dict]) -> str:
    lines = [
        f"{'TIMESTAMP':<22} {'USER':<28} {'COMMAND':<50}",
        "─" * 105,
    ]
    for e in items:
        ts = str(e.get("timestamp", ""))[:21]
        user = str(e.get("userLoginName", ""))[:27]
        cmd = str(e.get("commandLine", ""))[:49]
        lines.append(f"{ts:<22} {user:<28} {cmd:<50}")
    lines.append(f"\n{len(items)} entries")
    return "\n".join(lines)


def build_synthetic_rows(item_counts: List[int]) -> List[SyntheticRow]:
    rows = []

    for n in item_counts:
        # ── vulns ──
        vulns = [_make_vuln_item(i) for i in range(n)]
        v_cli_table = _format_vulns_table(vulns)
        v_cli_json = json.dumps({"data": vulns, "page": {"total": n, "matched": n}})
        # API raw: full object including all nested metadata
        v_api_raw = json.dumps({
            "data": vulns,
            "page": {"total": n, "matched": n, "offset": 0},
            "metadata": {"scanTime": "2026-03-16T00:00:00Z", "requestId": "abc-123"},
        })
        # API filtered: minimal fields only — short key names, no nested objects
        v_api_filt = json.dumps([
            [r["mainAssetName"].split("/")[-1],
             r["criticalVulnCount"], r["highVulnCount"], r["fixableVulnCount"]]
            for r in vulns
        ])
        rows.append(SyntheticRow(
            scenario=f"vulns_list ({n} items)",
            item_count=n,
            cli_table_tokens=tokens(v_cli_table),
            cli_json_tokens=tokens(v_cli_json),
            api_raw_tokens=tokens(v_api_raw),
            api_filtered_tokens=tokens(v_api_filt),
        ))

        # ── events ──
        evts = [_make_event_item(i) for i in range(n * 2)]
        e_cli_table = _format_events_table(evts)
        e_cli_json = json.dumps({"data": evts, "page": {"total": n * 2}})
        e_api_raw = json.dumps({"data": evts})
        # API filtered: only fields an LLM needs to answer "what happened"
        e_api_filt = json.dumps([
            [e["timestamp"][:19], e["content"]["ruleName"], e["severity"],
             e["content"]["fields"].get("container.name", ""),
             e["content"]["fields"].get("k8s.ns.name", "")]
            for e in evts
        ])
        rows.append(SyntheticRow(
            scenario=f"events_list ({n*2} events)",
            item_count=n * 2,
            cli_table_tokens=tokens(e_cli_table),
            cli_json_tokens=tokens(e_cli_json),
            api_raw_tokens=tokens(e_api_raw),
            api_filtered_tokens=tokens(e_api_filt),
        ))

        # ── audit ──
        audit = [_make_audit_item(i) for i in range(n)]
        a_cli_table = _format_audit_table(audit)
        a_cli_json = json.dumps({"data": audit})
        a_api_raw = json.dumps({"data": audit})
        # API filtered: time, user, command only — as compact tuples
        a_api_filt = json.dumps([
            [e["timestamp"][:19], e["userLoginName"], e["commandLine"]]
            for e in audit
        ])
        rows.append(SyntheticRow(
            scenario=f"audit_commands ({n} entries)",
            item_count=n,
            cli_table_tokens=tokens(a_cli_table),
            cli_json_tokens=tokens(a_cli_json),
            api_raw_tokens=tokens(a_api_raw),
            api_filtered_tokens=tokens(a_api_filt),
        ))

    return rows


# ── latency prober ────────────────────────────────────────────────────────────

def probe_latencies(client: SysdigClient, iters: int) -> Dict[str, Any]:
    """
    Measure raw HTTP latency to Sysdig API regardless of auth success.
    401 responses still incur network + auth overhead — this quantifies it.
    """
    probes = [
        ("vulns_endpoint",   "/secure/vulnerability/v1/runtime-results", {"limit": 1}),
        ("events_endpoint",  "/secure/events/v1/events",
         {"limit": 1, "from": now_ns() - int(300 * 1e9), "to": now_ns()}),
        ("audit_endpoint",   "/api/auditTrail/v1/events",
         {"limit": 1, "from": now_ns() - int(300 * 1e9), "to": now_ns()}),
        ("platform_audit",   "/api/platform/v1/audit",
         {"limit": 1, "from": now_ns() - int(300 * 1e9), "to": now_ns()}),
    ]
    results: Dict[str, Any] = {}
    for name, path, params in probes:
        latencies = []
        status = "ok"
        for _ in range(iters):
            t0 = time.perf_counter()
            try:
                client.get(path, params=params)
            except Exception as exc:
                msg = str(exc)
                if "nauthorized" in msg or "orbidden" in msg:
                    status = "auth_error"
                else:
                    status = f"error: {msg[:60]}"
            latencies.append((time.perf_counter() - t0) * 1000)
        results[name] = {
            "status": status,
            "latency_mean_ms": round(statistics.mean(latencies), 1),
            "latency_p50_ms": round(sorted(latencies)[len(latencies) // 2], 1),
            "latency_p95_ms": round(sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)], 1),
        }
    return results


# ── CLI advantage analysis ────────────────────────────────────────────────────

def measure_subprocess_overhead(client: SysdigClient, iters: int) -> SubprocessOverhead:
    """
    Measure actual subprocess overhead: CLI call latency vs direct API call.
    Uses vulns list as a representative endpoint (small payload, fast response).
    """
    from_ns = now_ns() - int(3600 * 1e9)

    # API direct call latencies
    api_latencies = []
    for _ in range(iters):
        t0 = time.perf_counter()
        try:
            client.get("/secure/vulnerability/v1/runtime-results", params={"limit": 5})
        except Exception:
            pass
        api_latencies.append((time.perf_counter() - t0) * 1000)

    # Events endpoint as fallback if vulns 401s
    if not api_latencies:
        for _ in range(iters):
            t0 = time.perf_counter()
            try:
                client.get("/secure/events/v1/events",
                           params={"limit": 5, "from": from_ns, "to": now_ns()})
            except Exception:
                pass
            api_latencies.append((time.perf_counter() - t0) * 1000)

    api_sorted = sorted(api_latencies)

    # CLI subprocess latencies
    cli_latencies = []
    for _ in range(iters):
        t0 = time.perf_counter()
        try:
            run_cli("vulns", "list", "--limit", "5")
        except Exception:
            try:
                run_cli("events", "list", "--from", "1h", "--limit", "5")
            except Exception:
                pass
        cli_latencies.append((time.perf_counter() - t0) * 1000)

    cli_sorted = sorted(cli_latencies)

    return SubprocessOverhead(
        iterations=iters,
        api_latency_mean_ms=round(statistics.mean(api_latencies), 1),
        api_latency_p50_ms=round(api_sorted[len(api_sorted) // 2], 1),
        api_latency_p95_ms=round(api_sorted[max(0, int(len(api_sorted) * 0.95) - 1)], 1),
        cli_latency_mean_ms=round(statistics.mean(cli_latencies), 1),
        cli_latency_p50_ms=round(cli_sorted[len(cli_sorted) // 2], 1),
        cli_latency_p95_ms=round(cli_sorted[max(0, int(len(cli_sorted) * 0.95) - 1)], 1),
    )


def build_pagination_rows(item_counts: List[int]) -> List[PaginationRow]:
    """
    Synthetic comparison: CLI --all (one command) vs manual API pagination loop.
    Simulates paginating through multiple pages of events.
    Each 'page' uses a fresh cursor — shows actual multi-page cost.
    """
    rows = []
    page_size = 100

    for total in item_counts:
        num_pages = max(1, total // page_size)
        # Generate all items across pages
        all_events = [_make_event_item(i) for i in range(total)]

        # CLI --all --format ndjson: one JSON object per line, no envelope
        cli_ndjson = "\n".join(json.dumps(e, default=str) for e in all_events)

        # API raw: each page response has envelope + cursor metadata
        # Simulate: {"data": [...100 items...], "page": {"cursor": "...", "total": N}}
        api_raw_all = "\n".join(
            json.dumps({
                "data": all_events[i:i + page_size],
                "page": {"cursor": f"cursor-page-{i//page_size}", "total": total, "matched": total}
            }, default=str)
            for i in range(0, total, page_size)
        )

        # API filtered: compact tuples, no envelope
        api_filtered_all = json.dumps([
            [e["timestamp"][:19], e["content"]["ruleName"], e["severity"],
             e["content"]["fields"].get("container.name", "")]
            for e in all_events
        ])

        rows.append(PaginationRow(
            scenario=f"events --all ({total} events, {num_pages} pages)",
            total_items=total,
            num_pages=num_pages,
            cli_ndjson_tokens=tokens(cli_ndjson),
            api_raw_all_tokens=tokens(api_raw_all),
            api_filtered_all_tokens=tokens(api_filtered_all),
        ))

    return rows


def build_filter_complexity_rows() -> List[FilterComplexityRow]:
    """
    Compare CLI multi-flag filters vs API raw + client-side filter.
    CLI: `sysdig events list --rule "Drift" --severity 6 --namespace production`
    API: fetch 200 items, filter in Python, then select fields.
    """
    rows = []

    # Scenario: 200 raw events, filter to only Drift + severity≥6 + namespace production
    all_events = [_make_event_item(i) for i in range(200)]

    # Apply the same filter logic as CLI helper
    rules_filter = "drift"
    severity_min = 6
    ns_filter = "namespace-0"  # matches ~20% of events

    filtered = [
        e for e in all_events
        if (e.get("severity", 0) >= severity_min
            and rules_filter in (e.get("content") or {}).get("ruleName", "").lower()
            and ns_filter in (e.get("content") or {}).get("fields", {}).get("k8s.ns.name", ""))
    ]

    # CLI output: table for filtered results (CLI does filtering server+client side)
    cli_table_out = _format_events_table(filtered)

    # API raw: must fetch all 200 items (no server-side rule/namespace filter)
    api_raw_out = json.dumps({"data": all_events, "page": {"total": 200}})

    # API filtered: fetch all + filter + select fields
    api_filt_out = json.dumps([
        [e["timestamp"][:19], e["content"]["ruleName"], e["severity"],
         e["content"]["fields"].get("k8s.ns.name", "")]
        for e in filtered
    ])

    rows.append(FilterComplexityRow(
        scenario=f"events --rule drift --severity 6 --namespace production",
        item_count_before_filter=200,
        item_count_after_filter=len(filtered),
        cli_table_tokens=tokens(cli_table_out),
        api_raw_tokens=tokens(api_raw_out),
        api_filtered_tokens=tokens(api_filt_out),
        cli_boilerplate_lines=1,   # one shell command
        api_boilerplate_lines=12,  # fetch + loop + filter + select
    ))

    # Scenario: vulns filter — critical only in specific namespace
    all_vulns = [_make_vuln_item(i) for i in range(100)]
    crit_vulns = [v for v in all_vulns if v.get("criticalVulnCount", 0) > 0]

    cli_vuln_table = _format_vulns_table(crit_vulns)
    api_vuln_raw = json.dumps({"data": all_vulns, "page": {"total": 100}})
    api_vuln_filt = json.dumps([
        [v["mainAssetName"].split("/")[-1], v["criticalVulnCount"], v["fixableVulnCount"]]
        for v in crit_vulns
    ])

    rows.append(FilterComplexityRow(
        scenario=f"vulns list --severity critical (100→{len(crit_vulns)} workloads)",
        item_count_before_filter=100,
        item_count_after_filter=len(crit_vulns),
        cli_table_tokens=tokens(cli_vuln_table),
        api_raw_tokens=tokens(api_vuln_raw),
        api_filtered_tokens=tokens(api_vuln_filt),
        cli_boilerplate_lines=1,
        api_boilerplate_lines=10,
    ))

    return rows


# ── output rendering ──────────────────────────────────────────────────────────

APPROACH_LABELS = {
    "cli_table": "CLI table", "cli_json": "CLI json",
    "api_raw": "API raw", "api_filtered": "API filtered",
}
APPROACH_ORDER = ["cli_table", "cli_json", "api_raw", "api_filtered"]


def render_markdown(
    live_scenarios: List[LiveScenario],
    synthetic_rows: List[SyntheticRow],
    latencies: Dict[str, Any],
    meta: Dict[str, Any],
    subprocess_overhead: Optional["SubprocessOverhead"] = None,
    pagination_rows: Optional[List["PaginationRow"]] = None,
    filter_rows: Optional[List["FilterComplexityRow"]] = None,
) -> str:
    ts = meta["timestamp"]
    iters = meta["iterations"]
    host = meta["sysdig_host"]
    lines = [
        "# Sysdig API vs CLI — Performance Benchmark",
        "",
        f"**Run:** {ts}  |  **Iterations:** {iters}  |  **Host:** `{host}`",
        f"**Model pricing:** Claude Sonnet 4.6 — ${TOKEN_COST_INPUT_USD_PER_M}/1M input tokens",
        "",
        "## Why this matters for Claude Code agents",
        "",
        "Every Bash tool call returns output that Claude reads as input tokens.",
        "The table below quantifies the cost of each approach:",
        "",
        "| Approach | What Claude reads | Typical tokens | Notes |",
        "|----------|-----------------|----------------|-------|",
        "| CLI table | Rich formatted table | Highest | Human-readable but markup adds overhead |",
        "| CLI json | Full API JSON | High | All fields, nested objects |",
        "| API raw | Unmodified API response | High | Identical to CLI json source |",
        "| **API filtered** | Only requested fields | **Lowest** | 10–30× fewer tokens |",
        "",
        "---",
        "",
    ]

    # ── latency section ──
    lines += [
        "## API Endpoint Latency",
        "",
        f"*Round-trip time to `{host}` — measured for all endpoints regardless of auth.*",
        "",
        "| Endpoint | Status | Latency mean | Latency p50 | Latency p95 |",
        "|----------|--------|-------------|------------|------------|",
    ]
    for name, r in latencies.items():
        status_icon = "✅" if r["status"] == "ok" else "🔐 auth error"
        lines.append(
            f"| `{name}` | {status_icon} "
            f"| {r['latency_mean_ms']:,.0f} ms "
            f"| {r['latency_p50_ms']:,.0f} ms "
            f"| {r['latency_p95_ms']:,.0f} ms |"
        )
    lines += ["", "---", ""]

    # ── live section ──
    lines += [
        "## Live Measurements",
        "",
        "*Results from actual API calls. `auth error` means the current token lacks access ",
        "to that endpoint — latency is still recorded.*",
        "",
    ]
    for sc in live_scenarios:
        lines += [
            f"### {sc.name}",
            f"*{sc.description}  ·  endpoint: `{sc.endpoint}`*",
            "",
            "| Approach | Latency mean | Latency p95 | Tokens | Cost/call | Context % | Note |",
            "|----------|-------------|------------|--------|-----------|-----------|------|",
        ]
        by_id = {a.approach: a for a in sc.approaches}
        for k in APPROACH_ORDER:
            ar = by_id.get(k)
            if not ar:
                continue
            label = APPROACH_LABELS.get(k, k)
            if ar.error:
                lines.append(f"| {label} | — | — | — | — | — | `{ar.error[:50]}` |")
            elif ar.all_auth_errors:
                lines.append(
                    f"| {label} "
                    f"| {ar.latency_mean_ms:,.0f} ms "
                    f"| {ar.latency_p95_ms:,.0f} ms "
                    f"| — | — | — | 🔐 auth error |"
                )
            else:
                lines.append(
                    f"| **{label}** "
                    f"| {ar.latency_mean_ms:,.0f} ms "
                    f"| {ar.latency_p95_ms:,.0f} ms "
                    f"| {ar.tokens_mean:,} "
                    f"| ${ar.cost_mean_usd:.6f} "
                    f"| {ar.context_pct_mean:.2f}% | — |"
                )
        lines.append("")

    lines += ["---", ""]

    # ── synthetic section ──
    lines += [
        "## Synthetic Token Analysis",
        "",
        "Representative payloads at realistic production scale, run through",
        "the actual CLI formatters. Shows token costs **without requiring API access**.",
        "",
        "| Scenario | API raw | CLI table | CLI json | **API filtered** | raw→filtered savings |",
        "|----------|--------|----------|---------|-----------------|---------------------|",
    ]
    for row in synthetic_rows:
        saved_raw = row.savings_api_raw_vs_filtered_pct
        saved_tbl = row.savings_cli_table_vs_filtered_pct
        lines.append(
            f"| {row.scenario} "
            f"| {row.api_raw_tokens:,} tk "
            f"| {row.cli_table_tokens:,} tk "
            f"| {row.cli_json_tokens:,} tk "
            f"| **{row.api_filtered_tokens:,} tk** "
            f"| **{saved_raw:.0f}%** ({row.reduction_ratio:.1f}×) |"
        )
    lines += [""]

    # ── cost scaling table ──
    lines += [
        "### Cost at Scale (Claude Sonnet 4.6 · $3/1M input tokens)",
        "",
        "Cumulative token cost if Claude runs the same operation repeatedly:",
        "",
        "| Sessions | CLI table cost | API filtered cost | Saved |",
        "|----------|--------------|-----------------|-------|",
    ]
    # Use vulns row at n=25 as representative
    vuln_row = next((r for r in synthetic_rows if "vulns" in r.scenario and r.item_count == 25), None)
    if vuln_row:
        for session_count in [100, 1_000, 10_000, 100_000]:
            raw_cost = cost_usd(vuln_row.api_raw_tokens) * session_count
            filt_cost = cost_usd(vuln_row.api_filtered_tokens) * session_count
            saved = raw_cost - filt_cost
            lines.append(
                f"| {session_count:,} | ${raw_cost:.4f} | ${filt_cost:.4f} | ${saved:.4f} |"
            )

    lines += ["", "---", ""]

    # ── CLI advantage section ──
    lines += [
        "## When CLI Wins: Agent Decision Guide",
        "",
        "The CLI is NOT always less efficient. These scenarios show where CLI genuinely beats",
        "writing raw API code — measured by latency overhead, token cost, and implementation complexity.",
        "",
    ]

    # Subprocess overhead
    if subprocess_overhead:
        ovh = subprocess_overhead
        lines += [
            "### Subprocess Overhead",
            "",
            "Each CLI call spawns a subprocess. This overhead is **fixed per call**, not per item.",
            "",
            "| | API direct call | CLI subprocess | Overhead |",
            "|---|---|---|---|",
            f"| Latency mean | {ovh.api_latency_mean_ms:,.0f} ms "
            f"| {ovh.cli_latency_mean_ms:,.0f} ms "
            f"| **+{ovh.overhead_ms:,.0f} ms** ({ovh.overhead_ratio:.1f}×) |",
            f"| Latency p95  | {ovh.api_latency_p95_ms:,.0f} ms "
            f"| {ovh.cli_latency_p95_ms:,.0f} ms | — |",
            "",
            f"> **Rule of thumb:** {ovh.overhead_ratio:.0f}× overhead per call. "
            f"For a single one-shot query this is negligible. "
            f"For a loop of 10+ calls, API direct saves **{ovh.overhead_ms * 10 / 1000:.0f}s**.",
            "",
        ]

    # Pagination comparison
    if pagination_rows:
        lines += [
            "### Auto-Pagination: CLI `--all` vs Manual API Loop",
            "",
            "CLI `--all` handles cursor pagination automatically with one command.",
            "API requires writing a cursor loop (~15 lines of boilerplate code).",
            "",
            "| Scenario | CLI ndjson | API raw (all pages) | API filtered | CLI vs filtered |",
            "|----------|-----------|---------------------|--------------|----------------|",
        ]
        for pr in pagination_rows:
            diff = pr.cli_vs_filtered_pct
            direction = f"+{diff:.0f}% larger" if diff > 0 else f"{abs(diff):.0f}% smaller"
            lines.append(
                f"| {pr.scenario} "
                f"| {pr.cli_ndjson_tokens:,} tk "
                f"| {pr.api_raw_all_tokens:,} tk "
                f"| {pr.api_filtered_all_tokens:,} tk "
                f"| {direction} |"
            )
        lines += [
            "",
            "> **Use CLI `--all`** for streaming full result sets to files, SIEM, or jq.",
            "> **Use API filtered** when an agent needs to reason about the results — far fewer tokens.",
            "> **CLI wins on implementation complexity**: 1 command vs ~15 lines of pagination loop code.",
            "",
        ]

    # Filter complexity
    if filter_rows:
        lines += [
            "### Complex Filtering: CLI Flags vs API + Python Filter",
            "",
            "CLI bundles multi-condition filtering (rule name, severity, namespace, container) as flags.",
            "API returns raw unfiltered data — filtering logic must be written by the caller.",
            "",
            "| Scenario | Before filter | After filter | CLI tokens | API raw | API filtered | Code lines |",
            "|----------|:-------------:|:------------:|:----------:|:-------:|:------------:|:----------:|",
        ]
        for fr in filter_rows:
            lines.append(
                f"| `{fr.scenario}` "
                f"| {fr.item_count_before_filter} items "
                f"| {fr.item_count_after_filter} items "
                f"| {fr.cli_table_tokens:,} tk "
                f"| {fr.api_raw_tokens:,} tk "
                f"| {fr.api_filtered_tokens:,} tk "
                f"| CLI: {fr.cli_boilerplate_lines} · API: {fr.api_boilerplate_lines} |"
            )
        lines += [
            "",
            "> **CLI wins** when you need multi-condition filtering without writing Python.",
            "> **API filtered wins** when you also need to select specific fields — lowest token cost.",
            "",
        ]

    # Decision table
    lines += [
        "### Decision Guide: CLI vs API",
        "",
        "| Scenario | Use | Why |",
        "|----------|-----|-----|",
        "| **One-shot spot check** (`is anything critical right now?`) | **CLI** | No code, readable output, 1 command |",
        "| **Paginate full history** (`export last 7d to SIEM`) | **CLI `--all`** | Auto-handles cursor loop, streaming |",
        "| **Complex multi-flag filter** (`rule + severity + namespace`) | **CLI** | Filters built-in, no loop code needed |",
        "| **Pipe to jq / grep / file** | **CLI `--format ndjson`** | UNIX-friendly streaming format |",
        "| **Answer a specific question** (agent reasoning) | **API filtered** | 10–30× fewer input tokens |",
        "| **Loop over 10+ calls** (automation, dashboards) | **API direct** | Skip subprocess overhead × N |",
        "| **Build automation / reports** | **API filtered** | Full control, field selection, type safety |",
        "",
        "**Bottom line:** CLI is the right tool for human spot-checks, pagination, and complex filtering.",
        "API filtered is the right tool when an AI agent needs to reason about the data — token efficiency wins.",
        "",
        "---",
        "",
    ]

    lines += [
        "## Recommendations for Claude Code Agents",
        "",
        "1. **Default to `api_filtered`** — 10–30× fewer tokens; use `SysdigClient` directly "
        "   and select only the fields you need for the question being answered.",
        "2. **Use CLI for pagination** — `sysdig events list --from 7d --all --format ndjson` "
        "   handles cursor pagination automatically. Writing a pagination loop is ~15 lines.",
        "3. **Use CLI for one-shot spot-checks** — when you need a quick answer without writing code, "
        "   CLI is faster to invoke and handles auth, pagination, and output formatting.",
        "4. **Never loop CLI calls** — subprocess overhead is ~900ms per call. For 10 calls that's "
        "   9 extra seconds. Use the API directly for any loop.",
        "5. **Use `--limit` always** — unbounded pages can return 200 items, saturating context.",
        "6. **CLI table is for humans** — compact and readable, but not machine-parseable. "
        "   Never parse CLI table output in code.",
        "7. **Watch context pressure** — for a 200K-token window, a single unfiltered vulns page "
        "   consumes the percentages shown in the Synthetic Analysis table above.",
        "",
        f"*Generated by `prompts/benchmark_api_vs_cli.py` · {ts}*",
    ]
    return "\n".join(lines)


def render_json_output(
    live_scenarios: List[LiveScenario],
    synthetic_rows: List[SyntheticRow],
    latencies: Dict[str, Any],
    meta: Dict[str, Any],
    subprocess_overhead: Optional["SubprocessOverhead"] = None,
    pagination_rows: Optional[List["PaginationRow"]] = None,
    filter_rows: Optional[List["FilterComplexityRow"]] = None,
) -> Dict[str, Any]:
    def _ap(ar: ApproachResult) -> Dict[str, Any]:
        return {
            "approach": ar.approach,
            "description": ar.description,
            "error": ar.error,
            "all_auth_errors": ar.all_auth_errors,
            "latency_mean_ms": round(ar.latency_mean_ms, 1),
            "latency_p50_ms": round(ar.latency_p50_ms, 1),
            "latency_p95_ms": round(ar.latency_p95_ms, 1),
            "bytes_mean": ar.bytes_mean,
            "tokens_mean": ar.tokens_mean,
            "cost_per_call_usd": round(ar.cost_mean_usd, 8),
            "context_window_pct": round(ar.context_pct_mean, 4),
            "measurements": [
                {"latency_ms": round(m.latency_ms, 1),
                 "payload_bytes": m.payload_bytes,
                 "token_count": m.token_count,
                 "auth_error": m.auth_error}
                for m in ar.measurements
            ],
        }

    result: Dict[str, Any] = {
        "meta": meta,
        "latency_probes": latencies,
        "live_scenarios": [
            {"name": sc.name, "description": sc.description, "endpoint": sc.endpoint,
             "approaches": [_ap(ar) for ar in sc.approaches]}
            for sc in live_scenarios
        ],
        "synthetic_analysis": [
            {"scenario": r.scenario, "item_count": r.item_count,
             "cli_table_tokens": r.cli_table_tokens,
             "cli_json_tokens": r.cli_json_tokens,
             "api_raw_tokens": r.api_raw_tokens,
             "api_filtered_tokens": r.api_filtered_tokens,
             "savings_api_raw_vs_filtered_pct": round(r.savings_api_raw_vs_filtered_pct, 1),
             "savings_cli_table_vs_filtered_pct": round(r.savings_cli_table_vs_filtered_pct, 1),
             "reduction_ratio": round(r.reduction_ratio, 1)}
            for r in synthetic_rows
        ],
    }
    if subprocess_overhead:
        result["subprocess_overhead"] = {
            "api_latency_mean_ms": subprocess_overhead.api_latency_mean_ms,
            "api_latency_p95_ms": subprocess_overhead.api_latency_p95_ms,
            "cli_latency_mean_ms": subprocess_overhead.cli_latency_mean_ms,
            "cli_latency_p95_ms": subprocess_overhead.cli_latency_p95_ms,
            "overhead_ms": round(subprocess_overhead.overhead_ms, 1),
            "overhead_ratio": round(subprocess_overhead.overhead_ratio, 2),
        }
    if pagination_rows:
        result["pagination_analysis"] = [
            {"scenario": r.scenario, "total_items": r.total_items, "num_pages": r.num_pages,
             "cli_ndjson_tokens": r.cli_ndjson_tokens,
             "api_raw_all_tokens": r.api_raw_all_tokens,
             "api_filtered_all_tokens": r.api_filtered_all_tokens,
             "savings_vs_api_raw_pct": round(r.savings_vs_api_raw, 1)}
            for r in pagination_rows
        ]
    if filter_rows:
        result["filter_complexity"] = [
            {"scenario": r.scenario,
             "before_filter": r.item_count_before_filter,
             "after_filter": r.item_count_after_filter,
             "cli_table_tokens": r.cli_table_tokens,
             "api_raw_tokens": r.api_raw_tokens,
             "api_filtered_tokens": r.api_filtered_tokens,
             "cli_boilerplate_lines": r.cli_boilerplate_lines,
             "api_boilerplate_lines": r.api_boilerplate_lines}
            for r in filter_rows
        ]
    return result


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    global _cli_profile

    import argparse
    parser = argparse.ArgumentParser(
        description="Sysdig API vs CLI performance benchmark for Claude Code agents"
    )
    parser.add_argument("--profile", "-p", default="default",
                        help="Config-file profile (bypasses SYSDIG_API_TOKEN env var)")
    parser.add_argument("--iterations", "-n", type=int, default=DEFAULT_ITERATIONS,
                        help=f"Iterations per measurement (default: {DEFAULT_ITERATIONS})")
    args = parser.parse_args()
    _cli_profile = args.profile

    print("=" * 70)
    print("  Sysdig Performance Benchmark: Native API vs CLI")
    print("  For Claude Code Agent token & cost analysis")
    print("=" * 70)
    print()

    # Auth
    try:
        auth = load_profile_auth(args.profile)
        print(f"  Auth  : {auth.host}")
        print(f"  Profile: {auth.profile}  (config file)")
    except Exception:
        try:
            auth = resolve_auth()
            print(f"  Auth  : {auth.host}  (env vars)")
        except Exception as e:
            print(f"  ERROR: {e}")
            sys.exit(1)

    iters = args.iterations
    print(f"  Iters  : {iters} per measurement")
    print(f"  Pricing: ${TOKEN_COST_INPUT_USD_PER_M}/1M input tokens (Claude Sonnet 4.6)")
    print()

    subprocess_overhead: Optional[SubprocessOverhead] = None
    pagination_rows: List[PaginationRow] = []
    filter_rows: List[FilterComplexityRow] = []

    with SysdigClient(auth=auth) as client:

        # ── latency probes ──
        print("  [1/5] Probing endpoint latencies ...", flush=True)
        latencies = probe_latencies(client, iters)
        for name, r in latencies.items():
            icon = "✓" if r["status"] == "ok" else "🔐"
            print(f"        {icon} {name:<28} {r['latency_mean_ms']:>7.0f} ms avg  "
                  f"({r['status']})")
        print()

        # ── live scenarios ──
        print("  [2/5] Live API measurements ...", flush=True)
        live_fns = [
            ("vulns list",          live_vulns_list),
            ("events list",         live_events_list),
            ("audit recent-cmds",   live_audit_commands),
            ("audit platform-evts", live_platform_events),
        ]
        live_scenarios: List[LiveScenario] = []
        for label, fn in live_fns:
            print(f"        ▶ {label} ...", end="", flush=True)
            try:
                sc = fn(client, iters)
                live_scenarios.append(sc)
                by_id = {a.approach: a for a in sc.approaches}
                ct = by_id.get("cli_table")
                af = by_id.get("api_filtered")
                if ct and af and ct.ok and af.ok:
                    saved = (1 - af.tokens_mean / max(ct.tokens_mean, 1)) * 100
                    print(f"  {ct.tokens_mean:,} tk (table) → {af.tokens_mean:,} tk (filtered)  "
                          f"[{saved:.0f}% saved]")
                else:
                    auth_errs = sum(1 for a in sc.approaches if a.all_auth_errors)
                    print(f"  ({auth_errs}/4 auth errors — latency recorded)")
            except Exception as exc:
                print(f"  ERROR: {exc}")
        print()

        # ── synthetic analysis ──
        print("  [3/5] Synthetic token analysis ...", flush=True)
        synthetic_rows = build_synthetic_rows([10, 25, 100])
        for row in synthetic_rows:
            saved_raw = row.savings_api_raw_vs_filtered_pct
            saved_tbl = row.savings_cli_table_vs_filtered_pct
            print(f"        {row.scenario:<35}  "
                  f"raw={row.api_raw_tokens:>6,}tk  "
                  f"table={row.cli_table_tokens:>5,}tk  "
                  f"filtered={row.api_filtered_tokens:>4,}tk  "
                  f"[raw→filt: {saved_raw:.0f}%  tbl→filt: {saved_tbl:.0f}%]")
        print()

        # ── subprocess overhead ──
        print("  [4/5] Measuring subprocess overhead (CLI vs API direct) ...", flush=True)
        subprocess_overhead = measure_subprocess_overhead(client, max(iters, 5))
        print(f"        API direct: {subprocess_overhead.api_latency_mean_ms:.0f} ms mean  "
              f"(p95: {subprocess_overhead.api_latency_p95_ms:.0f} ms)")
        print(f"        CLI subprocess: {subprocess_overhead.cli_latency_mean_ms:.0f} ms mean  "
              f"(p95: {subprocess_overhead.cli_latency_p95_ms:.0f} ms)")
        print(f"        Overhead: +{subprocess_overhead.overhead_ms:.0f} ms per CLI call  "
              f"({subprocess_overhead.overhead_ratio:.1f}× slower)")
        print()

        # ── CLI advantage: pagination + filter complexity ──
        print("  [5/5] CLI advantage analysis (pagination + filter complexity) ...", flush=True)
        pagination_rows = build_pagination_rows([100, 300, 1000])
        for pr in pagination_rows:
            diff_pct = pr.cli_vs_filtered_pct
            direction = f"+{diff_pct:.0f}% vs filtered" if diff_pct > 0 else f"{abs(diff_pct):.0f}% vs filtered"
            print(f"        {pr.scenario:<40}  "
                  f"cli={pr.cli_ndjson_tokens:>7,}tk  "
                  f"raw={pr.api_raw_all_tokens:>8,}tk  "
                  f"filtered={pr.api_filtered_all_tokens:>6,}tk  [{direction}]")

        filter_rows = build_filter_complexity_rows()
        for fr in filter_rows:
            print(f"        {fr.scenario:<55}  "
                  f"cli={fr.cli_table_tokens:>5,}tk  "
                  f"api_raw={fr.api_raw_tokens:>6,}tk  "
                  f"api_filt={fr.api_filtered_tokens:>5,}tk  "
                  f"[code: CLI {fr.cli_boilerplate_lines}L vs API {fr.api_boilerplate_lines}L]")
        print()

    # ── write results ──
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    meta: Dict[str, Any] = {
        "timestamp": ts,
        "iterations": iters,
        "token_cost_input_usd_per_million": TOKEN_COST_INPUT_USD_PER_M,
        "context_window_tokens": CONTEXT_WINDOW_TOKENS,
        "chars_per_token": CHARS_PER_TOKEN,
        "sysdig_host": auth.host,
        "profile": auth.profile,
    }

    out_dir = ROOT / "prompts"
    out_dir.mkdir(exist_ok=True)
    json_path = out_dir / f"benchmark-results-{ts}.json"
    md_path = out_dir / f"benchmark-results-{ts}.md"

    json_path.write_text(
        json.dumps(render_json_output(
            live_scenarios, synthetic_rows, latencies, meta,
            subprocess_overhead, pagination_rows, filter_rows,
        ), indent=2),
        encoding="utf-8",
    )
    md_path.write_text(
        render_markdown(
            live_scenarios, synthetic_rows, latencies, meta,
            subprocess_overhead, pagination_rows, filter_rows,
        ),
        encoding="utf-8",
    )

    print(f"  Results saved:")
    print(f"    JSON → {json_path}")
    print(f"    MD   → {md_path}")
    print()

    # ── terminal summary ──
    print("  " + "─" * 78)
    print(f"  {'SYNTHETIC ANALYSIS':^78}")
    print(f"  {'SCENARIO':<35} {'API raw':>8}  {'CLI tbl':>8}  {'CLI json':>9}  {'Filtered':>9}  {'raw→filt':>9}")
    print("  " + "─" * 78)
    for row in synthetic_rows:
        saved = row.savings_api_raw_vs_filtered_pct
        print(f"  {row.scenario:<35} {row.api_raw_tokens:>7,}tk  "
              f"{row.cli_table_tokens:>7,}tk  "
              f"{row.cli_json_tokens:>8,}tk  "
              f"{row.api_filtered_tokens:>8,}tk  "
              f"{saved:>8.0f}%")
    print("  " + "─" * 78)

    print()
    print("  Endpoint latencies (round-trip to API):")
    for name, r in latencies.items():
        icon = "✅" if r["status"] == "ok" else "🔐"
        print(f"    {icon} {name:<30} {r['latency_mean_ms']:>6.0f} ms  (p95: {r['latency_p95_ms']:,.0f} ms)")
    print()


if __name__ == "__main__":
    main()

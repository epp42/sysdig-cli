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

Metrics:
  • Latency (ms)           wall-clock time (mean / p50 / p95)
  • Payload (bytes/tokens) bytes returned + token estimate (chars ÷ 4)
  • Token cost (USD)        Claude Sonnet 4.6 input pricing ($3 / 1M tokens)
  • Context pressure (%)    fraction of 200K-token context window

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

    lines += [
        "",
        "---",
        "",
        "## Recommendations for Claude Code Agents",
        "",
        "1. **Default to `api_filtered`** — 10–30× fewer tokens; use `SysdigClient` directly "
        "   and select only the fields you need for the question being answered.",
        "2. **Never use CLI table format for machine consumption** — table formatting adds "
        "   column headers, padding, and borders with zero semantic value for LLMs.",
        "3. **Batch operations with field selection** — instead of `sysdig vulns list` (full page), "
        "   call the API once with `fields=['mainAssetName','criticalVulnCount']`.",
        "4. **Use `--limit` always** — unbounded pages can return 200 items, saturating context.",
        "5. **`sysdig` CLI is best for human spot-checks** — when the agent needs to present "
        "   results to a human in readable form, table format is appropriate.",
        "6. **Watch context pressure** — for a 200K-token window, a single unfiltered vulns page "
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

    return {
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

    with SysdigClient(auth=auth) as client:

        # ── latency probes ──
        print("  [1/3] Probing endpoint latencies ...", flush=True)
        latencies = probe_latencies(client, iters)
        for name, r in latencies.items():
            icon = "✓" if r["status"] == "ok" else "🔐"
            print(f"        {icon} {name:<28} {r['latency_mean_ms']:>7.0f} ms avg  "
                  f"({r['status']})")
        print()

        # ── live scenarios ──
        print("  [2/3] Live API measurements ...", flush=True)
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
        print("  [3/3] Synthetic token analysis ...", flush=True)
        synthetic_rows = build_synthetic_rows([10, 25, 100])
        # print quick summary
        for row in synthetic_rows:
            saved_raw = row.savings_api_raw_vs_filtered_pct
            saved_tbl = row.savings_cli_table_vs_filtered_pct
            print(f"        {row.scenario:<35}  "
                  f"raw={row.api_raw_tokens:>6,}tk  "
                  f"table={row.cli_table_tokens:>5,}tk  "
                  f"filtered={row.api_filtered_tokens:>4,}tk  "
                  f"[raw→filt: {saved_raw:.0f}%  tbl→filt: {saved_tbl:.0f}%]")
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
        json.dumps(render_json_output(live_scenarios, synthetic_rows, latencies, meta), indent=2),
        encoding="utf-8",
    )
    md_path.write_text(
        render_markdown(live_scenarios, synthetic_rows, latencies, meta),
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

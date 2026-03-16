"""
Alerts helper commands.
+noise-report: Show top-N rules by event volume with inhibition suggestions
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info
from ..timestamps import now_ns, parse_timestamp

alerts_helpers_app = typer.Typer(
    name="alerts-helpers",
    help="Alerts helper commands.",
    no_args_is_help=True,
)


@alerts_helpers_app.command("noise-report")
def alerts_noise_report(
    since: str = typer.Option("7d", "--since"),
    top: int = typer.Option(20, "--top"),
    suggest_inhibitions: bool = typer.Option(False, "--suggest-inhibitions"),
    format: str = typer.Option("table", "--format"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Show top-N rules by event volume with inhibition suggestions."""
    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        from_ns = parse_timestamp(since)
    except ValueError as e:
        print_error(f"Invalid --since value: {e}")
        raise typer.Exit(1)

    print_info(f"Fetching event volume data (last {since}, top {top})...")

    rule_counts: Counter = Counter()
    rule_details: Dict[str, Dict[str, Any]] = {}

    try:
        with SysdigClient(auth=auth) as client:
            params: Dict[str, Any] = {
                "limit": 1000,
                "from": from_ns,
                "to": now_ns(),
            }
            resp = client.get("/secure/events/v1/events", params=params)
            events = (resp or {}).get("data") or (resp or {}).get("events") or []

            for event in events:
                rule_name = (
                    event.get("ruleName") or
                    event.get("name") or
                    event.get("policyName") or
                    "unknown"
                )
                rule_counts[rule_name] += 1
                if rule_name not in rule_details:
                    rule_details[rule_name] = {
                        "severity": event.get("severity", ""),
                        "type": event.get("type") or event.get("source", ""),
                    }

    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    top_rules: List[Dict[str, Any]] = []
    for rule_name, count in rule_counts.most_common(top):
        details = rule_details.get(rule_name, {})
        entry: Dict[str, Any] = {
            "rule": rule_name,
            "event_count": count,
            "severity": details.get("severity", ""),
            "type": details.get("type", ""),
        }
        if suggest_inhibitions:
            entry["suggested_inhibition"] = _suggest_inhibition(rule_name, count)
        top_rules.append(entry)

    total_events = sum(rule_counts.values())
    result = {
        "noise_report": {
            "since": since,
            "total_events": total_events,
            "unique_rules": len(rule_counts),
            "top_rules": top_rules,
        }
    }
    output(result, fmt=format)
    print_info(
        f"Noise report: {total_events} total events, {len(rule_counts)} unique rules."
    )


def _suggest_inhibition(rule_name: str, count: int) -> str:
    """Generate a simple inhibition suggestion based on rule name and count."""
    if count < 10:
        return "no_action_needed"
    rule_lower = rule_name.lower()
    if "bash" in rule_lower or "shell" in rule_lower:
        return "Consider scoping to specific namespaces or service accounts"
    if "network" in rule_lower or "connection" in rule_lower:
        return "Consider adding trusted IP allowlist"
    if "file" in rule_lower or "write" in rule_lower:
        return "Consider scoping to specific container images"
    if count > 1000:
        return "High volume - review rule conditions, consider time-based suppression"
    return "Review rule conditions and scope to reduce false positives"

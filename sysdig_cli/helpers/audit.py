"""
Audit helper commands.
+recent-commands: Last 100 commands from activity audit
+compliance-export: Export audit trail structured for compliance frameworks
+incident-timeline: Chronological timeline of commands+connections+file accesses for a workload
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning
from ..paginator import paginate_all_items
from ..timestamps import now_ns, parse_timestamp

# ---------------------------------------------------------------------------
# Typer sub-app for audit helpers (used by main.py)
# ---------------------------------------------------------------------------
audit_helpers_app = typer.Typer(
    name="audit-helpers",
    help="Audit helper commands.",
    no_args_is_help=True,
)


def recent_commands(
    profile: str = "default",
    region: Optional[str] = None,
    fmt: str = "table",
    limit: int = 100,
    user: Optional[str] = None,
    all_pages: bool = False,
    from_time: str = "24h",
) -> None:
    """
    Show the last N commands from the activity audit log.
    Displays recent platform activity including API calls and user actions.
    """
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        from_ns = parse_timestamp(from_time)
    except ValueError:
        from_ns = now_ns() - int(24 * 3600 * 1e9)

    params: Dict[str, Any] = {
        "limit": min(limit, 1000),
        "from": from_ns,
        "to": now_ns(),
    }

    # Add user filter if specified (server-side filter; also applied client-side below)
    if user:
        params["filter"] = f'username="{user}"'

    if all_pages:
        actual_fmt = "ndjson" if fmt == "table" else fmt
        print_info("Streaming all activity audit entries...")
        count = 0
        try:
            import json
            import sys as _sys
            with SysdigClient(auth=auth) as client:
                for entry in paginate_all_items(
                    client, "GET", "/secure/activity-audit/v1/entries",
                    params=params,
                    cursor_exclusive_keys=["from", "to"],
                ):
                    if user and user.lower() not in (
                        entry.get("username") or entry.get("userLoginName") or ""
                    ).lower():
                        continue
                    count += 1
                    if actual_fmt == "ndjson":
                        print(json.dumps(entry, default=str))
                        _sys.stdout.flush()
                    else:
                        output({"entries": [entry]}, fmt=actual_fmt)
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
        print_info(f"Total: {count} audit entries")
        return

    try:
        with SysdigClient(auth=auth) as client:
            response = client.get("/secure/activity-audit/v1/entries", params=params)
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, 'exit_code', 3))

    if response is None:
        output({"entries": [], "total": 0}, fmt=fmt)
        return

    entries = (
        response.get("data") or
        response.get("entries") or
        response.get("items") or
        []
    )

    # Return structured output
    result = {
        "entries": entries,
        "total": len(entries),
        "limit": limit,
    }

    if user:
        result["user_filter"] = user

    output(result, fmt=fmt)
    print_info(f"Showing {len(entries)} recent audit entries.")


# ---------------------------------------------------------------------------
# Compliance export command
# ---------------------------------------------------------------------------

_FRAMEWORK_FILTERS: Dict[str, str] = {
    "soc2": "type IN ('kubectl.exec','kubectl.cp','config.change','user.login','policy.update')",
    "pci": "type IN ('kubectl.exec','network.access','config.change','user.login','data.access')",
    "iso27001": "type IN ('config.change','user.login','policy.update','access.change')",
    "hipaa": "type IN ('data.access','user.login','config.change','kubectl.exec')",
}


@audit_helpers_app.command("compliance-export")
def audit_compliance_export(
    framework: str = typer.Option("soc2", "--framework", help="soc2|pci|iso27001|hipaa"),
    since: str = typer.Option("30d", "--since", help="Time window (30d, 7d, etc.)"),
    format: str = typer.Option("json", "--format", help="json|csv"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Export audit trail structured for compliance frameworks."""
    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    if framework not in _FRAMEWORK_FILTERS:
        print_error(f"Unknown framework '{framework}'. Valid: {', '.join(_FRAMEWORK_FILTERS)}")
        raise typer.Exit(1)

    try:
        from_ns = parse_timestamp(since)
    except ValueError as e:
        print_error(f"Invalid --since value: {e}")
        raise typer.Exit(1)

    print_info(f"Exporting audit trail for {framework.upper()} compliance (since {since})...")

    params: Dict[str, Any] = {
        "limit": 1000,
        "sort": "timestamp",
        "order": "asc",
        "from": from_ns,
        "to": now_ns(),
    }

    try:
        with SysdigClient(auth=auth) as client:
            response = client.get("/secure/activity-audit/v1/entries", params=params)
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    if response is None:
        response = {}

    entries = (
        response.get("data") or
        response.get("entries") or
        response.get("items") or
        []
    )

    # Flatten for export
    flat_entries = []
    for entry in entries:
        flat_entry = {
            "id": entry.get("id", ""),
            "timestamp": entry.get("timestamp", ""),
            "type": entry.get("type", ""),
            "user": (entry.get("user") or {}).get("name", entry.get("user", "")),
            "resource": entry.get("resourceName") or entry.get("resource", ""),
            "action": entry.get("commandLine") or entry.get("action", ""),
            "result": entry.get("result", ""),
            "ip": entry.get("ipAddress") or entry.get("ip", ""),
            "framework": framework,
        }
        flat_entries.append(flat_entry)

    result = {
        "compliance_export": {
            "framework": framework,
            "since": since,
            "total_entries": len(flat_entries),
            "entries": flat_entries,
        }
    }
    output(result, fmt=format)
    print_info(f"Exported {len(flat_entries)} audit entries for {framework.upper()}.")


# ---------------------------------------------------------------------------
# Incident timeline command
# ---------------------------------------------------------------------------


@audit_helpers_app.command("incident-timeline")
def audit_incident_timeline(
    pod: str = typer.Argument(..., help="Pod name to investigate"),
    since: str = typer.Option("2h", "--since", help="Time window"),
    namespace: Optional[str] = typer.Option(None, "--namespace"),
    format: str = typer.Option("table", "--format"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Chronological timeline of commands+connections+file accesses for a workload."""
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

    ns_label = f" in namespace '{namespace}'" if namespace else ""
    print_info(f"Building incident timeline for pod '{pod}'{ns_label} (last {since})...")

    pod_filter = f'pod.name="{pod}"'
    if namespace:
        pod_filter += f' and kubernetes.namespace.name="{namespace}"'

    params: Dict[str, Any] = {
        "limit": 1000,
        "sort": "timestamp",
        "order": "asc",
        "from": from_ns,
        "to": now_ns(),
        "filter": pod_filter,
    }

    timeline_events: List[Dict[str, Any]] = []

    try:
        with SysdigClient(auth=auth) as client:
            # Fetch activity audit entries
            audit_resp = client.get("/secure/activity-audit/v1/entries", params=params)
            audit_entries = (audit_resp or {}).get("data") or (audit_resp or {}).get("entries") or []
            for entry in audit_entries:
                timeline_events.append({
                    "timestamp": entry.get("timestamp", ""),
                    "type": "audit",
                    "subtype": entry.get("type", ""),
                    "detail": entry.get("commandLine") or entry.get("action") or "",
                    "user": (entry.get("user") or {}).get("name", ""),
                    "pod": pod,
                    "namespace": namespace or "",
                })

            # Fetch security events
            events_resp = client.get("/secure/events/v1/events", params=params)
            sec_events = (events_resp or {}).get("data") or (events_resp or {}).get("events") or []
            for event in sec_events:
                timeline_events.append({
                    "timestamp": event.get("timestamp", ""),
                    "type": "security_event",
                    "subtype": event.get("name") or event.get("type", ""),
                    "detail": event.get("description") or event.get("output", ""),
                    "user": "",
                    "pod": pod,
                    "namespace": namespace or "",
                    "severity": event.get("severity", ""),
                })

    except (AuthError, ForbiddenError, SysdigError) as e:
        print_warning(f"API error: {e}")

    # Sort chronologically
    timeline_events.sort(key=lambda x: str(x.get("timestamp", "")))

    result = {
        "incident_timeline": {
            "pod": pod,
            "namespace": namespace or "",
            "since": since,
            "total_events": len(timeline_events),
            "events": timeline_events,
        }
    }
    output(result, fmt=format)
    print_info(f"Timeline: {len(timeline_events)} events found for pod '{pod}'.")


# ---------------------------------------------------------------------------
# Platform audit events command
# ---------------------------------------------------------------------------


def audit_platform_events(
    from_time: str = typer.Option("24h", "--from", help="Start time: 1h, 24h, 7d, ISO8601"),
    to_time: Optional[str] = typer.Option(None, "--to", help="End time (default: now)"),
    user: Optional[str] = typer.Option(None, "--user", help="Filter by user email"),
    action: Optional[str] = typer.Option(None, "--action", help="Filter by action type"),
    limit: int = typer.Option(100, "--limit", "-n"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml|ndjson"),
    all_pages: bool = typer.Option(False, "--all", help="Stream ALL pages via cursor pagination (outputs ndjson)"),
) -> None:
    """List platform-level audit events (login, config changes, etc).

    Examples:
      sysdig audit platform-events                    Last 24h
      sysdig audit platform-events --user admin@corp.com
      sysdig audit platform-events --action login
    """
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        from_ns = parse_timestamp(from_time)
    except ValueError as e:
        print_error(f"Invalid --from value: {e}")
        raise typer.Exit(1)

    to_ns = now_ns()
    if to_time:
        try:
            to_ns = parse_timestamp(to_time)
        except ValueError as e:
            print_error(f"Invalid --to value: {e}")
            raise typer.Exit(1)

    params: Dict[str, Any] = {
        "from": from_ns,
        "to": to_ns,
        "limit": limit,
    }

    if all_pages:
        actual_fmt = "ndjson" if fmt == "table" else fmt
        print_info("Streaming all platform audit events...")
        count = 0
        try:
            import json
            import sys as _sys
            with SysdigClient(auth=auth) as client:
                for event in paginate_all_items(
                    client, "GET", "/platform/v1/platform-audit-events",
                    params=params,
                ):
                    username = (event.get("content") or {}).get("username") or event.get("userEmail") or ""
                    if user and user.lower() not in username.lower():
                        continue
                    req_uri = (event.get("content") or {}).get("requestUri") or event.get("action") or ""
                    if action and action.lower() not in req_uri.lower():
                        continue
                    count += 1
                    if actual_fmt == "ndjson":
                        print(json.dumps(event, default=str))
                        _sys.stdout.flush()
                    else:
                        output({"data": [event]}, fmt=actual_fmt, schema="platform_audit_events")
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
        print_info(f"Total: {count} audit events")
        return

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.get("/platform/v1/platform-audit-events", params=params)
    except AuthError as e:
        print_error(str(e))
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(str(e))
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    if resp is None:
        resp = {}

    events: List[Dict[str, Any]] = (
        resp.get("data")
        or resp.get("items")
        or resp.get("events")
        or resp.get("auditEvents")
        or []
    )

    if user:
        events = [
            ev for ev in events
            if user.lower() in str(
                (ev.get("content") or {}).get("username") or ev.get("userEmail") or ""
            ).lower()
        ]

    if action:
        events = [
            ev for ev in events
            if action.lower() in str(
                (ev.get("content") or {}).get("requestUri") or ev.get("action") or ""
            ).lower()
        ]

    output(events, fmt=fmt, schema="platform_audit_events")
    print_info(f"Showing {len(events)} platform audit event(s).")

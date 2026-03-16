"""
Events helper commands.
+tail: Poll for new events every 10s, stream to stdout
+hunt: Search events for keyword/IOC pattern
"""
# ruff: noqa: C901
from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict, List, Optional, Set

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning
from ..paginator import stream_ndjson, paginate_all_items
from ..timestamps import now_ns, parse_timestamp


def tail(
    profile: str = "default",
    region: Optional[str] = None,
    interval: int = 10,
    fmt: str = "ndjson",
    filter: Optional[str] = None,
    limit: int = 100,
) -> None:
    """
    Poll for new security events every N seconds and stream to stdout.
    Press Ctrl+C to stop.
    """
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    print_info(f"Tailing Sysdig events every {interval}s (Ctrl+C to stop)...")

    seen_ids: Set[str] = set()
    last_from = now_ns() - int(60 * 1e9)  # Start 60s ago

    try:
        with SysdigClient(auth=auth) as client:
            while True:
                params: Dict[str, Any] = {
                    "limit": limit,
                    "from": last_from,
                    "to": now_ns(),
                }
                if filter:
                    params["filter"] = filter

                try:
                    response = client.get("/secure/events/v1/events", params=params)
                    if response is None:
                        time.sleep(interval)
                        continue

                    events = (
                        response.get("data") or
                        response.get("events") or
                        response.get("items") or
                        []
                    )

                    new_events = []
                    for event in events:
                        event_id = str(event.get("id", "") or event.get("eventId", ""))
                        if event_id and event_id in seen_ids:
                            continue
                        if event_id:
                            seen_ids.add(event_id)
                        new_events.append(event)

                    for event in new_events:
                        if fmt == "ndjson":
                            print(json.dumps(event, default=str))
                        else:
                            output(event, fmt=fmt)

                    # Update time window
                    last_from = now_ns() - int(5 * 1e9)  # overlap 5s

                    if new_events:
                        # Flush
                        sys.stdout.flush()

                except (AuthError, ForbiddenError) as e:
                    print_error(str(e))
                    raise typer.Exit(2)
                except SysdigError as e:
                    print_warning(f"API error (will retry): {e}")

                time.sleep(interval)

    except KeyboardInterrupt:
        print_info("Stopped tailing events.")


def hunt(
    ioc: str,
    profile: str = "default",
    region: Optional[str] = None,
    fmt: str = "json",
    from_time: Optional[str] = None,
    limit: int = 500,
) -> None:
    """
    Hunt for events matching a keyword or IOC (Indicator of Compromise).
    Searches event content for the specified pattern.
    """
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    print_info(f"Hunting for IOC: {ioc!r}")

    # Default: last 24 hours
    from_ns: int
    if from_time:
        try:
            from_ns = parse_timestamp(from_time)
        except ValueError as e:
            print_error(f"Invalid --from time: {e}")
            raise typer.Exit(1)
    else:
        from_ns = now_ns() - int(24 * 3600 * 1e9)

    params: Dict[str, Any] = {
        "limit": min(limit, 1000),
        "from": from_ns,
        "to": now_ns(),
    }

    try:
        with SysdigClient(auth=auth) as client:
            response = client.get("/secure/events/v1/events", params=params)
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
        output({"matches": [], "total": 0, "ioc": ioc}, fmt=fmt)
        return

    events = (
        response.get("data") or
        response.get("events") or
        response.get("items") or
        []
    )

    # Search for IOC in event JSON content
    ioc_lower = ioc.lower()
    matches = []
    for event in events:
        event_str = json.dumps(event, default=str).lower()
        if ioc_lower in event_str:
            matches.append(event)

    result = {
        "ioc": ioc,
        "from": from_ns,
        "to": now_ns(),
        "total_scanned": len(events),
        "matches": matches,
        "match_count": len(matches),
    }
    output(result, fmt=fmt)
    print_info(f"Found {len(matches)} matching events out of {len(events)} scanned.")


def events_list(
    from_time: str = typer.Option("1h", "--from", help="Start time: 1h, 24h, 7d, ISO8601"),
    to_time: Optional[str] = typer.Option(None, "--to", help="End time (default: now)"),
    severity: Optional[int] = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity (integer, higher=worse, e.g. 4=warning, 6=error, 7=critical)",
    ),
    rule: Optional[str] = typer.Option(None, "--rule", help="Filter by rule name (substring)"),
    container: Optional[str] = typer.Option(None, "--container", help="Filter by container name (substring)"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Filter by namespace (substring)"),
    pod: Optional[str] = typer.Option(None, "--pod", help="Filter by pod name (substring)"),
    limit: int = typer.Option(100, "--limit", "-n", help="Max events per page (ignored with --all)"),
    all_pages: bool = typer.Option(False, "--all", help="Stream ALL pages via cursor pagination (outputs ndjson)"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml|ndjson"),
    no_trunc: bool = typer.Option(False, "--no-trunc", help="Disable output truncation (show full names)"),
) -> None:
    """List security events with rich filtering.

    Use --all to paginate through the full time window automatically.
    The events API supports up to 2 weeks of history.

    Examples:
      sysdig events list                                  Last 1h (default)
      sysdig events list --from 24h                      Last 24 hours
      sysdig events list --from 7d --severity 7          Critical events last 7d
      sysdig events list --from 7d --all --format ndjson  Stream ALL pages
      sysdig events list --rule "Drift" --all            All drift events, paginated
      sysdig events list --container nginx               Container name filter
    """
    try:
        auth = resolve_auth(profile=profile or "default", region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        from_ns = parse_timestamp(from_time)
    except ValueError as e:
        print_error(f"Invalid --from time: {e}")
        raise typer.Exit(1)

    to_ns: int
    if to_time:
        try:
            to_ns = parse_timestamp(to_time)
        except ValueError as e:
            print_error(f"Invalid --to time: {e}")
            raise typer.Exit(1)
    else:
        to_ns = now_ns()

    def _field_val(e: Dict[str, Any], *keys: str) -> str:
        """Extract a Falco fields value, handling flat dot-keys and nested dicts."""
        fields = (e.get("content") or {}).get("fields") or {}
        for key in keys:
            # Try flat key first (Falco stores as {"container.name": "nginx"})
            v = fields.get(key)
            if v is not None:
                return str(v).lower()
            # Try nested key split by first dot segment
            parts = key.split(".", 1)
            if len(parts) == 2:
                nested = (fields.get(parts[0]) or {})
                if isinstance(nested, dict):
                    v2 = nested.get(parts[1])
                    if v2 is not None:
                        return str(v2).lower()
        return ""

    # Build client-side filter function (applied to every event regardless of mode)
    def _matches(e: Dict[str, Any]) -> bool:
        if severity is not None and (e.get("severity") or 0) < severity:
            return False
        if rule:
            rule_name = (e.get("content") or {}).get("ruleName") or e.get("name") or ""
            if rule.lower() not in rule_name.lower():
                return False
        if container:
            cont = _field_val(e, "container.name", "container_name")
            if container.lower() not in cont:
                return False
        if namespace:
            ns = _field_val(e, "k8s.ns.name", "k8s.namespace.name", "kubernetes.namespace.name")
            if namespace.lower() not in ns:
                return False
        if pod:
            pname = _field_val(e, "k8s.pod.name", "kubernetes.pod.name")
            if pod.lower() not in pname:
                return False
        return True

    filters_applied = []
    if from_time != "1h" or to_time:
        filters_applied.append(f"from={from_time}")
    if severity is not None:
        filters_applied.append(f"severity>={severity}")
    if rule:
        filters_applied.append(f"rule~={rule!r}")
    if container:
        filters_applied.append(f"container~={container!r}")
    if namespace:
        filters_applied.append(f"namespace~={namespace!r}")
    if pod:
        filters_applied.append(f"pod~={pod!r}")
    filter_str = f" [{', '.join(filters_applied)}]" if filters_applied else ""

    params: Dict[str, Any] = {
        "limit": 200,  # max per page
        "from": from_ns,
        "to": to_ns,
    }

    # --all mode: stream all pages via cursor pagination, output as ndjson
    if all_pages:
        actual_fmt = "ndjson" if fmt == "table" else fmt
        print_info(f"Streaming all events{filter_str} in last {from_time} (paginated)...")
        count = 0
        try:
            with SysdigClient(auth=auth) as client:
                for event in paginate_all_items(
                    client, "GET", "/secure/events/v1/events",
                    params=params,
                    # Events API: cursor and from/to are mutually exclusive
                    cursor_exclusive_keys=["from", "to"],
                ):
                    if not _matches(event):
                        continue
                    count += 1
                    if actual_fmt == "ndjson":
                        print(json.dumps(event, default=str))
                        sys.stdout.flush()
                    else:
                        output({"data": [event]}, fmt=actual_fmt, schema="events_list", no_trunc=no_trunc)
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
        print_info(f"Total: {count} events{filter_str}")
        return

    # Single-page mode
    params["limit"] = min(limit * 2, 1000)
    try:
        with SysdigClient(auth=auth) as client:
            response = client.get("/secure/events/v1/events", params=params)
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    events: List[Dict[str, Any]] = (
        (response or {}).get("data") or
        (response or {}).get("events") or
        (response or {}).get("items") or
        []
    )

    events = [e for e in events if _matches(e)][:limit]

    total_matched = (response or {}).get("page", {}).get("total") if response else None
    suffix = f" (API reports {total_matched:,} total — use --all to fetch all)" if total_matched and total_matched > len(events) else ""
    print_info(f"{len(events)} events{filter_str}{suffix}")
    output({"data": events}, fmt=fmt, schema="events_list", no_trunc=no_trunc)


def events_id(
    event_id: str = typer.Argument(..., help="Event ID (from 'events list' ID column)"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("json", "--format", "-f", help="json|yaml|table"),
    no_trunc: bool = typer.Option(False, "--no-trunc", help="Disable output truncation (show full names)"),
) -> None:
    """Show full detail for a specific security event.

    The event ID comes from 'sysdig events list' or 'sysdig events tail'.

    Example:
      sysdig events id abc123
    """
    try:
        auth = resolve_auth(profile=profile or "default", region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        with SysdigClient(auth=auth) as client:
            event = client.get(f"/secure/events/v1/events/{event_id}")
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    if not event:
        print_error(f"Event not found: {event_id!r}")
        raise typer.Exit(1)

    # Print key fields to stderr for quick scan
    ts = event.get("timestamp")
    rule_name = (event.get("content") or {}).get("ruleName") or ""
    sev = event.get("severity") or ""
    output_text = (event.get("content") or {}).get("output") or ""
    print_info(f"Event: {rule_name}  severity={sev}  time={ts}")
    if output_text:
        print_info(f"  {output_text[:120]}")

    output(event, fmt=fmt, no_trunc=no_trunc)

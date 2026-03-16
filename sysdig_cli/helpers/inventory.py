"""
Inventory helper commands.
+diff: Show inventory changes (new/removed/changed resources) since a time window
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning
from ..timestamps import now_ns, parse_timestamp

inventory_helpers_app = typer.Typer(
    name="inventory-helpers",
    help="Inventory helper commands.",
    no_args_is_help=True,
)


@inventory_helpers_app.command("diff")
def inventory_diff(
    since: str = typer.Argument("1h", help="Time window or snapshot ID"),
    namespace: Optional[str] = typer.Option(None, "--namespace"),
    format: str = typer.Option("table", "--format", help="table|json"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Show inventory changes (new/removed/changed resources) since a time window."""
    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        from_ns = parse_timestamp(since)
    except ValueError as e:
        print_error(f"Invalid time window: {e}")
        raise typer.Exit(1)

    ns_label = f" in namespace '{namespace}'" if namespace else ""
    print_info(f"Fetching inventory diff since {since}{ns_label}...")

    to_ns = now_ns()

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []

    try:
        with SysdigClient(auth=auth) as client:
            params: Dict[str, Any] = {
                "limit": 1000,
                "from": from_ns,
                "to": to_ns,
            }
            if namespace:
                params["filter"] = f'kubernetes.namespace.name="{namespace}"'

            # Try to get current snapshot
            current_resp = client.get(
                "/api/cspm/v1/resourceInventory/resources",
                params=params,
            )
            _ = current_resp  # fetched for side-effects / future use

            # Try inventory change endpoint
            changes_resp = client.get(
                "/api/cspm/v1/resourceInventory/changes",
                params=params,
            )
            changes = (
                (changes_resp or {}).get("data") or
                (changes_resp or {}).get("changes") or
                []
            )

            for change in changes:
                change_type = change.get("changeType") or change.get("type") or ""
                resource = {
                    "name": change.get("resourceName") or change.get("name", ""),
                    "kind": change.get("resourceKind") or change.get("kind", ""),
                    "namespace": change.get("namespace", namespace or ""),
                    "timestamp": change.get("timestamp", ""),
                    "change_type": change_type,
                }
                if change_type.lower() in ("added", "created", "new"):
                    added.append(resource)
                elif change_type.lower() in ("removed", "deleted"):
                    removed.append(resource)
                else:
                    changed.append(resource)

    except (AuthError, ForbiddenError) as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))
    except SysdigError as e:
        print_warning(f"API error: {e} - inventory diff endpoint may not be available")

    result: Dict[str, Any] = {
        "inventory_diff": {
            "since": since,
            "namespace": namespace or "",
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
            },
        }
    }
    output(result, fmt=format)
    print_info(
        f"Inventory diff: +{len(added)} added, -{len(removed)} removed, ~{len(changed)} changed."
    )

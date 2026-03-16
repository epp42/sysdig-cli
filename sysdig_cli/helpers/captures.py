"""
Captures helper commands — via Response Actions API.
+list:    List recent capture executions
+trigger: Submit a new syscall capture from a running container
+status:  Get status/detail for a specific capture execution
+download: Download file from a file-acquire execution
+actions: Discover all available response action types and their parameters
"""
# ruff: noqa: C901
from __future__ import annotations

import sys
import time
from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning
from ..timestamps import now_ns, parse_timestamp

_BASE = "/secure/response-actions/v1alpha1"


def _resolve_auth(profile: str, region: Optional[str]):
    try:
        return resolve_auth(profile=profile or "default", region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)


def captures_list(
    from_time: str = typer.Option("24h", "--from", help="Start time: 1h, 24h, 7d, ISO8601"),
    to_time: Optional[str] = typer.Option(None, "--to", help="End time (default: now)"),
    status: Optional[str] = typer.Option(
        None, "--status", "-s",
        help="Filter by status: pending|running|succeeded|failed",
    ),
    limit: int = typer.Option(50, "--limit", "-n"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml"),
) -> None:
    """List recent capture and response-action executions.

    Shows all response action executions (capture, file_acquire, etc.) filtered
    to the requested time window. Use --status to narrow by execution state.

    Examples:
      sysdig captures list                      Last 24h executions
      sysdig captures list --from 7d            Last 7 days
      sysdig captures list --status succeeded   Completed captures only
      sysdig captures list --status failed      Failed captures
    """
    auth = _resolve_auth(profile, region)

    try:
        from_ns = parse_timestamp(from_time)
    except ValueError as e:
        print_error(f"Invalid --from: {e}")
        raise typer.Exit(1)

    to_ns = now_ns()
    if to_time:
        try:
            to_ns = parse_timestamp(to_time)
        except ValueError as e:
            print_error(f"Invalid --to: {e}")
            raise typer.Exit(1)

    params: Dict[str, Any] = {
        "limit": min(limit, 200),
        "from": from_ns,
        "to": to_ns,
    }

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.get(f"{_BASE}/action-executions", params=params)
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    executions: List[Dict[str, Any]] = (resp or {}).get("data", []) if resp else []

    if status:
        executions = [e for e in executions if (e.get("status") or "").lower() == status.lower()]

    # Flatten useful fields for table display
    rows = []
    for ex in executions:
        params_raw = ex.get("parameters") or {}
        rows.append({
            "id": ex.get("id") or "",
            "type": ex.get("actionType") or "",
            "status": ex.get("status") or "",
            "container": params_raw.get("containerId") or params_raw.get("containerName") or "",
            "duration": params_raw.get("durationSeconds") or params_raw.get("duration") or "",
            "created": ex.get("createdAt") or "",
            "updated": ex.get("updatedAt") or "",
            "failure": (ex.get("failure") or {}).get("failureReason") or "",
        })

    status_filter = f" [status={status}]" if status else ""
    print_info(f"{len(rows)} action executions in last {from_time}{status_filter}")
    output({"data": rows}, fmt=fmt, schema="captures_list")


def captures_trigger(
    container_id: str = typer.Argument(..., help="Container ID to capture from"),
    duration: int = typer.Option(10, "--duration", "-d", help="Capture duration in seconds"),
    filter_str: Optional[str] = typer.Option(
        None, "--filter", help="Falco filter expression (e.g. 'proc.name=nginx')"
    ),
    wait: bool = typer.Option(False, "--wait", "-w", help="Wait for capture to complete"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("json", "--format", "-f"),
) -> None:
    """Trigger a syscall capture from a running container.

    Submits a 'capture' response action. The container ID comes from
    'sysdig events list' or the Sysdig UI. Captured data is written to
    the configured capture storage (S3 bucket).

    Examples:
      sysdig captures trigger abc123def456           10s capture (default)
      sysdig captures trigger abc123 --duration 30   30s capture
      sysdig captures trigger abc123 --wait          Wait for completion
      sysdig captures trigger abc123 --filter 'proc.name=curl'
    """
    auth = _resolve_auth(profile, region)

    parameters: Dict[str, Any] = {
        "containerId": container_id,
        "durationSeconds": duration,
    }
    if filter_str:
        parameters["filterString"] = filter_str

    body: Dict[str, Any] = {
        "actionType": "capture",
        "parameters": parameters,
    }

    print_info(
        f"Triggering capture on container {container_id!r} "
        f"(duration={duration}s{', filter=' + repr(filter_str) if filter_str else ''})"
    )

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.post(f"{_BASE}/action-executions", json=body)

            if not resp:
                print_error("Empty response from API")
                raise typer.Exit(3)

            exec_id = resp.get("id") or ""
            status = resp.get("status") or "unknown"
            print_info(f"Execution ID: {exec_id}  status={status}")

            if wait and exec_id:
                print_info("Waiting for capture to complete...")
                resp = _poll_until_done(client, exec_id, timeout=duration + 30)
                status = resp.get("status") or status
                if status == "succeeded":
                    print_info(f"Capture completed successfully.")
                elif status == "failed":
                    reason = (resp.get("failure") or {}).get("failureReason") or ""
                    print_warning(f"Capture failed: {reason}")
                else:
                    print_info(f"Final status: {status}")

    except (AuthError, ForbiddenError, SysdigError) as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    output(resp, fmt=fmt)


def captures_status(
    execution_id: str = typer.Argument(..., help="Execution ID (from 'captures list' or 'captures trigger')"),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("json", "--format", "-f", help="json|yaml|table"),
) -> None:
    """Get status and detail for a specific capture/response-action execution.

    Example:
      sysdig captures status abc123-exec-id
    """
    auth = _resolve_auth(profile, region)

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.get(f"{_BASE}/action-executions/{execution_id}")
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    if not resp:
        print_error(f"Execution not found: {execution_id!r}")
        raise typer.Exit(1)

    status = resp.get("status") or "unknown"
    action_type = resp.get("actionType") or ""
    created = resp.get("createdAt") or ""
    failure = (resp.get("failure") or {}).get("failureReason") or ""

    print_info(f"Execution: {execution_id}  type={action_type}  status={status}  created={created}")
    if failure:
        print_warning(f"Failure reason: {failure}")

    output(resp, fmt=fmt)


def captures_download(
    execution_id: str = typer.Argument(..., help="Execution ID of a file-acquire action"),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save to file (default: print to stdout)"
    ),
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """Download the file from a file-acquire response action.

    NOTE: This endpoint is for 'file_acquire' actions, not syscall captures.
    Syscall captures are written directly to configured capture storage (S3).

    Example:
      sysdig captures download abc123-exec-id --output /tmp/acquired.bin
    """
    auth = _resolve_auth(profile, region)

    try:
        with SysdigClient(auth=auth) as client:
            # Use raw HTTP to stream binary response
            import requests
            url = f"{auth.host}{_BASE}/action-executions/{execution_id}/acquired-file"
            headers = {"Authorization": f"Bearer {auth.token}"}
            r = requests.get(url, headers=headers, stream=True, timeout=60)
            if r.status_code == 404:
                print_error(f"Execution not found or file not available: {execution_id!r}")
                raise typer.Exit(1)
            if r.status_code == 400:
                print_error(
                    "This execution is not a file-acquire action. "
                    "Only file_acquire executions have downloadable files."
                )
                raise typer.Exit(1)
            r.raise_for_status()

            if output_file:
                with open(output_file, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                size = sum(1 for _ in open(output_file, "rb").read()) if False else None
                print_info(f"File saved to: {output_file}")
            else:
                # Stream to stdout (binary-safe)
                for chunk in r.iter_content(chunk_size=8192):
                    sys.stdout.buffer.write(chunk)

    except ImportError:
        print_error("requests library not available")
        raise typer.Exit(3)
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))


def captures_actions(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml"),
) -> None:
    """List all available response action types and their parameters.

    Use this to discover what actions your environment supports and
    what parameters each action accepts.

    Example:
      sysdig captures actions
      sysdig captures actions --format json | jq '.data[] | select(.type=="capture")'
    """
    auth = _resolve_auth(profile, region)

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.get(f"{_BASE}/actions")
    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    actions: List[Dict[str, Any]] = (resp or {}).get("data", []) if resp else []

    # Flatten for table: one row per action, params as comma-separated list
    rows = []
    for a in actions:
        params = a.get("parameters") or []
        required_params = [p["name"] for p in params if p.get("required")]
        optional_params = [p["name"] for p in params if not p.get("required")]
        rows.append({
            "type": a.get("type") or "",
            "responder": a.get("responderType") or "",
            "description": (a.get("description") or "")[:80],
            "required_params": ", ".join(required_params),
            "optional_params": ", ".join(optional_params),
            "undoable": "yes" if a.get("isUndoable") else "",
        })

    print_info(f"{len(rows)} response action types available")
    output({"data": rows}, fmt=fmt, schema="captures_actions")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _poll_until_done(
    client: "SysdigClient",
    execution_id: str,
    timeout: int = 60,
    interval: int = 3,
) -> Dict[str, Any]:
    """Poll execution status until terminal state or timeout."""
    terminal = {"succeeded", "failed", "cancelled", "error"}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = client.get(f"{_BASE}/action-executions/{execution_id}")
            if resp and (resp.get("status") or "").lower() in terminal:
                return resp
        except SysdigError:
            pass
        time.sleep(interval)
    # Return last known state
    try:
        return client.get(f"{_BASE}/action-executions/{execution_id}") or {}
    except SysdigError:
        return {"id": execution_id, "status": "unknown"}

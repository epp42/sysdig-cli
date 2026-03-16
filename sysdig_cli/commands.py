"""
Dynamic command tree generated from OpenAPI spec.
Zero hardcoded per-endpoint handlers.
"""
# ruff: noqa: C901
from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

import typer
from click import Context

from .auth import AuthError as AuthConfigError
from .auth import resolve_auth
from .client import (
    APIError,
    AuthError,
    ForbiddenError,
    NotFoundError,
    SysdigClient,
    SysdigError,
    UsageError,
)
from .formatter import output, print_error, print_info, print_warning
from .paginator import stream_ndjson
from .spec import (
    SERVICE_MAP,
    extract_path_params,
    get_operations_for_service,
    load_spec,
)
from .timestamps import parse_timestamp
from .validator import check_dangerous_endpoint, validate_path_param


def _detect_schema(method: str, path: str) -> Optional[str]:
    """Detect a named display schema from the API path and method."""
    path_lower = path.lower()
    method_lower = method.lower()
    if "vulnerability" in path_lower and "runtime-results" in path_lower:
        return "vulns_runtime"
    if "events/v1/events" in path_lower:
        return "events"
    if "activity-audit" in path_lower:
        return "audit"
    if "zones" in path_lower and method_lower == "get":
        return "zones"
    if "users" in path_lower and method_lower == "get":
        return "users"
    if "teams" in path_lower and method_lower == "get":
        return "teams"
    return None


def _make_service_app(service_name: str, service_desc: str) -> typer.Typer:
    """Create a typer app for a service."""
    return typer.Typer(
        name=service_name,
        help=service_desc,
        no_args_is_help=True,
    )


def _convert_param_type(schema: Dict[str, Any]) -> Any:
    """Convert OpenAPI schema type to Python/typer type."""
    t = schema.get("type", "string")

    if t == "integer" or t == "number":
        return Optional[int]
    if t == "boolean":
        return Optional[bool]
    return Optional[str]


def _get_param_default(schema: Dict[str, Any]) -> Any:
    """Get default value for a parameter."""
    return schema.get("default")


def _slugify(name: str) -> str:
    """Convert a name to a valid Python identifier."""
    # Replace non-alphanumeric with underscore
    name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    # Remove leading digits
    if name and name[0].isdigit():
        name = "p_" + name
    return name


def _path_to_subcommand(path: str, method: str, service: str) -> str:
    """Generate a CLI subcommand name from path + method."""
    prefixes = SERVICE_MAP.get(service, [])

    # Strip service prefix
    stripped = path
    for prefix in sorted(prefixes, key=len, reverse=True):
        if path.startswith(prefix):
            stripped = path[len(prefix):]
            break

    # Remove version segments
    stripped = re.sub(r"^/v\d+[a-z0-9]*/", "/", stripped)
    stripped = re.sub(r"^/v\d+[a-z0-9]*$", "", stripped)

    # Remove path parameters (e.g., /{id})
    resource_path = re.sub(r"/\{[^}]+\}", "", stripped)
    resource_path = resource_path.strip("/").replace("/", "-").replace("_", "-")
    resource_path = re.sub(r"-+", "-", resource_path).strip("-")

    # Has path params?
    has_id_param = bool(re.search(r"\{[^}]+\}", stripped))

    # Map method to verb
    method_verbs = {
        "get": "get" if has_id_param else "list",
        "post": "create",
        "put": "update",
        "delete": "delete",
        "patch": "patch",
    }
    verb = method_verbs.get(method.lower(), method.lower())

    if resource_path:
        return f"{resource_path}-{verb}"
    return verb


def _build_command_for_operation(
    service: str,
    path: str,
    method: str,
    operation: Dict[str, Any],
) -> Tuple[str, Callable]:
    """Build a typer command function for a single API operation."""

    parameters = operation.get("parameters", [])
    request_body = operation.get("request_body")
    summary = operation.get("summary", "")
    path_params = extract_path_params(path)
    is_mutating = method.upper() in ("POST", "PUT", "DELETE", "PATCH")

    cmd_name = _path_to_subcommand(path, method, service)

    # Build the function docstring
    help_text = summary or f"{method.upper()} {path}"

    def command_fn(
        ctx: Context,
        # We'll add params dynamically below - using **kwargs pattern
        profile: str = typer.Option("default", "--profile", help="Auth profile to use"),
        region: Optional[str] = typer.Option(None, "--region", help="Region: us2/us4/eu1/au1"),
        fmt: str = typer.Option("json", "--format", "-f", help="Output format: json/table/yaml/ndjson/csv"),
        page_all: bool = typer.Option(False, "--page-all", help="Fetch all pages (streams NDJSON)"),
        limit: Optional[int] = typer.Option(None, "--limit", help="Items per page"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print what would be sent without executing"),
        _path: str = path,
        _method: str = method,
        _service: str = service,
        _parameters: List[Dict] = parameters,
        _path_params: List[str] = path_params,
        _is_mutating: bool = is_mutating,
        _request_body_schema: Optional[Dict] = request_body,
        **kwargs: Any,
    ) -> None:
        try:
            auth = resolve_auth(profile=profile, region=region)
        except AuthConfigError as e:
            print_error(str(e))
            raise typer.Exit(2)

        # Build path with substituted params
        actual_path = _path
        for pp in _path_params:
            val = kwargs.get(pp) or kwargs.get(_slugify(pp))
            if val is None:
                print_error(f"Missing required path parameter: {pp}")
                raise typer.Exit(1)
            try:
                val = validate_path_param(pp, str(val))
            except Exception as ve:
                print_error(str(ve))
                raise typer.Exit(1)
            actual_path = actual_path.replace(f"{{{pp}}}", val)

        # Build query params
        query_params: Dict[str, Any] = {}
        for param in _parameters:
            p_name = param.get("name", "")
            p_in = param.get("in", "")
            if p_in != "query":
                continue
            val = kwargs.get(p_name) or kwargs.get(_slugify(p_name))
            if val is not None:
                query_params[p_name] = val

        # Build body from --body JSON
        json_body = None
        body_str = kwargs.get("body")
        if body_str:
            try:
                json_body = json.loads(body_str)
            except json.JSONDecodeError as e:
                print_error(f"Invalid JSON body: {e}")
                raise typer.Exit(1)

        check_dangerous_endpoint(actual_path, _method)

        if _is_mutating and dry_run:
            dry_info = {
                "dry_run": True,
                "method": _method.upper(),
                "url": f"{auth.host}{actual_path}",
                "params": query_params,
                "body": json_body,
            }
            print(json.dumps(dry_info, indent=2))
            raise typer.Exit(0)

        try:
            with SysdigClient(auth=auth, dry_run=dry_run) as client:
                if page_all:
                    count = stream_ndjson(
                        client, _method, actual_path,
                        params=query_params,
                        json_body=json_body,
                        limit=limit,
                    )
                    print_info(f"Total items streamed: {count}")
                else:
                    if limit is not None:
                        query_params["limit"] = limit
                    response = client.request(
                        _method, actual_path,
                        params=query_params,
                        json_body=json_body,
                    )
                    if response is not None:
                        output(response, fmt=fmt)

        except AuthError as e:
            print_error(f"Authentication failed: {e}")
            raise typer.Exit(2)
        except ForbiddenError as e:
            print_error(f"Forbidden: {e}")
            raise typer.Exit(5)
        except NotFoundError as e:
            print_error(f"Not found: {e}")
            raise typer.Exit(4)
        except UsageError as e:
            print_error(f"Bad request: {e}")
            raise typer.Exit(1)
        except APIError as e:
            print_error(f"API error: {e}")
            raise typer.Exit(3)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(e.exit_code)

    # Set function metadata
    command_fn.__name__ = _slugify(cmd_name)
    command_fn.__doc__ = help_text

    return cmd_name, command_fn


def build_service_app(service_name: str) -> typer.Typer:
    """Build a complete typer app for a service with all its operations."""
    spec = load_spec()
    operations = get_operations_for_service(service_name, spec)

    service_descs = {
        "vulns": "Vulnerability management",
        "events": "Security events",
        "audit": "Activity audit",
        "inventory": "Inventory resources",
        "actions": "Response actions",
        "platform": "Platform management",
        "zones": "Zone management",
        "teams": "Team management",
        "users": "User management",
        "roles": "Role management",
        "alerts": "Alert management",
        "metrics": "Prometheus metrics",
        "sysql": "SysQL queries",
        "fwd": "Events forwarder",
        "cost": "Cost advisor",
    }

    desc = service_descs.get(service_name, f"Sysdig {service_name} commands")
    app = typer.Typer(
        name=service_name,
        help=desc,
        no_args_is_help=True,
    )

    # Track used command names to avoid duplicates
    used_names: Dict[str, int] = {}

    for op in operations:
        path = op["path"]
        method = op["method"]
        parameters = op["parameters"]
        path_params = extract_path_params(path)
        is_mutating = method.upper() in ("POST", "PUT", "DELETE", "PATCH")

        cmd_name = _path_to_subcommand(path, method, service_name)

        # Deduplicate
        if cmd_name in used_names:
            used_names[cmd_name] += 1
            cmd_name = f"{cmd_name}-{used_names[cmd_name]}"
        else:
            used_names[cmd_name] = 0

        _register_command(
            app, service_name, path, method, op, cmd_name,
            parameters, path_params, is_mutating
        )

    return app


def _register_command(
    app: typer.Typer,
    service_name: str,
    path: str,
    method: str,
    operation: Dict[str, Any],
    cmd_name: str,
    parameters: List[Dict],
    path_params: List[str],
    is_mutating: bool,
) -> None:
    """Register a single command with the typer app."""

    # Build params for the command
    # We use a factory to capture loop variables
    summary = operation.get("summary", f"{method.upper()} {path}")

    # Build annotations dict for dynamic function
    # We need to create a function that accepts the right CLI params

    # Collect query parameter names for this operation
    query_param_names = [
        p["name"] for p in parameters
        if p.get("in") == "query"
    ]

    def make_cmd(
        _path=path,
        _method=method,
        _service=service_name,
        _parameters=parameters,
        _path_params=path_params,
        _is_mutating=is_mutating,
        _request_body=operation.get("request_body"),
        _summary=summary,
        _query_param_names=query_param_names,
    ):
        def cmd(
            # Common options
            profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
            region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
            fmt: str = typer.Option("json", "--format", "-f", help="Output: json/table/yaml/ndjson/csv"),
            page_all: bool = typer.Option(False, "--page-all", help="Fetch all pages (NDJSON stream)"),
            limit: Optional[int] = typer.Option(None, "--limit", "-n", help="Items per page"),
            dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be sent, no execution"),
            watch: Optional[int] = typer.Option(None, "--watch", "-w", help="Refresh every N seconds (e.g. --watch 5)"),
            # Path params as positional args - we handle them via --param style
            param_id: Optional[str] = typer.Argument(None, help="Resource ID (for get/update/delete)"),
            # Query params and body
            filter: Optional[str] = typer.Option(None, "--filter", help="Filter expression"),
            sort: Optional[str] = typer.Option(None, "--sort", help="Sort field"),
            order: Optional[str] = typer.Option(None, "--order", help="Sort order: asc/desc"),
            cursor: Optional[str] = typer.Option(None, "--cursor", help="Pagination cursor"),
            body: Optional[str] = typer.Option(None, "--body", "-b", help="JSON request body"),
            from_time: Optional[str] = typer.Option(None, "--from", help="Start time (e.g. 1h, 30m, ISO8601)"),
            to_time: Optional[str] = typer.Option(None, "--to", help="End time (default: now)"),
            # Extra params as key=value
            param: Optional[List[str]] = typer.Option(None, "--param", help="Extra params as key=value"),
        ) -> None:
            try:
                auth = resolve_auth(profile=profile, region=region)
            except AuthConfigError as e:
                print_error(str(e))
                raise typer.Exit(2)

            # Build path with substituted params
            actual_path = _path
            for i, pp in enumerate(_path_params):
                # First path param maps to param_id, rest need --param
                if i == 0 and param_id is not None:
                    val = param_id
                else:
                    # Try to get from --param key=value
                    val = _find_extra_param(param or [], pp)
                    if val is None:
                        print_error(f"Missing required path parameter: {pp!r}. Use positional arg or --param {pp}=<value>")
                        raise typer.Exit(1)
                try:
                    val = validate_path_param(pp, str(val))
                except Exception as ve:
                    print_error(str(ve))
                    raise typer.Exit(1)
                actual_path = actual_path.replace(f"{{{pp}}}", val)

            # Build query params
            query_params: Dict[str, Any] = {}
            if filter is not None:
                query_params["filter"] = filter
            if sort is not None:
                query_params["sort"] = sort
            if order is not None:
                query_params["order"] = order
            if cursor is not None:
                query_params["cursor"] = cursor

            # Handle time params - convert to nanoseconds
            if from_time is not None:
                try:
                    query_params["from"] = parse_timestamp(from_time)
                except ValueError as e:
                    print_error(f"Invalid --from value: {e}")
                    raise typer.Exit(1)
            if to_time is not None:
                try:
                    query_params["to"] = parse_timestamp(to_time)
                except ValueError as e:
                    print_error(f"Invalid --to value: {e}")
                    raise typer.Exit(1)
            # If --from set but --to not set, auto-add to=now (required by events/audit APIs)
            if "from" in query_params and "to" not in query_params:
                import time as _time
                query_params["to"] = int(_time.time() * 1e9)

            # Extra --param key=value pairs
            for kv in (param or []):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    query_params[k.strip()] = v.strip()
                else:
                    print_warning(f"Ignoring invalid --param format (expected key=value): {kv!r}")

            # Body from --body JSON
            json_body = None
            if body:
                try:
                    json_body = json.loads(body)
                except json.JSONDecodeError as e:
                    print_error(f"Invalid JSON in --body: {e}")
                    raise typer.Exit(1)

            check_dangerous_endpoint(actual_path, _method)

            if _is_mutating and dry_run:
                dry_info = {
                    "dry_run": True,
                    "method": _method.upper(),
                    "url": f"{auth.host}{actual_path}",
                    "params": query_params,
                    "body": json_body,
                }
                print(json.dumps(dry_info, indent=2))
                raise typer.Exit(0)

            _schema = _detect_schema(_method, actual_path)

            def _do_request_and_output(qp: Dict[str, Any]) -> None:
                with SysdigClient(auth=auth, dry_run=dry_run) as client:
                    if page_all:
                        count = stream_ndjson(
                            client, _method, actual_path,
                            params=qp,
                            json_body=json_body,
                            limit=limit,
                        )
                        print_info(f"Total items streamed: {count}")
                    else:
                        if limit is not None:
                            qp["limit"] = limit
                        response = client.request(
                            _method, actual_path,
                            params=qp,
                            json_body=json_body,
                        )
                        if response is not None:
                            output(response, fmt=fmt, schema=_schema)

            try:
                if watch:
                    import time as _time
                    from rich.live import Live
                    from .formatter import format_table
                    _watch_fmt = "table" if fmt in ("table", "json") else fmt

                    if _watch_fmt == "table":
                        with Live(refresh_per_second=1) as live:
                            while True:
                                try:
                                    with SysdigClient(auth=auth, dry_run=dry_run) as client:
                                        if limit is not None:
                                            query_params["limit"] = limit
                                        response = client.request(
                                            _method, actual_path,
                                            params=query_params,
                                            json_body=json_body,
                                        )
                                        if response is not None:
                                            rich_table = format_table(response, schema=_schema, return_rich=True)
                                            live.update(rich_table)
                                except SysdigError as _we:
                                    pass
                                _time.sleep(watch)
                    else:
                        while True:
                            try:
                                _do_request_and_output(dict(query_params))
                            except SysdigError as _we:
                                pass
                            _time.sleep(watch)
                else:
                    _do_request_and_output(query_params)

            except AuthError as e:
                print_error(f"Authentication failed: {e}")
                raise typer.Exit(2)
            except ForbiddenError as e:
                print_error(f"Forbidden: {e}")
                raise typer.Exit(5)
            except NotFoundError as e:
                print_error(f"Not found: {e}")
                raise typer.Exit(4)
            except UsageError as e:
                print_error(f"Bad request: {e}")
                raise typer.Exit(1)
            except APIError as e:
                print_error(f"API error: {e}")
                raise typer.Exit(3)
            except SysdigError as e:
                print_error(str(e))
                raise typer.Exit(getattr(e, 'exit_code', 3))

        cmd.__name__ = _slugify(cmd_name)
        cmd.__doc__ = _summary
        return cmd

    def _find_extra_param(params: List[str], name: str) -> Optional[str]:
        for kv in params:
            if "=" in kv:
                k, v = kv.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    fn = make_cmd()
    app.command(name=cmd_name, help=summary)(fn)

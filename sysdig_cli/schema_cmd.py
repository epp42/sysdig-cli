"""
Schema inspection commands.
sysdig schema <path> shows endpoint parameters + response schema.
"""
# ruff: noqa: C901
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

import click
import typer
import yaml

from .spec import get_paths, load_spec


class SchemaGroup(typer.core.TyperGroup):
    """Custom command group that handles paths starting with / as schema show."""

    def resolve_command(self, ctx: click.Context, args: list):
        # If first arg looks like an API path (starts with /), route to 'show'
        if args and isinstance(args[0], str) and args[0].startswith("/"):
            cmd = self.commands.get("show")
            if cmd:
                return "show", cmd, args
        return super().resolve_command(ctx, args)


app = typer.Typer(
    name="schema",
    help="Inspect API schema for any endpoint path.",
    no_args_is_help=True,
    cls=SchemaGroup,
)


def _format_schema_type(schema: Dict[str, Any]) -> str:
    """Format a schema object as a readable type string."""
    if not schema:
        return "any"

    t = schema.get("type", "")
    fmt = schema.get("format", "")
    ref = schema.get("$ref", "")

    if ref:
        return ref.split("/")[-1]
    if fmt:
        return f"{t}({fmt})" if t else fmt
    if t == "array":
        items = schema.get("items", {})
        inner = _format_schema_type(items)
        return f"array[{inner}]"
    if t == "object":
        props = schema.get("properties", {})
        if props:
            return f"object{{{', '.join(list(props.keys())[:5])}}}"
        return "object"
    return t or "any"


def _print_parameter(param: Dict[str, Any]) -> None:
    """Print a single parameter description."""
    name = param.get("name", "?")
    location = param.get("in", "?")
    required = param.get("required", False)
    desc = param.get("description", "")
    schema = param.get("schema", {})
    type_str = _format_schema_type(schema)
    default = schema.get("default")
    enum_vals = schema.get("enum", [])

    req_str = "[required]" if required else "[optional]"
    default_str = f" (default: {default})" if default is not None else ""
    enum_str = f" (enum: {', '.join(str(e) for e in enum_vals[:5])})" if enum_vals else ""

    print(f"  {name} ({location}) {req_str}: {type_str}{default_str}{enum_str}")
    if desc:
        # Truncate long descriptions
        short_desc = desc.split("\n")[0][:120]
        print(f"    → {short_desc}")


def _print_schema_summary(schema: Dict[str, Any], indent: int = 0) -> None:
    """Print a schema summary."""
    prefix = "  " * indent
    if not schema:
        print(f"{prefix}(empty schema)")
        return

    t = schema.get("type", "")
    if t == "object":
        props = schema.get("properties", {})
        required_fields = schema.get("required", [])
        print(f"{prefix}object:")
        for prop_name, prop_schema in list(props.items())[:20]:
            req = " [required]" if prop_name in required_fields else ""
            type_str = _format_schema_type(prop_schema)
            desc = prop_schema.get("description", "")[:60]
            print(f"{prefix}  {prop_name}{req}: {type_str}  {desc}")
        if len(props) > 20:
            print(f"{prefix}  ... ({len(props) - 20} more fields)")
    elif t == "array":
        items = schema.get("items", {})
        print(f"{prefix}array of:")
        _print_schema_summary(items, indent + 1)
    else:
        type_str = _format_schema_type(schema)
        print(f"{prefix}{type_str}")


@app.command("show")
def schema_show(
    path: str = typer.Argument(
        ..., help="API path to inspect, e.g. /secure/vulnerability/v1/policies"
    ),
    method: str = typer.Option(
        "GET", "--method", "-m", help="HTTP method to show"
    ),
    fmt: str = typer.Option(
        "text", "--format", "-f", help="Output format: text, json, yaml"
    ),
) -> None:
    """Show parameters and schema for an API endpoint."""
    spec = load_spec()
    paths = get_paths(spec)

    if path not in paths:
        # Try fuzzy match
        matches = [p for p in paths.keys() if path.lower() in p.lower()]
        if matches:
            print(f"Path {path!r} not found. Similar paths:", file=sys.stderr)
            for m in matches[:10]:
                print(f"  {m}", file=sys.stderr)
        else:
            print(f"Path {path!r} not found in spec.", file=sys.stderr)
            print(f"Total paths in spec: {len(paths)}", file=sys.stderr)
        raise typer.Exit(4)

    path_item = paths[path]
    method_lower = method.lower()

    if method_lower not in path_item:
        available = [m.upper() for m in path_item.keys()
                     if m in ("get", "post", "put", "delete", "patch")]
        print(
            f"Method {method.upper()} not available for {path}. "
            f"Available: {', '.join(available)}",
            file=sys.stderr,
        )
        raise typer.Exit(1)

    operation = path_item[method_lower]

    if fmt == "json":
        print(json.dumps(operation, indent=2, default=str))
        return
    if fmt == "yaml":
        print(yaml.dump(operation, default_flow_style=False))
        return

    # Text format
    print(f"\n{'='*60}")
    print(f"  {method.upper()} {path}")
    print(f"{'='*60}")
    print(f"  Summary: {operation.get('summary', 'N/A')}")
    print(f"  Operation ID: {operation.get('operationId', 'N/A')}")
    desc = operation.get("description", "")
    if desc:
        short = desc.split("\n")[0][:200]
        print(f"  Description: {short}")

    # Parameters
    parameters = operation.get("parameters", [])
    if parameters:
        print(f"\n  Parameters ({len(parameters)}):")
        for param in parameters:
            _print_parameter(param)

    # Request body
    request_body = operation.get("requestBody")
    if request_body:
        print("\n  Request Body:")
        required = request_body.get("required", False)
        print(f"    Required: {required}")
        content = request_body.get("content", {})
        for media_type, media_schema in content.items():
            print(f"    Content-Type: {media_type}")
            schema = media_schema.get("schema", {})
            _print_schema_summary(schema, indent=2)

    # Responses
    responses = operation.get("responses", {})
    if responses:
        print("\n  Responses:")
        for status_code, response_obj in responses.items():
            desc = response_obj.get("description", "")
            print(f"    {status_code}: {desc}")
            content = response_obj.get("content", {})
            for media_type, media_schema in content.items():
                schema = media_schema.get("schema", {})
                if schema:
                    _print_schema_summary(schema, indent=3)

    print()


@app.command("list")
def schema_list(
    prefix: Optional[str] = typer.Argument(
        None, help="Filter paths by prefix"
    ),
) -> None:
    """List all available API paths."""
    spec = load_spec()
    paths = get_paths(spec)

    filtered = list(paths.keys())
    if prefix:
        filtered = [p for p in filtered if p.startswith(prefix)]

    filtered.sort()
    for p in filtered:
        methods = [m.upper() for m in paths[p].keys()
                   if m in ("get", "post", "put", "delete", "patch")]
        print(f"  {', '.join(methods):20} {p}")

    print(f"\nTotal: {len(filtered)} paths", file=sys.stderr)


@app.callback(invoke_without_command=True)
def schema_main(
    ctx: typer.Context,
) -> None:
    """Inspect API schema for endpoints.

    Use: sysdig schema /path/to/endpoint
    Or:  sysdig schema show /path/to/endpoint
    Or:  sysdig schema list [prefix]
    """
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())

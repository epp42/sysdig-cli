"""
SysQL helper commands.
+list: List available SysQL query templates
+run: Run a pre-built SysQL investigation query template
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning

sysql_helpers_app = typer.Typer(
    name="sysql-helpers",
    help="SysQL helper commands.",
    no_args_is_help=True,
)


TEMPLATES: Dict[str, str] = {
    "kube-nodes": (
        "MATCH KubeNode AS n "
        "RETURN n.name, n.clusterName, n.version, n.operatingSystem "
        "LIMIT 50;"
    ),
    "kube-workloads": (
        "MATCH KubeWorkload AS w "
        "RETURN w.name, w.namespace, w.clusterName, w.kind "
        "ORDER BY w.clusterName ASC LIMIT 50;"
    ),
    "packages-with-vulns": (
        "MATCH Package AS p "
        "RETURN p.name, p.version, p.type "
        "LIMIT 50;"
    ),
    "runtime-events": (
        "MATCH RuntimeEvent AS e "
        "RETURN e.name, e.severity, e.hostName "
        "ORDER BY e.severity DESC LIMIT 50;"
    ),
    "identities": (
        "MATCH Identity AS i "
        "RETURN i.name, i.type "
        "LIMIT 50;"
    ),
}


@sysql_helpers_app.command("list")
def sysql_templates_list(
    fmt: str = typer.Option("table", "--format", "-f", help="Output: json/table/yaml"),
) -> None:
    """List available SysQL query templates."""
    templates_list = [
        {"name": name, "query_preview": query[:80] + ("..." if len(query) > 80 else "")}
        for name, query in TEMPLATES.items()
    ]
    result = {
        "templates": templates_list,
        "total": len(templates_list),
    }
    output(result, fmt=fmt)
    print_info(f"Available templates: {', '.join(TEMPLATES.keys())}")


@sysql_helpers_app.command("run")
def sysql_templates_run(
    template: str = typer.Argument(..., help="Template name"),
    var: Optional[List[str]] = typer.Option(None, "--var", help="Variables: key=value"),
    format: str = typer.Option("table", "--format"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Run a pre-built SysQL investigation query template."""
    if template not in TEMPLATES:
        print_error(
            f"Unknown template '{template}'. Available: {', '.join(TEMPLATES.keys())}"
        )
        raise typer.Exit(1)

    query = TEMPLATES[template]

    # Apply variable substitutions
    if var:
        for v in var:
            if "=" not in v:
                print_error(f"Invalid --var format: {v!r}. Expected key=value")
                raise typer.Exit(1)
            key, _, value = v.partition("=")
            query = query.replace(f"{{{key}}}", value)

    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    print_info(f"Running SysQL template '{template}'...")
    print_info(f"Query: {query[:100]}{'...' if len(query) > 100 else ''}")

    results: List[Any] = []
    error_msg: Optional[str] = None

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.post(
                "/api/sysql/v2/query",
                json_body={"query": query},
            )
            results = (resp or {}).get("items") or (resp or {}).get("data") or []

    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        error_msg = str(e)
        print_warning(f"API error: {e} - query may not be supported on this cluster")

    result: Dict[str, Any] = {
        "template": template,
        "query": query,
        "result_count": len(results),
        "results": results,
    }
    if error_msg:
        result["api_error"] = error_msg

    output(result, fmt=format)
    print_info(f"Template '{template}' returned {len(results)} results.")

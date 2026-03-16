"""
Sysdig CLI - Main entry point.
All commands generated from OpenAPI spec.
"""
# ruff: noqa: E402
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .commands import build_service_app
from .formatter import print_error
from .spec import SERVICE_MAP

_console = Console(highlight=False)

_EXAMPLES = """\
 [bold]Examples[/bold]

   [cyan]sysdig vulns list --severity critical[/cyan]           Critical-only workloads
   [cyan]sysdig vulns list --cve CVE-2023-44487[/cyan]          All workloads with this CVE
   [cyan]sysdig vulns list --reachable --cloud aws[/cyan]       Reachable vulns on AWS
   [cyan]sysdig events list --from 24h --severity 7[/cyan]      Critical events last 24h
   [cyan]sysdig events list --rule "Drift" --container nginx[/cyan]  Drift events in nginx
   [cyan]sysdig audit recent-commands[/cyan]                    Last 24h activity log
   [cyan]sysdig audit platform-events --from 7d[/cyan]          Platform logins & changes
   [cyan]sysdig auth setup[/cyan]                               Configure credentials

   [dim]Pipe:  sysdig vulns list --format json | jq '.data[].mainAssetName'[/dim]
   [dim]Pipe:  sysdig events list --from 24h --format ndjson | grep -i shell[/dim]
"""

# Create main app
app = typer.Typer(
    name="sysdig",
    help="Sysdig Platform Security CLI  ·  v0.1-alpha  ·  by sergej epp",
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=True,
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit.", is_eager=True
    ),
) -> None:
    """Sysdig Platform Security CLI."""
    if version:
        typer.echo(f"sysdig-cli {__version__}")
        raise typer.Exit(0)

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        _console.print(_EXAMPLES)


# ---- Register service sub-apps from OpenAPI spec ----

_service_apps: dict = {}
for _svc in SERVICE_MAP:
    _svc_app = build_service_app(_svc)
    _service_apps[_svc] = _svc_app
    app.add_typer(_svc_app, name=_svc)


# ---- Auth management commands ----

auth_app = typer.Typer(
    name="auth",
    help="Manage authentication profiles and credentials.",
    no_args_is_help=True,
)
app.add_typer(auth_app, name="auth")


@auth_app.command("setup")
def auth_setup(
    profile: str = typer.Option("default", "--profile", "-p", help="Profile name to configure"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Sysdig API token"),
    host: str = typer.Option(
        "https://us2.app.sysdig.com", "--host", help="Sysdig host URL (must be https://)"
    ),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
) -> None:
    """Configure a Sysdig authentication profile."""
    from .auth import REGION_HOSTS, setup_profile
    from .auth import AuthError as AuthConfigError

    if region:
        if region not in REGION_HOSTS:
            print_error(f"Unknown region {region!r}. Valid: {', '.join(REGION_HOSTS)}")
            raise typer.Exit(1)
        host = REGION_HOSTS[region]

    if not token:
        import getpass
        try:
            token = getpass.getpass(f"Sysdig API Token for profile '{profile}': ").strip()
        except (EOFError, KeyboardInterrupt):
            print_error("No token provided.")
            raise typer.Exit(1)

    if not token:
        print_error("Token cannot be empty.")
        raise typer.Exit(1)

    try:
        setup_profile(profile=profile, token=token, host=host)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(1)

    _stderr_console.print(
        f"[green]Profile '{profile}' configured successfully.[/green]",
    )
    _stderr_console.print(f"  Host: {host}")
    _stderr_console.print("  Config: ~/.sysdig/config.yaml")


@auth_app.command("list")
def auth_list(
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: json/table/yaml"),
) -> None:
    """List all configured authentication profiles."""
    from .auth import list_profiles
    from .formatter import output

    profiles = list_profiles()
    if not profiles:
        _stderr_console.print("[yellow]No profiles configured. Run 'sysdig auth setup'[/yellow]")
        raise typer.Exit(0)

    output(profiles, fmt=fmt)


@auth_app.command("delete")
def auth_delete(
    profile: str = typer.Argument(..., help="Profile name to delete"),
) -> None:
    """Delete an authentication profile."""
    from .auth import delete_profile

    deleted = delete_profile(profile)
    if deleted:
        _stderr_console.print(
            f"[green]Profile '{profile}' deleted.[/green]"
        )
    else:
        print_error(f"Profile '{profile}' not found.")
        raise typer.Exit(1)


@auth_app.command("whoami")
def auth_whoami(
    profile: str = typer.Option("default", "--profile", "-p", help="Profile to check"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region override"),
) -> None:
    """Show current authentication configuration."""
    import json

    from .auth import AuthError as AuthConfigError
    from .auth import resolve_auth

    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    token_preview = auth.token[:4] + "****" if len(auth.token) > 4 else "****"
    info = {
        "profile": auth.profile,
        "host": auth.host,
        "token": token_preview,
    }
    print(json.dumps(info, indent=2))


# ---- Schema inspection ----

from .schema_cmd import app as schema_app

app.add_typer(schema_app, name="schema")


# ---- Vulns helper commands ----

@_service_apps["vulns"].command("list-critical")
def vulns_list_critical(
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: json/table/yaml"),
    limit: int = typer.Option(100, "--limit", "-n", help="Max results"),
    filter: Optional[str] = typer.Option(None, "--filter", help="Additional filter expression"),
) -> None:
    """List runtime results with critical vulnerabilities."""
    from .helpers.vulns import list_critical
    list_critical(profile=profile, region=region, fmt=fmt, limit=limit, filter=filter)


@_service_apps["vulns"].command("scan-summary")
def vulns_scan_summary(
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|json|yaml"),
) -> None:
    """Summarize vulnerability counts by severity across all runtime results."""
    from .helpers.vulns import scan_summary
    scan_summary(profile=profile, region=region, fmt=fmt)


# ---- Events helper commands ----

@_service_apps["events"].command("tail")
def events_tail(
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
    interval: int = typer.Option(10, "--interval", "-i", help="Poll interval in seconds"),
    fmt: str = typer.Option("ndjson", "--format", "-f", help="Output format: ndjson/json"),
    filter: Optional[str] = typer.Option(None, "--filter", help="Filter expression"),
    limit: int = typer.Option(100, "--limit", "-n", help="Events per poll"),
) -> None:
    """Poll for new security events and stream to stdout. Ctrl+C to stop."""
    from .helpers.events import tail
    tail(profile=profile, region=region, interval=interval, fmt=fmt, filter=filter, limit=limit)


@_service_apps["events"].command("hunt")
def events_hunt(
    ioc: str = typer.Argument(..., help="IOC or keyword to search for"),
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json/table/yaml/ndjson"),
    from_time: Optional[str] = typer.Option(None, "--from", help="Start time (e.g. 24h, 1h, ISO8601)"),
    limit: int = typer.Option(200, "--limit", "-n", help="Max events to scan (API max: 200)"),
) -> None:
    """Hunt for events matching a keyword or IOC pattern."""
    from .helpers.events import hunt
    hunt(ioc=ioc, profile=profile, region=region, fmt=fmt, from_time=from_time, limit=limit)


# -- events list and id (registered after service apps) --
from .helpers.events import events_id as _events_id_fn, events_list as _events_list_fn  # noqa: E402

_service_apps["events"].command("list")(_events_list_fn)
_service_apps["events"].command("id")(_events_id_fn)


# ---- Audit helper commands ----

@_service_apps["audit"].command("recent-commands")
def audit_recent_commands(
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region: us2/us4/eu1/au1"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: json/table/yaml"),
    from_time: str = typer.Option("24h", "--from", help="Start time: 1h, 24h, 7d, ISO8601"),
    limit: int = typer.Option(100, "--limit", "-n", help="Number of entries"),
    user: Optional[str] = typer.Option(None, "--user", help="Filter by username"),
    all_pages: bool = typer.Option(False, "--all", help="Stream ALL pages via cursor pagination (outputs ndjson)"),
) -> None:
    """Show recent commands from the activity audit log."""
    from .helpers.audit import recent_commands
    recent_commands(profile=profile, region=region, fmt=fmt, limit=limit, user=user, all_pages=all_pages, from_time=from_time)


# ---- Register new helper commands directly on service apps ----

# -- vulns helpers --
from .helpers.vulns import (  # noqa: E402
    vulns_coverage_report,
    vulns_high_reachable,
    vulns_id,
    vulns_list,
    vulns_new,
    vulns_overview,
    vulns_pod_vulns,
    vulns_reachable,
    vulns_risk_digest,
    vulns_sbom_diff,
    vulns_weekly_report,
    vulns_zone_comparison,
)

_service_apps["vulns"].command("weekly-report")(vulns_weekly_report)
_service_apps["vulns"].command("zone-comparison")(vulns_zone_comparison)
_service_apps["vulns"].command("sbom-diff")(vulns_sbom_diff)
_service_apps["vulns"].command("coverage-report")(vulns_coverage_report)
_service_apps["vulns"].command("risk-digest")(vulns_risk_digest)
_service_apps["vulns"].command("overview")(vulns_overview)
_service_apps["vulns"].command("reachable")(vulns_reachable)
_service_apps["vulns"].command("high-reachable")(vulns_high_reachable)
_service_apps["vulns"].command("pod-vulns")(vulns_pod_vulns)
_service_apps["vulns"].command("new")(vulns_new)
_service_apps["vulns"].command("list")(vulns_list)
_service_apps["vulns"].command("id")(vulns_id)

# -- vulns accept-risks --
from .helpers.vulns import vulns_accept_risks_list, vulns_accept_risks_create, vulns_accept_risks_delete  # noqa: E402

_vulns_accept_risks_app = typer.Typer(name="accept-risks", help="Manage accepted vulnerability risks.", no_args_is_help=True)
_service_apps["vulns"].add_typer(_vulns_accept_risks_app, name="accept-risks")
_vulns_accept_risks_app.command("list")(vulns_accept_risks_list)
_vulns_accept_risks_app.command("create")(vulns_accept_risks_create)
_vulns_accept_risks_app.command("delete")(vulns_accept_risks_delete)

# -- audit helpers --
from .helpers.audit import (  # noqa: E402
    audit_compliance_export,
    audit_incident_timeline,
)

_service_apps["audit"].command("compliance-export")(audit_compliance_export)
_service_apps["audit"].command("incident-timeline")(audit_incident_timeline)

# -- users helpers (users app from service map or create new) --
from .helpers.users import users_access_review  # noqa: E402

if "users" in _service_apps:
    _service_apps["users"].command("access-review")(users_access_review)
else:
    _users_app = typer.Typer(name="users", help="Users commands.", no_args_is_help=True)
    _service_apps["users"] = _users_app
    app.add_typer(_users_app, name="users")
    _users_app.command("access-review")(users_access_review)

# -- alerts helpers --
from .helpers.alerts import alerts_noise_report  # noqa: E402

if "alerts" in _service_apps:
    _service_apps["alerts"].command("noise-report")(alerts_noise_report)
else:
    _alerts_app = typer.Typer(name="alerts", help="Alerts commands.", no_args_is_help=True)
    _service_apps["alerts"] = _alerts_app
    app.add_typer(_alerts_app, name="alerts")
    _alerts_app.command("noise-report")(alerts_noise_report)

# -- sysql helpers --
from .helpers.sysql import sysql_templates_list, sysql_templates_run  # noqa: E402

_sysql_templates_app = typer.Typer(name="templates", help="SysQL query templates.", no_args_is_help=True)
_service_apps["sysql"].add_typer(_sysql_templates_app, name="templates")
_sysql_templates_app.command("list")(sysql_templates_list)
_sysql_templates_app.command("run")(sysql_templates_run)

# -- inventory helpers --
from .helpers.inventory import inventory_diff  # noqa: E402

if "inventory" in _service_apps:
    _service_apps["inventory"].command("diff")(inventory_diff)
else:
    _inventory_app = typer.Typer(name="inventory", help="Inventory commands.", no_args_is_help=True)
    _service_apps["inventory"] = _inventory_app
    app.add_typer(_inventory_app, name="inventory")
    _inventory_app.command("diff")(inventory_diff)

# -- cost helpers --
from .helpers.cost import cost_security_rightsizing  # noqa: E402

if "cost" in _service_apps:
    _service_apps["cost"].command("security-weighted-rightsizing")(cost_security_rightsizing)
else:
    _cost_app = typer.Typer(name="cost", help="Cost optimization commands.", no_args_is_help=True)
    _service_apps["cost"] = _cost_app
    app.add_typer(_cost_app, name="cost")
    _cost_app.command("security-weighted-rightsizing")(cost_security_rightsizing)

# -- captures helpers (via response-actions API) --
from .helpers.captures import (  # noqa: E402
    captures_actions,
    captures_download,
    captures_list,
    captures_status,
    captures_trigger,
)

_captures_app = typer.Typer(
    name="captures",
    help="Syscall captures and response actions.",
    no_args_is_help=True,
)
app.add_typer(_captures_app, name="captures")
_captures_app.command("list")(captures_list)
_captures_app.command("trigger")(captures_trigger)
_captures_app.command("status")(captures_status)
_captures_app.command("download")(captures_download)
_captures_app.command("actions")(captures_actions)

# -- IAM helpers --
from .helpers.iam import (  # noqa: E402
    iam_access_keys_list,
    iam_roles_list,
    iam_group_mappings_list,
    iam_sso_settings,
)

_iam_app = typer.Typer(name="iam", help="Identity & Access Management commands.", no_args_is_help=True)
app.add_typer(_iam_app, name="iam")
_iam_access_keys_app = typer.Typer(name="access-keys", help="API access key management.", no_args_is_help=True)
_iam_app.add_typer(_iam_access_keys_app, name="access-keys")
_iam_access_keys_app.command("list")(iam_access_keys_list)

_iam_roles_app = typer.Typer(name="roles", help="Platform role management.", no_args_is_help=True)
_iam_app.add_typer(_iam_roles_app, name="roles")
_iam_roles_app.command("list")(iam_roles_list)

_iam_app.command("group-mappings")(iam_group_mappings_list)
_iam_app.command("sso-settings")(iam_sso_settings)

# -- audit platform-events --
from .helpers.audit import audit_platform_events  # noqa: E402
_service_apps["audit"].command("platform-events")(audit_platform_events)

"""
IAM (Identity & Access Management) helper commands.
+access-keys: List API access keys
+roles: List platform roles
+group-mappings: List identity provider group mappings
+sso-settings: Show SSO configuration
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info, print_warning
from ..paginator import paginate_all_items


def iam_access_keys_list(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml"),
    user: Optional[str] = typer.Option(None, "--user", help="Filter by user email"),
    all_pages: bool = typer.Option(False, "--all", help="Follow cursor if multiple pages exist"),
) -> None:
    """List API access keys."""
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    if all_pages:
        keys: List[Dict[str, Any]] = []
        try:
            with SysdigClient(auth=auth) as client:
                for key in paginate_all_items(client, "GET", "/platform/v1/access-keys"):
                    keys.append(key)
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
    else:
        try:
            with SysdigClient(auth=auth) as client:
                resp = client.get("/platform/v1/access-keys")
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

        keys = resp.get("data") or []

    if user:
        # Filter by access key value substring or team ID
        keys = [
            k for k in keys
            if user.lower() in str(k.get("accessKey", "")).lower()
            or user == str(k.get("teamId", ""))
        ]

    output(keys, fmt=fmt, schema="iam_access_keys")
    print_info(f"Showing {len(keys)} access key(s).")


def iam_roles_list(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml"),
    all_pages: bool = typer.Option(False, "--all", help="Follow cursor if multiple pages exist"),
) -> None:
    """List platform roles."""
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    if all_pages:
        roles: List[Dict[str, Any]] = []
        try:
            with SysdigClient(auth=auth) as client:
                for role in paginate_all_items(client, "GET", "/platform/v1/roles"):
                    roles.append(role)
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
    else:
        try:
            with SysdigClient(auth=auth) as client:
                resp = client.get("/platform/v1/roles")
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

        roles = resp.get("data") or []

    output(roles, fmt=fmt, schema="iam_roles")
    print_info(f"Showing {len(roles)} role(s).")


def iam_group_mappings_list(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("table", "--format", "-f", help="table|json|yaml"),
    all_pages: bool = typer.Option(False, "--all", help="Follow cursor if multiple pages exist"),
) -> None:
    """List IdP group-to-role mappings."""
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    if all_pages:
        mappings: List[Dict[str, Any]] = []
        try:
            with SysdigClient(auth=auth) as client:
                for mapping in paginate_all_items(client, "GET", "/platform/v1/group-mappings"):
                    mappings.append(mapping)
        except (AuthError, ForbiddenError) as e:
            print_error(str(e))
            raise typer.Exit(2)
        except SysdigError as e:
            print_error(str(e))
            raise typer.Exit(getattr(e, "exit_code", 3))
    else:
        try:
            with SysdigClient(auth=auth) as client:
                resp = client.get("/platform/v1/group-mappings")
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

        mappings = resp.get("data") or []

    # Flatten teamMap for display
    normalised: List[Dict[str, Any]] = []
    for m in mappings:
        row = dict(m)
        team_map = m.get("teamMap") or {}
        if team_map.get("isForAllTeams"):
            row["teams"] = "ALL"
        else:
            team_ids = team_map.get("teamIds") or []
            row["teams"] = ",".join(str(t) for t in team_ids) if team_ids else ""
        normalised.append(row)

    output(normalised, fmt=fmt, schema="iam_group_mappings")
    print_info(f"Showing {len(normalised)} group mapping(s).")


def iam_sso_settings(
    profile: str = typer.Option("default", "--profile", "-p"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    fmt: str = typer.Option("json", "--format", "-f", help="json|yaml|table"),
) -> None:
    """Show SSO/SAML configuration."""
    try:
        auth = resolve_auth(profile=profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    try:
        with SysdigClient(auth=auth) as client:
            resp = client.get("/platform/v1/sso-settings")
    except AuthError as e:
        print_error(str(e))
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(str(e))
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    output(resp, fmt=fmt)

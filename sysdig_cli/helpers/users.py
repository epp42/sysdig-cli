"""
Users helper commands.
+access-review: Export users + roles + teams for access certification (SOX/ISO compliance)
"""
# ruff: noqa: C901
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import typer

from ..auth import AuthError as AuthConfigError
from ..auth import resolve_auth
from ..client import AuthError, ForbiddenError, SysdigClient, SysdigError
from ..formatter import output, print_error, print_info

users_helpers_app = typer.Typer(
    name="users-helpers",
    help="Users helper commands.",
    no_args_is_help=True,
)


@users_helpers_app.command("access-review")
def users_access_review(
    format: str = typer.Option("table", "--format", help="table|csv|json"),
    inactive_since: int = typer.Option(90, "--inactive-since", help="Flag users inactive for N days"),
    profile: Optional[str] = typer.Option(None, "--profile"),
    region: Optional[str] = typer.Option(None, "--region"),
) -> None:
    """Export users + roles + teams for access certification (SOX/ISO compliance)."""
    _resolved_profile = profile or "default"
    try:
        auth = resolve_auth(profile=_resolved_profile, region=region)
    except AuthConfigError as e:
        print_error(str(e))
        raise typer.Exit(2)

    print_info(f"Fetching users, roles, and teams (inactive threshold: {inactive_since} days)...")

    inactive_threshold_s = inactive_since * 86400
    now_s = time.time()

    users: List[Dict[str, Any]] = []
    roles_by_id: Dict[str, str] = {}
    teams_by_id: Dict[str, str] = {}

    try:
        with SysdigClient(auth=auth) as client:
            # Fetch roles for lookup
            roles_resp = client.get("/platform/v1/roles")
            roles_data = (roles_resp or {}).get("roles") or (roles_resp or {}).get("data") or []
            for role in roles_data:
                roles_by_id[str(role.get("id", ""))] = role.get("name", "")

            # Fetch teams for lookup
            teams_resp = client.get("/platform/v1/teams")
            teams_data = (teams_resp or {}).get("teams") or (teams_resp or {}).get("data") or []
            for team in teams_data:
                teams_by_id[str(team.get("id", ""))] = team.get("name", "")

            # Fetch users
            users_resp = client.get("/platform/v1/users")
            users_data = (users_resp or {}).get("users") or (users_resp or {}).get("data") or []

            for user in users_data:
                # Resolve roles
                user_role_ids = [str(r) for r in (user.get("roleIds") or user.get("roles") or [])]
                user_roles = [roles_by_id.get(rid, rid) for rid in user_role_ids]

                # Try direct role field
                if not user_roles and user.get("role"):
                    user_roles = [user["role"]]

                # Resolve teams
                user_team_ids = [str(t) for t in (user.get("teamIds") or user.get("teams") or [])]
                user_teams = [teams_by_id.get(tid, tid) for tid in user_team_ids]

                # Determine inactivity
                last_login = user.get("lastSeenAt") or user.get("lastLoginAt") or user.get("lastLogin")
                inactive = False
                if last_login:
                    try:
                        last_s = float(last_login) / 1e9 if float(last_login) > 1e12 else float(last_login)
                        inactive = (now_s - last_s) > inactive_threshold_s
                    except (TypeError, ValueError):
                        pass
                else:
                    inactive = True  # Never logged in

                joined = user.get("createdAt") or user.get("joinedAt") or user.get("created")

                users.append({
                    "username": user.get("username") or user.get("email") or user.get("name", ""),
                    "email": user.get("email", ""),
                    "roles": ", ".join(user_roles) if user_roles else "",
                    "teams": ", ".join(user_teams) if user_teams else "",
                    "joined_at": str(joined) if joined else "",
                    "last_login": str(last_login) if last_login else "never",
                    "inactive": inactive,
                    "system_role": user.get("systemRole", ""),
                })

    except AuthError as e:
        print_error(f"Authentication failed: {e}")
        raise typer.Exit(2)
    except ForbiddenError as e:
        print_error(f"Forbidden: {e}")
        raise typer.Exit(5)
    except SysdigError as e:
        print_error(str(e))
        raise typer.Exit(getattr(e, "exit_code", 3))

    inactive_count = sum(1 for u in users if u.get("inactive"))

    result = {
        "access_review": {
            "total_users": len(users),
            "inactive_users": inactive_count,
            "inactive_threshold_days": inactive_since,
            "users": users,
        }
    }
    output(result, fmt=format)
    print_info(f"Access review: {len(users)} users, {inactive_count} inactive (>{inactive_since}d).")

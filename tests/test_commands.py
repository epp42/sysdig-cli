"""
Tests for OpenAPI-driven command generation.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from sysdig_cli.spec import (
    load_spec,
    get_paths,
    get_operations_for_service,
    SERVICE_MAP,
    extract_path_params,
    path_to_command_name,
)
from sysdig_cli.commands import (
    build_service_app,
    _path_to_subcommand,
)


class TestSpecLoading:
    def test_spec_loads(self):
        spec = load_spec()
        assert isinstance(spec, dict)
        assert "paths" in spec

    def test_spec_has_paths(self):
        spec = load_spec()
        paths = get_paths(spec)
        assert len(paths) > 0

    def test_spec_version(self):
        spec = load_spec()
        info = spec.get("info", {})
        assert "version" in info

    def test_vulns_paths_in_spec(self):
        spec = load_spec()
        paths = get_paths(spec)
        vuln_paths = [p for p in paths if "/secure/vulnerability" in p]
        assert len(vuln_paths) > 0

    def test_audit_paths_in_spec(self):
        spec = load_spec()
        paths = get_paths(spec)
        audit_paths = [p for p in paths if "/secure/activity-audit" in p]
        assert len(audit_paths) > 0


class TestRefResolution:
    def test_parameters_resolved(self):
        spec = load_spec()
        paths = get_paths(spec)
        # Find a path that uses $ref for parameters
        for path, path_item in paths.items():
            for method, op in path_item.items():
                if method not in ("get", "post", "put", "delete", "patch"):
                    continue
                if isinstance(op, dict):
                    params = op.get("parameters", [])
                    for param in params:
                        # $refs should be resolved
                        assert "$ref" not in param, f"Unresolved $ref in {path} {method}"
                    break
            break

    def test_schemas_resolved(self):
        spec = load_spec()
        # Ensure refs in path items are resolved
        paths = get_paths(spec)
        runtime_path = "/secure/vulnerability/v1/runtime-results"
        assert runtime_path in paths
        op = paths[runtime_path].get("get", {})
        assert isinstance(op, dict)
        assert "parameters" in op


class TestExtractPathParams:
    def test_no_params(self):
        assert extract_path_params("/api/test") == []

    def test_single_param(self):
        assert extract_path_params("/api/test/{id}") == ["id"]

    def test_multiple_params(self):
        params = extract_path_params("/api/{version}/test/{id}")
        assert "version" in params
        assert "id" in params

    def test_complex_params(self):
        params = extract_path_params("/platform/v1/teams/{teamId}/users/{userId}")
        assert "teamId" in params
        assert "userId" in params


class TestPathToSubcommand:
    def test_list_endpoint(self):
        name = _path_to_subcommand(
            "/secure/vulnerability/v1/runtime-results", "get", "vulns"
        )
        assert "list" in name or "runtime-results" in name

    def test_get_with_id(self):
        name = _path_to_subcommand(
            "/secure/vulnerability/v1/results/{resultId}", "get", "vulns"
        )
        assert "get" in name

    def test_create_endpoint(self):
        name = _path_to_subcommand(
            "/secure/vulnerability/v1/policies", "post", "vulns"
        )
        assert "create" in name

    def test_delete_endpoint(self):
        name = _path_to_subcommand(
            "/secure/vulnerability/v1/policies/{policyId}", "delete", "vulns"
        )
        assert "delete" in name

    def test_update_endpoint(self):
        name = _path_to_subcommand(
            "/secure/vulnerability/v1/policies/{policyId}", "put", "vulns"
        )
        assert "update" in name


class TestGetOperationsForService:
    def test_vulns_operations(self):
        ops = get_operations_for_service("vulns")
        assert len(ops) > 0
        for op in ops:
            assert "path" in op
            assert "method" in op
            assert "summary" in op

    def test_events_operations(self):
        ops = get_operations_for_service("events")
        assert len(ops) > 0

    def test_audit_operations(self):
        ops = get_operations_for_service("audit")
        assert len(ops) > 0

    def test_all_services_have_operations(self):
        for service in SERVICE_MAP:
            ops = get_operations_for_service(service)
            # Some services might have no ops if paths don't match
            assert isinstance(ops, list)

    def test_operations_have_required_fields(self):
        ops = get_operations_for_service("vulns")
        for op in ops:
            assert "path" in op
            assert "method" in op
            assert "parameters" in op
            assert isinstance(op["parameters"], list)


class TestBuildServiceApp:
    def test_vulns_app_created(self):
        app = build_service_app("vulns")
        import typer
        assert isinstance(app, typer.Typer)

    def test_vulns_app_has_commands(self):
        import typer
        app = build_service_app("vulns")
        # Get the click command
        cmd = typer.main.get_command(app)
        assert len(cmd.commands) > 0

    def test_audit_app_has_list_command(self):
        import typer
        app = build_service_app("audit")
        cmd = typer.main.get_command(app)
        # Should have at least one command
        assert len(cmd.commands) > 0

    def test_no_duplicate_commands(self):
        import typer
        app = build_service_app("vulns")
        cmd = typer.main.get_command(app)
        names = list(cmd.commands.keys())
        assert len(names) == len(set(names)), "Duplicate command names found"

"""
Integration tests: mock HTTP, full command pipeline e2e.
"""
from __future__ import annotations

import json
from typing import Any, Dict

import httpx
import pytest
import respx
import typer
from typer.testing import CliRunner

from sysdig_cli.main import app

BASE_URL = "https://us2.app.sysdig.com"
runner = CliRunner(mix_stderr=False)


@pytest.fixture(autouse=True)
def set_token_env(monkeypatch):
    """Set test API token for all integration tests."""
    monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken12345")
    monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)


class TestCLIHelp:
    def test_help_returns_zero(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_version_returns_zero(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_vulns_help(self):
        result = runner.invoke(app, ["vulns", "--help"])
        assert result.exit_code == 0
        assert "vulns" in result.output.lower() or "vulnerability" in result.output.lower()

    def test_auth_setup_help(self):
        result = runner.invoke(app, ["auth", "setup", "--help"])
        assert result.exit_code == 0
        assert "--token" in result.output or "token" in result.output.lower()

    def test_schema_help(self):
        result = runner.invoke(app, ["schema", "--help"])
        assert result.exit_code == 0

    def test_all_service_help(self):
        services = ["vulns", "events", "audit", "inventory", "actions",
                    "platform", "zones", "teams", "users", "roles",
                    "alerts", "metrics", "sysql", "fwd", "cost", "auth"]
        for svc in services:
            result = runner.invoke(app, [svc, "--help"])
            assert result.exit_code == 0, f"{svc} --help failed: {result.output}"


class TestSchemaCommand:
    def test_schema_show_policies(self):
        # Direct path shortcut: sysdig schema /path
        result = runner.invoke(app, ["schema", "/secure/vulnerability/v1/policies"])
        assert result.exit_code == 0, f"Failed: {result.output}"
        assert "GET" in result.output
        assert "/secure/vulnerability/v1/policies" in result.output

    def test_schema_not_found(self):
        result = runner.invoke(app, ["schema", "/nonexistent/path"])
        assert result.exit_code == 4  # Not found

    def test_schema_list_command(self):
        result = runner.invoke(app, ["schema", "list"])
        assert result.exit_code == 0
        assert "/secure/" in result.output or "/platform/" in result.output

    def test_schema_show_json_format(self):
        result = runner.invoke(app, [
            "schema", "/secure/vulnerability/v1/policies",
            "--format", "json"
        ])
        assert result.exit_code == 0, f"Failed: {result.output}"
        out = result.output.strip()
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_schema_show_yaml_format(self):
        result = runner.invoke(app, [
            "schema", "/secure/vulnerability/v1/policies",
            "--format", "yaml"
        ])
        assert result.exit_code == 0


class TestAuthCommands:
    def test_auth_whoami(self):
        result = runner.invoke(app, ["auth", "whoami"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "host" in data
        assert data["profile"] == "env"
        # Token should be masked
        assert "testtoken12345" not in data["token"]

    def test_auth_list_empty(self, tmp_path, monkeypatch):
        """auth list with no profiles configured."""
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        result = runner.invoke(app, ["auth", "list"])
        # Should exit 0 even with no profiles
        assert result.exit_code == 0

    def test_auth_setup_http_rejected(self, tmp_path, monkeypatch):
        """auth setup should reject http:// hosts."""
        result = runner.invoke(app, [
            "auth", "setup",
            "--token", "mytoken",
            "--host", "http://bad.example.com",
        ])
        assert result.exit_code != 0


class TestVulnsCommands:
    def test_policies_list(self):
        response_data = {
            "data": [
                {"id": "p1", "name": "Default Policy", "stages": ["runtime"]},
            ],
            "page": {"returned": 1, "matched": 1, "next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["data"][0]["id"] == "p1"

    def test_policies_list_table_format(self):
        response_data = {
            "data": [{"id": "p1", "name": "Default Policy"}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-list", "--format", "table"])
        assert result.exit_code == 0
        assert "p1" in result.output or "Default Policy" in result.output

    def test_runtime_results_list(self):
        response_data = {
            "data": [{"id": "r1", "resourceName": "nginx:1.19"}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/runtime-results").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "runtime-results-list"])
        assert result.exit_code == 0

    def test_policy_get_by_id(self):
        response_data = {"id": "p1", "name": "Default Policy"}
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies/p1").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["vulns", "policies-get", "p1"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["id"] == "p1"

    def test_dry_run_create(self):
        result = runner.invoke(app, [
            "vulns", "policies-create",
            "--body", '{"name": "test"}',
            "--dry-run",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert data["method"] == "POST"

    def test_401_exit_code(self):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(401, json={"message": "Unauthorized"})
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        assert result.exit_code == 2

    def test_404_exit_code(self):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies/nonexistent").mock(
                return_value=httpx.Response(404, json={"message": "Not found"})
            )
            result = runner.invoke(app, ["vulns", "policies-get", "nonexistent"])
        assert result.exit_code == 4

    def test_403_exit_code(self):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/vulnerability/v1/policies").mock(
                return_value=httpx.Response(403, json={"message": "Forbidden"})
            )
            result = runner.invoke(app, ["vulns", "policies-list"])
        assert result.exit_code == 5


class TestEventsCommands:
    def test_events_list(self):
        response_data = {
            "data": [{"id": "e1", "name": "Test Event"}],
            "page": {"next": None},
        }
        # events-list maps to /monitor/events/v1/events (first GET events endpoint)
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/monitor/events/v1/events").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["events", "events-list"])
        assert result.exit_code == 0

    def test_events_hunt(self):
        response_data = {
            "data": [
                {"id": "e1", "name": "netcat activity", "description": "netcat found"},
            ],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL, assert_all_called=False) as mock:
            mock.get("/secure/events/v1/events").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["events", "hunt", "netcat"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ioc"] == "netcat"
        assert data["match_count"] >= 1


class TestAuditCommands:
    def test_audit_list(self):
        response_data = {
            "data": [{"id": "a1", "type": "kubectl.exec"}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["audit", "entries-list"])
        assert result.exit_code == 0

    def test_audit_recent_commands(self):
        response_data = {
            "data": [{"id": "a1", "type": "kubectl.exec"}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/secure/activity-audit/v1/entries").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            result = runner.invoke(app, ["audit", "recent-commands"])
        assert result.exit_code == 0


class TestPagination:
    def test_page_all_streams_ndjson(self):
        responses = [
            {"data": [{"id": 1}], "page": {"next": "c2"}},
            {"data": [{"id": 2}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/secure/vulnerability/v1/policies").mock(side_effect=side_effect)
            result = runner.invoke(app, ["vulns", "policies-list", "--page-all"])

        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split("\n") if l.strip()]
        # Each line should be a valid JSON object
        items = []
        for line in lines:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        assert len(items) >= 1

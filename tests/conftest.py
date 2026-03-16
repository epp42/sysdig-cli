"""
Shared test fixtures for sysdig-cli tests.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import httpx
import respx

from sysdig_cli.auth import AuthConfig


@pytest.fixture
def sample_auth() -> AuthConfig:
    """Return a sample AuthConfig for testing."""
    return AuthConfig(
        token="test-token-12345",
        host="https://us2.app.sysdig.com",
        profile="default",
    )


@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """Return a temporary config directory."""
    config_dir = tmp_path / ".sysdig"
    config_dir.mkdir()
    return config_dir / "config.yaml"


@pytest.fixture
def sample_vuln_response() -> Dict[str, Any]:
    """Sample vulnerability runtime results response."""
    return {
        "page": {"returned": 2, "matched": 2, "next": None},
        "data": [
            {
                "id": "result-001",
                "resourceName": "nginx:1.19",
                "vulnTotalBySeverity": {
                    "critical": 3,
                    "high": 10,
                    "medium": 5,
                    "low": 2,
                    "negligible": 0,
                },
            },
            {
                "id": "result-002",
                "resourceName": "redis:6.0",
                "vulnTotalBySeverity": {
                    "critical": 1,
                    "high": 3,
                    "medium": 8,
                    "low": 4,
                    "negligible": 1,
                },
            },
        ],
    }


@pytest.fixture
def sample_events_response() -> Dict[str, Any]:
    """Sample security events response."""
    return {
        "data": [
            {
                "id": "evt-001",
                "name": "Suspicious bash execution",
                "severity": "high",
                "timestamp": 1705312800000000000,
                "description": "bash executed in container",
            },
            {
                "id": "evt-002",
                "name": "Netcat network activity",
                "severity": "critical",
                "timestamp": 1705312900000000000,
                "description": "netcat connection detected",
            },
        ],
        "page": {"next": None},
    }


@pytest.fixture
def sample_audit_response() -> Dict[str, Any]:
    """Sample activity audit response."""
    return {
        "data": [
            {
                "id": "entry-001",
                "timestamp": 1705312800000000000,
                "type": "kubectl.exec",
                "user": {"name": "alice@example.com"},
                "commandLine": "kubectl exec pod-abc -- /bin/bash",
            },
            {
                "id": "entry-002",
                "timestamp": 1705312700000000000,
                "type": "kubectl.exec",
                "user": {"name": "bob@example.com"},
                "commandLine": "kubectl exec pod-xyz -- env",
            },
        ],
        "page": {"next": None},
    }


@pytest.fixture
def respx_mock():
    """RESPX mock context for httpx."""
    with respx.mock(assert_all_called=False) as mock:
        yield mock

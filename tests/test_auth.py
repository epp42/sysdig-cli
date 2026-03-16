"""
Tests for authentication and credential resolution.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from sysdig_cli.auth import (
    AuthConfig,
    AuthError,
    resolve_auth,
    setup_profile,
    list_profiles,
    delete_profile,
    load_config_file,
    REGION_HOSTS,
    DEFAULT_HOST,
)


class TestAuthConfig:
    def test_valid_config(self):
        auth = AuthConfig(token="mytoken", host="https://us2.app.sysdig.com")
        assert auth.token == "mytoken"
        assert auth.host == "https://us2.app.sysdig.com"
        assert auth.profile == "default"

    def test_http_rejected(self):
        with pytest.raises(AuthError, match="HTTPS"):
            AuthConfig(token="mytoken", host="http://us2.app.sysdig.com")

    def test_empty_token_rejected(self):
        with pytest.raises(AuthError, match="empty"):
            AuthConfig(token="", host="https://us2.app.sysdig.com")

    def test_token_masked_in_repr(self):
        auth = AuthConfig(token="supersecrettoken", host="https://us2.app.sysdig.com")
        r = repr(auth)
        assert "supersecrettoken" not in r
        assert "supe****" in r

    def test_token_not_in_str(self):
        auth = AuthConfig(token="supersecrettoken", host="https://eu1.app.sysdig.com")
        assert "supersecrettoken" not in str(auth)


class TestResolveAuth:
    def test_env_var_sysdig_api_token(self, monkeypatch):
        monkeypatch.setenv("SYSDIG_API_TOKEN", "envtoken123")
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        auth = resolve_auth()
        assert auth.token == "envtoken123"
        assert auth.host == DEFAULT_HOST
        assert auth.profile == "env"

    def test_env_var_sysdig_secure_token_fallback(self, monkeypatch):
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.setenv("SYSDIG_SECURE_TOKEN", "securetoken456")
        auth = resolve_auth()
        assert auth.token == "securetoken456"
        assert auth.profile == "env"

    def test_sysdig_api_token_takes_priority(self, monkeypatch):
        monkeypatch.setenv("SYSDIG_API_TOKEN", "apitoken")
        monkeypatch.setenv("SYSDIG_SECURE_TOKEN", "securetoken")
        auth = resolve_auth()
        assert auth.token == "apitoken"

    def test_config_file_loading(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        config = {
            "profiles": {
                "default": {
                    "token": "filetoken789",
                    "host": "https://eu1.app.sysdig.com",
                }
            }
        }
        config_file.write_text(yaml.dump(config))
        auth = resolve_auth(config_path=config_file)
        assert auth.token == "filetoken789"
        assert auth.host == "https://eu1.app.sysdig.com"
        assert auth.profile == "default"

    def test_named_profile(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        config = {
            "profiles": {
                "prod": {
                    "token": "prodtoken",
                    "host": "https://eu1.app.sysdig.com",
                }
            }
        }
        config_file.write_text(yaml.dump(config))
        auth = resolve_auth(profile="prod", config_path=config_file)
        assert auth.token == "prodtoken"
        assert auth.profile == "prod"

    def test_no_credentials_raises(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        with pytest.raises(AuthError, match="No credentials"):
            resolve_auth(config_path=config_file)

    def test_region_override(self, monkeypatch):
        monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
        auth = resolve_auth(region="eu1")
        assert auth.host == "https://eu1.app.sysdig.com"

    def test_region_override_au1(self, monkeypatch):
        monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
        auth = resolve_auth(region="au1")
        assert auth.host == "https://app.au1.sysdig.com"

    def test_invalid_region_raises(self, monkeypatch):
        monkeypatch.setenv("SYSDIG_API_TOKEN", "testtoken")
        with pytest.raises(AuthError, match="Unknown region"):
            resolve_auth(region="invalid-region")

    def test_region_overrides_config_host(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SYSDIG_API_TOKEN", raising=False)
        monkeypatch.delenv("SYSDIG_SECURE_TOKEN", raising=False)
        config_file = tmp_path / "config.yaml"
        config = {
            "profiles": {
                "default": {
                    "token": "mytoken",
                    "host": "https://us2.app.sysdig.com",
                }
            }
        }
        config_file.write_text(yaml.dump(config))
        auth = resolve_auth(region="eu1", config_path=config_file)
        assert auth.host == "https://eu1.app.sysdig.com"

    def test_all_regions_mapped(self):
        for region in ["us2", "us4", "eu1", "au1"]:
            assert region in REGION_HOSTS
            assert REGION_HOSTS[region].startswith("https://")


class TestSetupProfile:
    def test_save_profile(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        setup_profile("default", "mytoken", "https://us2.app.sysdig.com", config_file)
        config = load_config_file(config_file)
        assert config["profiles"]["default"]["token"] == "mytoken"
        assert config["profiles"]["default"]["host"] == "https://us2.app.sysdig.com"

    def test_rejects_http_host(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(AuthError, match="HTTPS"):
            setup_profile("default", "mytoken", "http://bad.example.com", config_file)

    def test_multiple_profiles(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        setup_profile("dev", "devtoken", "https://us2.app.sysdig.com", config_file)
        setup_profile("prod", "prodtoken", "https://eu1.app.sysdig.com", config_file)
        config = load_config_file(config_file)
        assert "dev" in config["profiles"]
        assert "prod" in config["profiles"]

    def test_config_file_permissions(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        setup_profile("default", "token", "https://us2.app.sysdig.com", config_file)
        mode = oct(config_file.stat().st_mode)[-3:]
        assert mode == "600", f"Config file permissions should be 600, got {mode}"


class TestListProfiles:
    def test_empty_when_no_config(self, tmp_path):
        config_file = tmp_path / "noconfig.yaml"
        profiles = list_profiles(config_file)
        assert profiles == {}

    def test_tokens_masked(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        setup_profile("default", "supersecrettoken", "https://us2.app.sysdig.com", config_file)
        profiles = list_profiles(config_file)
        assert "supe****" in profiles["default"]["token"]
        assert "supersecrettoken" not in profiles["default"]["token"]


class TestDeleteProfile:
    def test_delete_existing(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        setup_profile("test", "token", "https://us2.app.sysdig.com", config_file)
        result = delete_profile("test", config_file)
        assert result is True
        config = load_config_file(config_file)
        assert "test" not in config.get("profiles", {})

    def test_delete_nonexistent(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        result = delete_profile("nonexistent", config_file)
        assert result is False

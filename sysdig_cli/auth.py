"""
Authentication and configuration management.
Priority chain: SYSDIG_API_TOKEN -> SYSDIG_SECURE_TOKEN -> ~/.sysdig/config.yaml -> prompt
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

CONFIG_PATH = Path.home() / ".sysdig" / "config.yaml"

REGION_HOSTS: Dict[str, str] = {
    "us2": "https://us2.app.sysdig.com",
    "us4": "https://us4.app.sysdig.com",
    "eu1": "https://eu1.app.sysdig.com",
    "au1": "https://app.au1.sysdig.com",
    "prodmon": "https://prodmon.app.sysdig.com",
}

DEFAULT_HOST = "https://us2.app.sysdig.com"


class AuthError(Exception):
    """Raised when authentication cannot be resolved."""
    pass


@dataclass
class AuthConfig:
    token: str
    host: str
    profile: str = "default"

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not self.token:
            raise AuthError("Token cannot be empty.")
        if not self.host.startswith("https://"):
            raise AuthError(
                f"Host must use HTTPS. Got: {self.host!r}. "
                "Plaintext HTTP connections are not allowed."
            )
        # Never log the token - mask it in repr

    def __repr__(self) -> str:
        masked = self.token[:4] + "****" if len(self.token) > 4 else "****"
        return f"AuthConfig(host={self.host!r}, profile={self.profile!r}, token={masked!r})"


def load_config_file(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load ~/.sysdig/config.yaml if it exists."""
    path = config_path or CONFIG_PATH
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def save_config_file(
    data: Dict[str, Any], config_path: Optional[Path] = None
) -> None:
    """Save configuration to ~/.sysdig/config.yaml."""
    path = config_path or CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    # Secure permissions: owner read/write only
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False)
    os.chmod(path, 0o600)


def resolve_auth(
    profile: str = "default",
    region: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> AuthConfig:
    """
    Resolve authentication credentials using priority chain:
    1. SYSDIG_API_TOKEN env var
    2. SYSDIG_SECURE_TOKEN env var
    3. ~/.sysdig/config.yaml profile
    4. Interactive prompt (if terminal)
    """
    # Determine host from region override
    host_override: Optional[str] = None
    if region:
        if region not in REGION_HOSTS:
            raise AuthError(
                f"Unknown region {region!r}. Valid regions: {', '.join(REGION_HOSTS)}"
            )
        host_override = REGION_HOSTS[region]

    # Env-var host: SYSDIG_API_URL takes precedence over hardcoded default
    env_host = (
        os.environ.get("SYSDIG_API_URL", "").strip()
        or os.environ.get("SYSDIG_HOST", "").strip()
        or os.environ.get("SYSDIG_MCP_API_HOST", "").strip()
    )
    # SYSDIG_REGION env var: shorthand for known regions (e.g. "eu1", "prodmon")
    env_region = os.environ.get("SYSDIG_REGION", "").strip().lower()
    if env_region and not env_host:
        if env_region not in REGION_HOSTS:
            raise AuthError(
                f"Unknown SYSDIG_REGION {env_region!r}. "
                f"Valid regions: {', '.join(REGION_HOSTS)}"
            )
        env_host = REGION_HOSTS[env_region]
    default_host = env_host if env_host else DEFAULT_HOST

    # 1. SYSDIG_API_TOKEN
    token = os.environ.get("SYSDIG_API_TOKEN", "").strip()
    if token:
        host = host_override or default_host
        return AuthConfig(token=token, host=host, profile="env")

    # 2. SYSDIG_SECURE_TOKEN / SYSDIG_MCP_API_SECURE_TOKEN
    token = (
        os.environ.get("SYSDIG_SECURE_TOKEN", "").strip()
        or os.environ.get("SYSDIG_MCP_API_SECURE_TOKEN", "").strip()
    )
    if token:
        host = host_override or default_host
        return AuthConfig(token=token, host=host, profile="env")

    # 3. Config file
    config = load_config_file(config_path)
    profiles = config.get("profiles", {})
    if profile in profiles:
        profile_data = profiles[profile]
        token = profile_data.get("token", "").strip()
        file_host = profile_data.get("host", default_host).strip()
        host = host_override or file_host
        if token:
            return AuthConfig(token=token, host=host, profile=profile)

    # 4. Interactive prompt
    if sys.stdin.isatty() and sys.stderr.isatty():
        print(
            "\nNo credentials found. Please enter your Sysdig API token.",
            file=sys.stderr,
        )
        print("(Get your token from Sysdig UI -> Settings -> User Profile)", file=sys.stderr)
        try:
            import getpass
            token = getpass.getpass("Sysdig API Token: ").strip()
        except (EOFError, KeyboardInterrupt):
            token = ""

        if token:
            host = host_override or default_host
            print(
                "Tip: Save credentials with: sysdig auth setup",
                file=sys.stderr,
            )
            return AuthConfig(token=token, host=host, profile="interactive")

    raise AuthError(
        "No credentials found. Set SYSDIG_API_TOKEN env var or run 'sysdig auth setup'."
    )


def setup_profile(
    profile: str,
    token: str,
    host: str,
    config_path: Optional[Path] = None,
) -> None:
    """Save a profile to the config file."""
    if not host.startswith("https://"):
        raise AuthError(f"Host must use HTTPS. Got: {host!r}")

    config = load_config_file(config_path)
    if "profiles" not in config:
        config["profiles"] = {}
    config["profiles"][profile] = {
        "token": token,
        "host": host,
    }
    save_config_file(config, config_path)


def list_profiles(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return all configured profiles (tokens masked)."""
    config = load_config_file(config_path)
    profiles = config.get("profiles", {})
    result = {}
    for name, data in profiles.items():
        token = data.get("token", "")
        masked = token[:4] + "****" if len(token) > 4 else "****"
        result[name] = {
            "host": data.get("host", ""),
            "token": masked,
        }
    return result


def delete_profile(profile: str, config_path: Optional[Path] = None) -> bool:
    """Delete a profile from config. Returns True if deleted."""
    config = load_config_file(config_path)
    profiles = config.get("profiles", {})
    if profile not in profiles:
        return False
    del profiles[profile]
    config["profiles"] = profiles
    save_config_file(config, config_path)
    return True

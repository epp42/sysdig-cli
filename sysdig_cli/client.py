"""
HTTP client with retry/backoff logic.
Never logs token values. Raises typed exceptions matching exit codes.
"""
# ruff: noqa: C901
from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict, Optional

import httpx

from .auth import AuthConfig


# Exit code exceptions
class SysdigError(Exception):
    """Base exception for Sysdig CLI errors."""
    exit_code: int = 3


class UsageError(SysdigError):
    """Usage error / bad request (exit code 1)."""
    exit_code = 1


class AuthError(SysdigError):
    """Authentication error 401 (exit code 2)."""
    exit_code = 2


class APIError(SysdigError):
    """API error 5xx / 429 (exit code 3)."""
    exit_code = 3


class NotFoundError(SysdigError):
    """Not found 404 / 410 (exit code 4)."""
    exit_code = 4


class ForbiddenError(SysdigError):
    """Forbidden 403 (exit code 5)."""
    exit_code = 5


MAX_RETRIES = 3
BACKOFF_DELAYS = [1, 2, 4]  # seconds
RETRY_STATUS_CODES = {429, 502, 503, 504}


class SysdigClient:
    """HTTP client for the Sysdig Platform API."""

    def __init__(self, auth: AuthConfig, timeout: float = 30.0, dry_run: bool = False):
        self.auth = auth
        self.dry_run = dry_run
        self._client = httpx.Client(
            base_url=auth.host,
            headers={
                "Authorization": f"Bearer {auth.token}",
                "User-Agent": "sysdig-cli/0.1.0-alpha",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=timeout,
            follow_redirects=True,
        )

    def __enter__(self) -> "SysdigClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        dry_run: Optional[bool] = None,
    ) -> Any:
        """
        Make an HTTP request with retry/backoff.
        Returns parsed JSON response body.
        """
        is_dry = dry_run if dry_run is not None else self.dry_run
        is_mutating = method.upper() in ("POST", "PUT", "DELETE", "PATCH")

        if is_dry and is_mutating:
            dry_output = {
                "dry_run": True,
                "method": method.upper(),
                "path": path,
                "host": self.auth.host,
                "params": params or {},
                "body": json_body,
            }
            print(json.dumps(dry_output, indent=2))
            return None

        # Filter out None params
        clean_params: Optional[Dict[str, Any]] = None
        if params:
            clean_params = {k: v for k, v in params.items() if v is not None}

        last_error: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                response = self._client.request(
                    method=method.upper(),
                    url=path,
                    params=clean_params,
                    json=json_body,
                )
                return self._handle_response(response)

            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as e:
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    delay = BACKOFF_DELAYS[attempt]
                    print(
                        f"Connection error (attempt {attempt + 1}/{MAX_RETRIES}), "
                        f"retrying in {delay}s...",
                        file=sys.stderr,
                    )
                    time.sleep(delay)
                continue

            except SysdigError:
                raise

        raise APIError(f"Request failed after {MAX_RETRIES} attempts: {last_error}")

    def _handle_response(self, response: httpx.Response) -> Any:
        """Handle HTTP response, raising typed exceptions on errors."""
        status = response.status_code

        if status == 200 or (200 <= status < 300):
            if not response.content:
                return {}
            try:
                return response.json()
            except Exception:
                return {"raw": response.text}

        # Rate limiting - respect Retry-After
        if status == 429:
            retry_after = self._get_retry_after(response)
            print(
                f"Rate limited (429). Waiting {retry_after}s...",
                file=sys.stderr,
            )
            time.sleep(retry_after)
            # Re-raise so caller can retry
            raise APIError(f"Rate limited: {self._parse_error(response)}")

        # Server errors - will be retried
        if status in (502, 503, 504):
            raise APIError(
                f"Server error {status}: {self._parse_error(response)}"
            )

        # Client errors - no retry
        if status == 400:
            raise UsageError(f"Bad request: {self._parse_error(response)}")

        if status == 401:
            raise AuthError(f"Unauthorized: {self._parse_error(response)}")

        if status == 403:
            raise ForbiddenError(f"Forbidden: {self._parse_error(response)}")

        if status in (404, 410):
            raise NotFoundError(f"Not found ({status}): {self._parse_error(response)}")

        if status == 422:
            raise UsageError(f"Validation error: {self._parse_error(response)}")

        # Generic error
        raise APIError(f"API error {status}: {self._parse_error(response)}")

    def _get_retry_after(self, response: httpx.Response) -> float:
        """Parse Retry-After header, defaulting to 1s."""
        header = response.headers.get("Retry-After", "")
        try:
            return float(header)
        except (ValueError, TypeError):
            return 1.0

    def _parse_error(self, response: httpx.Response) -> str:
        """Parse error message from response body without logging sensitive data."""
        try:
            data = response.json()
            if isinstance(data, dict):
                msg = data.get("message") or data.get("error") or data.get("type", "")
                details = data.get("details", [])
                if details:
                    detail_str = "; ".join(str(d) for d in details[:3])
                    return f"{msg}: {detail_str}" if msg else detail_str
                return msg or str(data)
            return str(data)
        except Exception:
            text = response.text[:200] if response.text else "(empty body)"
            return text

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self.request("GET", path, params=params)

    def post(
        self, path: str, json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> Any:
        return self.request("POST", path, params=params, json_body=json_body, dry_run=dry_run)

    def put(
        self, path: str, json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> Any:
        return self.request("PUT", path, params=params, json_body=json_body, dry_run=dry_run)

    def delete(
        self, path: str, params: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> Any:
        return self.request("DELETE", path, params=params, dry_run=dry_run)

    def patch(
        self, path: str, json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> Any:
        return self.request("PATCH", path, params=params, json_body=json_body, dry_run=dry_run)

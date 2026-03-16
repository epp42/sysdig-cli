"""
Cursor-based pagination for Sysdig API.
Supports --page-all to fetch all pages and stream as NDJSON.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Generator, List, Optional  # List already imported

from .client import SysdigClient
from .formatter import print_info


def _extract_next_cursor(response: Any) -> Optional[str]:
    """Extract next cursor from response following Sysdig pagination patterns."""
    if not isinstance(response, dict):
        return None

    # Pattern 1: response.page.next
    page = response.get("page")
    if isinstance(page, dict):
        return page.get("next") or None

    # Pattern 2: response.cursor
    cursor = response.get("cursor")
    if cursor:
        return cursor

    # Pattern 3: response.nextCursor
    next_cursor = response.get("nextCursor")
    if next_cursor:
        return next_cursor

    return None


def _extract_data(response: Any) -> List[Any]:
    """Extract the data list from a response."""
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        for key in ("data", "items", "results", "entries", "resources"):
            if key in response and isinstance(response[key], list):
                return response[key]
    return []


def paginate(
    client: SysdigClient,
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    page_all: bool = False,
    limit: Optional[int] = None,
    cursor_exclusive_keys: Optional[List[str]] = None,
) -> Generator[Any, None, None]:
    """
    Fetch pages from the API and yield each response dict.
    If page_all=True, automatically follows cursors and yields each item (NDJSON mode).

    cursor_exclusive_keys: param keys to remove once cursor pagination begins.
    """
    current_params = dict(params or {})
    if limit is not None:
        current_params["limit"] = limit

    page_count = 0
    total_items = 0

    while True:
        if method.upper() == "GET":
            response = client.get(path, params=current_params)
        elif method.upper() == "POST":
            response = client.post(path, json_body=json_body, params=current_params)
        else:
            response = client.request(method, path, params=current_params, json_body=json_body)

        page_count += 1
        yield response

        if not page_all:
            break

        next_cursor = _extract_next_cursor(response)
        if not next_cursor:
            break

        if cursor_exclusive_keys:
            for key in cursor_exclusive_keys:
                current_params.pop(key, None)

        current_params["cursor"] = next_cursor
        data = _extract_data(response)
        total_items += len(data)

        if page_count > 1:
            print_info(f"Fetched page {page_count}, {total_items} items so far...")


def paginate_all_items(
    client: SysdigClient,
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    limit: Optional[int] = None,
    cursor_exclusive_keys: Optional[List[str]] = None,
) -> Generator[Any, None, None]:
    """
    Stream all items across all pages, yielding individual items.
    Each item is yielded as it is fetched.

    cursor_exclusive_keys: param keys to remove once cursor pagination begins.
      Use for APIs where cursor and time-range params are mutually exclusive
      (e.g. the Sysdig events API drops 'from'/'to' after first page).
    """
    current_params = dict(params or {})
    if limit is not None:
        current_params["limit"] = limit

    page_count = 0

    while True:
        if method.upper() == "GET":
            response = client.get(path, params=current_params)
        elif method.upper() == "POST":
            response = client.post(path, json_body=json_body, params=current_params)
        else:
            response = client.request(method, path, params=current_params, json_body=json_body)

        page_count += 1
        items = _extract_data(response)

        for item in items:
            yield item

        next_cursor = _extract_next_cursor(response)
        if not next_cursor:
            break

        # Switch to cursor-only mode: drop any keys that conflict with cursor
        if cursor_exclusive_keys:
            for key in cursor_exclusive_keys:
                current_params.pop(key, None)

        current_params["cursor"] = next_cursor


def stream_ndjson(
    client: SysdigClient,
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    limit: Optional[int] = None,
    file: Any = None,
    cursor_exclusive_keys: Optional[List[str]] = None,
) -> int:
    """
    Stream all items as NDJSON to stdout.
    Returns total items written.
    """
    if file is None:
        file = sys.stdout

    count = 0
    for item in paginate_all_items(
        client, method, path, params=params, json_body=json_body, limit=limit,
        cursor_exclusive_keys=cursor_exclusive_keys,
    ):
        print(json.dumps(item, default=str), file=file)
        count += 1
    return count

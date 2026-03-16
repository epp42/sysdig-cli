"""
Tests for cursor-based pagination.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from sysdig_cli.auth import AuthConfig
from sysdig_cli.client import SysdigClient
from sysdig_cli.paginator import (
    paginate,
    paginate_all_items,
    stream_ndjson,
    _extract_next_cursor,
    _extract_data,
)


BASE_URL = "https://us2.app.sysdig.com"


@pytest.fixture
def auth():
    return AuthConfig(token="testtoken", host=BASE_URL)


class TestExtractNextCursor:
    def test_page_next_pattern(self):
        response = {"page": {"next": "cursor123", "returned": 10}}
        assert _extract_next_cursor(response) == "cursor123"

    def test_page_next_none(self):
        response = {"page": {"next": None, "returned": 10}}
        assert _extract_next_cursor(response) is None

    def test_page_next_empty_string(self):
        response = {"page": {"next": ""}}
        assert _extract_next_cursor(response) is None

    def test_cursor_field(self):
        response = {"cursor": "abc123"}
        assert _extract_next_cursor(response) == "abc123"

    def test_next_cursor_field(self):
        response = {"nextCursor": "xyz789"}
        assert _extract_next_cursor(response) == "xyz789"

    def test_no_cursor(self):
        response = {"data": [1, 2, 3]}
        assert _extract_next_cursor(response) is None

    def test_non_dict_response(self):
        assert _extract_next_cursor([1, 2, 3]) is None
        assert _extract_next_cursor("string") is None


class TestExtractData:
    def test_data_field(self):
        assert _extract_data({"data": [1, 2, 3]}) == [1, 2, 3]

    def test_items_field(self):
        assert _extract_data({"items": [1, 2]}) == [1, 2]

    def test_results_field(self):
        assert _extract_data({"results": ["a", "b"]}) == ["a", "b"]

    def test_list_directly(self):
        assert _extract_data([1, 2, 3]) == [1, 2, 3]

    def test_empty_response(self):
        assert _extract_data({}) == []


class TestPaginate:
    def test_single_page(self, auth):
        response_data = {
            "data": [{"id": 1}, {"id": 2}],
            "page": {"next": None},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            with SysdigClient(auth=auth) as client:
                pages = list(paginate(client, "GET", "/api/test"))
        assert len(pages) == 1
        assert pages[0]["data"] == [{"id": 1}, {"id": 2}]

    def test_no_page_all_stops_after_first(self, auth):
        response_data = {
            "data": [{"id": 1}],
            "page": {"next": "cursor123"},
        }
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, json=response_data)
            )
            with SysdigClient(auth=auth) as client:
                pages = list(paginate(client, "GET", "/api/test", page_all=False))
        assert len(pages) == 1

    def test_page_all_follows_cursors(self, auth):
        responses = [
            {"data": [{"id": 1}], "page": {"next": "cursor2"}},
            {"data": [{"id": 2}], "page": {"next": "cursor3"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/test").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                pages = list(paginate(client, "GET", "/api/test", page_all=True))

        assert len(pages) == 3
        assert call_count == 3

    def test_limit_passed_in_params(self, auth):
        with respx.mock(base_url=BASE_URL) as mock:
            route = mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={"data": [], "page": {"next": None}})
            )
            with SysdigClient(auth=auth) as client:
                list(paginate(client, "GET", "/api/test", limit=50))
            assert "limit=50" in str(route.calls[0].request.url)


class TestPaginateAllItems:
    def test_yields_individual_items(self, auth):
        responses = [
            {"data": [{"id": 1}, {"id": 2}], "page": {"next": "c2"}},
            {"data": [{"id": 3}], "page": {"next": None}},
        ]
        call_count = 0

        with respx.mock(base_url=BASE_URL) as mock:
            def side_effect(request):
                nonlocal call_count
                resp = responses[min(call_count, len(responses) - 1)]
                call_count += 1
                return httpx.Response(200, json=resp)

            mock.get("/api/test").mock(side_effect=side_effect)

            with SysdigClient(auth=auth) as client:
                items = list(paginate_all_items(client, "GET", "/api/test"))

        assert len(items) == 3
        assert items[0] == {"id": 1}
        assert items[2] == {"id": 3}


class TestStreamNdjson:
    def test_streams_items_as_ndjson(self, auth, capsys):
        with respx.mock(base_url=BASE_URL) as mock:
            mock.get("/api/test").mock(
                return_value=httpx.Response(200, json={
                    "data": [{"id": 1}, {"id": 2}],
                    "page": {"next": None},
                })
            )
            with SysdigClient(auth=auth) as client:
                count = stream_ndjson(client, "GET", "/api/test")

        assert count == 2
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"id": 1}
        assert json.loads(lines[1]) == {"id": 2}

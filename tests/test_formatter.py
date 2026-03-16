"""
Tests for output formatters.
"""
from __future__ import annotations

import json
import sys

import pytest

from sysdig_cli.formatter import (
    format_json,
    format_yaml,
    format_ndjson,
    format_table,
    format_csv,
    flatten_dict,
    output,
)


class TestFlattenDict:
    def test_simple_dict(self):
        result = flatten_dict({"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_nested_dict(self):
        result = flatten_dict({"a": {"b": {"c": 1}}})
        assert result == {"a.b.c": 1}

    def test_mixed_nested(self):
        result = flatten_dict({"name": "test", "meta": {"version": "1.0"}})
        assert result == {"name": "test", "meta.version": "1.0"}

    def test_list_values(self):
        result = flatten_dict({"items": [1, 2, 3]})
        assert "items.0" in result or "items" in result

    def test_empty_dict(self):
        result = flatten_dict({})
        assert result == {}

    def test_null_values(self):
        result = flatten_dict({"a": None, "b": "value"})
        assert result["a"] is None
        assert result["b"] == "value"


class TestFormatJson:
    def test_simple_dict(self):
        result = format_json({"key": "value"})
        assert '"key": "value"' in result
        data = json.loads(result)
        assert data == {"key": "value"}

    def test_list_output(self):
        result = format_json([1, 2, 3])
        assert json.loads(result) == [1, 2, 3]

    def test_indented(self):
        result = format_json({"a": 1})
        assert "\n" in result  # should be pretty-printed

    def test_handles_non_serializable(self):
        from datetime import datetime
        result = format_json({"date": datetime(2024, 1, 1)})
        assert "2024" in result


class TestFormatYaml:
    def test_simple_dict(self):
        result = format_yaml({"key": "value"})
        assert "key: value" in result

    def test_nested_dict(self):
        result = format_yaml({"outer": {"inner": "val"}})
        assert "outer:" in result
        assert "inner: val" in result


class TestFormatNdjson:
    def test_list_to_ndjson(self):
        data = [{"a": 1}, {"b": 2}, {"c": 3}]
        result = format_ndjson(data)
        lines = result.strip().split("\n")
        assert len(lines) == 3
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}
        assert json.loads(lines[2]) == {"c": 3}

    def test_single_dict(self):
        result = format_ndjson({"key": "val"})
        assert json.loads(result) == {"key": "val"}

    def test_empty_list(self):
        result = format_ndjson([])
        assert result == ""


class TestFormatTable:
    def test_list_of_dicts(self):
        data = [
            {"name": "alice", "age": 30},
            {"name": "bob", "age": 25},
        ]
        result = format_table(data)
        assert "alice" in result
        assert "bob" in result
        assert "name" in result
        assert "age" in result

    def test_sysdig_response_pattern(self):
        data = {
            "data": [
                {"id": "1", "type": "test"},
                {"id": "2", "type": "prod"},
            ]
        }
        result = format_table(data)
        assert "1" in result
        assert "2" in result

    def test_empty_list(self):
        result = format_table([])
        assert "(empty)" in result

    def test_nested_dict_shows_scalar_fields(self):
        data = [{"meta": {"version": "1.0"}, "name": "test"}]
        result = format_table(data)
        # Smart detection: top-level scalar fields are shown; 'name' is scalar
        assert "test" in result or "name" in result

    def test_long_values_truncated(self):
        data = [{"description": "x" * 200}]
        result = format_table(data)
        assert "..." in result


class TestFormatCsv:
    def test_list_to_csv(self):
        data = [{"name": "alice", "age": 30}, {"name": "bob", "age": 25}]
        result = format_csv(data)
        lines = result.strip().split("\n")
        # Header line should contain both columns
        header = lines[0]
        assert "name" in header
        assert "age" in header
        assert "alice" in result
        assert "bob" in result

    def test_empty_list(self):
        result = format_csv([])
        assert result == ""


class TestOutput:
    def test_json_to_stdout(self, capsys):
        output({"key": "value"}, fmt="json")
        captured = capsys.readouterr()
        assert '"key": "value"' in captured.out
        assert captured.err == ""

    def test_yaml_to_stdout(self, capsys):
        output({"key": "value"}, fmt="yaml")
        captured = capsys.readouterr()
        assert "key: value" in captured.out
        assert captured.err == ""

    def test_table_to_stdout(self, capsys):
        output([{"name": "test"}], fmt="table")
        captured = capsys.readouterr()
        assert "test" in captured.out
        assert captured.err == ""

    def test_ndjson_to_stdout(self, capsys):
        output([{"a": 1}, {"b": 2}], fmt="ndjson")
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert json.loads(lines[0]) == {"a": 1}

    def test_none_produces_no_output(self, capsys):
        output(None, fmt="json")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_unknown_format_defaults_json(self, capsys):
        output({"key": "val"}, fmt="unknown")
        captured = capsys.readouterr()
        assert '"key": "val"' in captured.out

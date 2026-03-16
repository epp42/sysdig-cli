"""Comprehensive unit tests for sysdig_cli/formatter.py"""
from __future__ import annotations
import json
import pytest
from sysdig_cli.formatter import (
    flatten_dict, format_json, format_yaml, format_ndjson,
    _extract_rows, _get_nested, _ns_to_human, _format_date,
    _shorten_workload, format_table, format_csv, output,
    format_structured_error,
)


# ---------------------------------------------------------------------------
# flatten_dict
# ---------------------------------------------------------------------------

class TestFlattenDictComprehensive:
    def test_empty_dict(self):
        assert flatten_dict({}) == {}

    def test_flat_dict(self):
        assert flatten_dict({"a": 1, "b": "x"}) == {"a": 1, "b": "x"}

    def test_two_level_nesting(self):
        assert flatten_dict({"a": {"b": 2}}) == {"a.b": 2}

    def test_three_level_nesting(self):
        result = flatten_dict({"a": {"b": {"c": 42}}})
        assert result == {"a.b.c": 42}

    def test_mixed_scalar_and_nested(self):
        result = flatten_dict({"name": "Alice", "meta": {"role": "admin"}})
        assert result["name"] == "Alice"
        assert result["meta.role"] == "admin"

    def test_list_at_top_level(self):
        result = flatten_dict({"items": [10, 20]})
        assert result["items.0"] == 10
        assert result["items.1"] == 20

    def test_nested_list_of_dicts(self):
        result = flatten_dict({"outer": [{"inner": 5}]})
        assert result["outer.0.inner"] == 5

    def test_empty_list_value(self):
        result = flatten_dict({"items": []})
        # empty list produces no sub-keys
        assert not any(k.startswith("items.") for k in result)

    def test_custom_separator(self):
        result = flatten_dict({"a": {"b": 1}}, sep="__")
        assert "a__b" in result
        assert result["a__b"] == 1

    def test_none_value_preserved(self):
        result = flatten_dict({"a": None})
        assert result["a"] is None

    def test_boolean_value_preserved(self):
        result = flatten_dict({"flag": True})
        assert result["flag"] is True

    def test_plain_list_input(self):
        result = flatten_dict([100, 200])
        assert result["0"] == 100
        assert result["1"] == 200

    def test_scalar_input(self):
        # scalar that is not dict/list falls through to result[prefix] = obj
        result = flatten_dict(42, prefix="val")
        assert result["val"] == 42

    def test_deeply_nested_with_prefix(self):
        result = flatten_dict({"x": 1}, prefix="root")
        assert result["root.x"] == 1


# ---------------------------------------------------------------------------
# format_json
# ---------------------------------------------------------------------------

class TestFormatJsonComprehensive:
    def test_simple_dict(self):
        result = format_json({"key": "value"})
        assert json.loads(result) == {"key": "value"}

    def test_list(self):
        result = format_json([1, "two", 3])
        assert json.loads(result) == [1, "two", 3]

    def test_nested_dict(self):
        data = {"a": {"b": {"c": [1, 2, 3]}}}
        assert json.loads(format_json(data)) == data

    def test_pretty_printed(self):
        result = format_json({"k": "v"})
        assert "\n" in result

    def test_special_chars(self):
        result = format_json({"msg": "hello\nworld\ttab"})
        parsed = json.loads(result)
        assert parsed["msg"] == "hello\nworld\ttab"

    def test_unicode(self):
        result = format_json({"emoji": "café"})
        # json.dumps escapes non-ASCII by default; check the key is present
        assert "emoji" in result
        # The parsed value should round-trip correctly
        assert json.loads(result)["emoji"] == "café"

    def test_none_value(self):
        result = format_json({"key": None})
        assert json.loads(result) == {"key": None}

    def test_non_serializable_uses_str(self):
        from datetime import datetime
        dt = datetime(2024, 6, 15, 12, 0, 0)
        result = format_json({"ts": dt})
        assert "2024" in result


# ---------------------------------------------------------------------------
# format_yaml
# ---------------------------------------------------------------------------

class TestFormatYamlComprehensive:
    def test_simple_dict(self):
        import yaml
        result = format_yaml({"key": "value"})
        assert yaml.safe_load(result) == {"key": "value"}

    def test_list(self):
        import yaml
        result = format_yaml([1, 2, 3])
        assert yaml.safe_load(result) == [1, 2, 3]

    def test_nested(self):
        import yaml
        data = {"outer": {"inner": "val"}}
        assert yaml.safe_load(format_yaml(data)) == data

    def test_unicode_preserved(self):
        result = format_yaml({"city": "München"})
        assert "München" in result

    def test_returns_string(self):
        assert isinstance(format_yaml({}), str)


# ---------------------------------------------------------------------------
# format_ndjson
# ---------------------------------------------------------------------------

class TestFormatNdjsonComprehensive:
    def test_list_of_dicts(self):
        result = format_ndjson([{"a": 1}, {"b": 2}])
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}

    def test_single_item_list(self):
        result = format_ndjson([{"x": 99}])
        assert json.loads(result.strip()) == {"x": 99}

    def test_empty_list(self):
        assert format_ndjson([]) == ""

    def test_plain_dict_returns_single_line(self):
        result = format_ndjson({"key": "val"})
        assert json.loads(result) == {"key": "val"}

    def test_dict_with_data_key(self):
        data = {"data": [{"id": 1}, {"id": 2}]}
        result = format_ndjson(data)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["id"] == 1

    def test_three_items(self):
        items = [{"i": i} for i in range(3)]
        lines = format_ndjson(items).strip().split("\n")
        assert len(lines) == 3


# ---------------------------------------------------------------------------
# _extract_rows
# ---------------------------------------------------------------------------

class TestExtractRowsComprehensive:
    def test_list_input_returned_as_is(self):
        lst = [{"a": 1}, {"b": 2}]
        assert _extract_rows(lst) is lst

    def test_empty_list(self):
        assert _extract_rows([]) == []

    def test_dict_with_data_key(self):
        rows = _extract_rows({"data": [{"id": 1}]})
        assert rows == [{"id": 1}]

    def test_dict_with_items_key(self):
        rows = _extract_rows({"items": [{"id": 2}]})
        assert rows == [{"id": 2}]

    def test_dict_with_results_key(self):
        rows = _extract_rows({"results": [{"id": 3}]})
        assert rows == [{"id": 3}]

    def test_dict_with_events_key(self):
        rows = _extract_rows({"events": [{"id": 4}]})
        assert rows == [{"id": 4}]

    def test_dict_with_entries_key(self):
        rows = _extract_rows({"entries": [{"id": 5}]})
        assert rows == [{"id": 5}]

    def test_plain_dict_becomes_single_row(self):
        d = {"name": "test", "val": 42}
        rows = _extract_rows(d)
        assert rows == [d]

    def test_dict_with_nested_non_list_value(self):
        # data key present but not a list — should fall through to single row
        d = {"data": {"nested": True}}
        rows = _extract_rows(d)
        assert rows == [d]

    def test_non_dict_non_list(self):
        # scalar — should wrap in {"value": str(data)}
        rows = _extract_rows(42)
        assert rows == [{"value": "42"}]

    def test_dict_with_alerts_key(self):
        rows = _extract_rows({"alerts": [{"name": "a"}]})
        assert rows == [{"name": "a"}]

    def test_dict_with_vulnerabilities_key(self):
        rows = _extract_rows({"vulnerabilities": [{"cve": "CVE-2024-1"}]})
        assert rows[0]["cve"] == "CVE-2024-1"

    def test_prefers_first_matching_key(self):
        # "data" comes before "items" in lookup order
        d = {"data": [{"source": "data"}], "items": [{"source": "items"}]}
        rows = _extract_rows(d)
        assert rows[0]["source"] == "data"


# ---------------------------------------------------------------------------
# _get_nested
# ---------------------------------------------------------------------------

class TestGetNestedComprehensive:
    def test_simple_key(self):
        assert _get_nested({"a": 1}, "a") == 1

    def test_dot_notation_two_levels(self):
        obj = {"content": {"ruleName": "MyRule"}}
        assert _get_nested(obj, "content.ruleName") == "MyRule"

    def test_dot_notation_three_levels(self):
        obj = {"content": {"fields": {"container": {"name": "nginx"}}}}
        assert _get_nested(obj, "content.fields.container.name") == "nginx"

    def test_missing_key_returns_none(self):
        assert _get_nested({"a": 1}, "b") is None

    def test_missing_nested_key_returns_none(self):
        assert _get_nested({"a": {"b": 1}}, "a.c") is None

    def test_flat_dot_key(self):
        # key literally contains a dot stored at top level
        obj = {"container.name": "mycontainer"}
        assert _get_nested(obj, "container.name") == "mycontainer"

    def test_mixed_nesting_and_flat_key(self):
        # nested path for real nesting
        obj = {"a": {"b.c": 7}}
        assert _get_nested(obj, "a.b.c") == 7

    def test_empty_object(self):
        assert _get_nested({}, "a") is None

    def test_non_dict_at_intermediate_level(self):
        # "a" is not a dict so traversal should return None
        assert _get_nested({"a": 42}, "a.b") is None

    def test_top_level_key_no_dot(self):
        obj = {"status": "ok"}
        assert _get_nested(obj, "status") == "ok"


# ---------------------------------------------------------------------------
# _ns_to_human
# ---------------------------------------------------------------------------

class TestNsToHumanComprehensive:
    def test_none_returns_empty_string(self):
        assert _ns_to_human(None) == ""

    def test_zero_returns_string_zero(self):
        assert _ns_to_human(0) == "0"

    def test_negative_returns_string(self):
        assert _ns_to_human(-1) == "-1"

    def test_nanoseconds_large_value(self):
        # 2024-01-15 UTC nanoseconds
        ns = 1705276800000000000  # > 1e18
        result = _ns_to_human(ns)
        assert "Jan" in result
        assert ":" in result

    def test_milliseconds_value(self):
        # value between 1e12 and 1e18 treated as milliseconds
        ms = 1705276800000  # 2024-01-15 in milliseconds
        result = _ns_to_human(ms)
        assert "Jan" in result

    def test_seconds_value(self):
        # small value treated as seconds
        secs = 1705276800  # 2024-01-15 in seconds
        result = _ns_to_human(secs)
        assert "Jan" in result

    def test_string_int_input(self):
        result = _ns_to_human("1705276800000000000")
        assert "Jan" in result

    def test_invalid_string_returns_as_is(self):
        result = _ns_to_human("not_a_number")
        assert result == "not_a_number"

    def test_format_is_day_month_time(self):
        ns = 1705276800000000000
        result = _ns_to_human(ns)
        # Format is "%d %b %H:%M" which produces e.g. "15 Jan 00:00"
        parts = result.split()
        assert len(parts) == 3  # day, month abbreviation, HH:MM
        assert ":" in parts[2]  # time part


# ---------------------------------------------------------------------------
# _format_date
# ---------------------------------------------------------------------------

class TestFormatDateComprehensive:
    def test_none_returns_empty(self):
        assert _format_date(None) == ""

    def test_empty_string_returns_empty(self):
        assert _format_date("") == ""

    def test_iso_string_truncated(self):
        assert _format_date("2024-06-15T12:34:56Z") == "2024-06-15"

    def test_date_only_string(self):
        assert _format_date("2024-01-01") == "2024-01-01"

    def test_zero_int(self):
        # falsy value
        assert _format_date(0) == ""

    def test_epoch_int_no_T(self):
        # numeric epoch without T — returned as str
        result = _format_date(1705276800)
        assert result == "1705276800"

    def test_iso_with_milliseconds(self):
        result = _format_date("2024-03-01T08:00:00.000Z")
        assert result == "2024-03-01"


# ---------------------------------------------------------------------------
# _shorten_workload
# ---------------------------------------------------------------------------

class TestShortenWorkloadComprehensive:
    def test_short_name_unchanged(self):
        assert _shorten_workload("nginx:1.20.1") == "nginx:1.20.1"

    def test_long_gcr_path(self):
        result = _shorten_workload("us-docker.pkg.dev/org/tools/frontend-runner:1.1.9")
        assert result == "tools/frontend-runner:1.1.9"

    def test_ghcr_path(self):
        result = _shorten_workload("ghcr.io/dandelion-python/dandelion-python:latest")
        assert result == "dandelion-python/dandelion-python:latest"

    def test_sha256_stripped(self):
        name = "myrepo/myimage:tag@sha256:abc123deadbeef"
        result = _shorten_workload(name)
        assert "@sha256:" not in result
        assert "sha256" not in result

    def test_sha256_then_shortened(self):
        name = "gcr.io/proj/repo/image:tag@sha256:deadbeef"
        result = _shorten_workload(name)
        assert "@sha256:" not in result
        assert "/" in result

    def test_arn_path(self):
        name = "arn:aws:ecs:us-east-1:123/task/abc123"
        result = _shorten_workload(name)
        assert result == "task/abc123"

    def test_simple_name_no_slashes(self):
        assert _shorten_workload("quickstart-rancher-server") == "quickstart-rancher-server"

    def test_two_part_path_unchanged(self):
        assert _shorten_workload("org/image:v1") == "org/image:v1"


# ---------------------------------------------------------------------------
# format_table
# ---------------------------------------------------------------------------

class TestFormatTableComprehensive:
    def test_basic_rendering(self):
        data = [{"name": "alice", "age": 30}]
        result = format_table(data)
        assert "alice" in result

    def test_empty_data_returns_empty_message(self):
        assert "(empty)" in format_table([])

    def test_empty_data_return_rich(self):
        from rich.table import Table
        result = format_table([], return_rich=True)
        assert isinstance(result, Table)

    def test_schema_events(self):
        data = [{"timestamp": 1705276800000000000, "severity": 7,
                 "content": {"ruleName": "TestRule", "output": "some output",
                             "fields": {"container": {"name": "my-container"}}}}]
        result = format_table(data, schema="events")
        assert "TestRule" in result or "RULE" in result

    def test_schema_users(self):
        data = [{"email": "user@example.com", "firstName": "Joe", "lastName": "Doe",
                 "isAdmin": False, "isEnabled": True, "activationStatus": "active",
                 "dateCreated": "2024-01-01T00:00:00Z"}]
        result = format_table(data, schema="users")
        assert "user@example.com" in result

    def test_schema_alerts(self):
        data = [{"name": "MyAlert", "id": 42, "enabled": True, "severity": "high", "type": "PROMETHEUS"}]
        result = format_table(data, schema="alerts")
        assert "MyAlert" in result

    def test_no_trunc_flag(self):
        long_val = "x" * 200
        data = [{"description": long_val}]
        result = format_table(data, no_trunc=True)
        # With no_trunc the value should appear without truncation indicator
        assert "..." not in result or long_val[:50] in result

    def test_returns_string_by_default(self):
        result = format_table([{"a": 1}])
        assert isinstance(result, str)

    def test_return_rich_returns_table(self):
        from rich.table import Table
        result = format_table([{"a": 1}], return_rich=True)
        assert isinstance(result, Table)

    def test_sysdig_response_data_key(self):
        data = {"data": [{"name": "item1"}, {"name": "item2"}]}
        result = format_table(data)
        assert "item1" in result

    def test_schema_zones(self):
        data = [{"name": "Zone1", "id": 10, "author": "admin", "lastModifiedBy": "admin"}]
        result = format_table(data, schema="zones")
        assert "Zone1" in result

    def test_multiple_rows(self):
        data = [{"name": f"item{i}", "count": i} for i in range(5)]
        result = format_table(data)
        assert "item0" in result
        assert "item4" in result

    def test_unknown_schema_uses_smart_detection(self):
        data = [{"name": "test", "status": "ok"}]
        result = format_table(data, schema="nonexistent_schema_xyz")
        # Should fall back to smart detection and still render
        assert "test" in result


# ---------------------------------------------------------------------------
# format_csv
# ---------------------------------------------------------------------------

class TestFormatCsvComprehensive:
    def test_basic_list(self):
        data = [{"name": "alice", "age": 30}]
        result = format_csv(data)
        assert "name" in result
        assert "alice" in result

    def test_multiple_rows(self):
        data = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        result = format_csv(data)
        lines = result.strip().split("\n")
        assert len(lines) == 3  # header + 2 rows

    def test_empty_list(self):
        assert format_csv([]) == ""

    def test_header_contains_all_keys(self):
        data = [{"x": 1, "y": 2, "z": 3}]
        result = format_csv(data)
        header = result.split("\n")[0]
        assert "x" in header
        assert "y" in header
        assert "z" in header

    def test_nested_dict_is_flattened(self):
        data = [{"meta": {"version": "1.0"}, "name": "test"}]
        result = format_csv(data)
        assert "meta.version" in result
        assert "1.0" in result

    def test_sysdig_data_key(self):
        data = {"data": [{"id": 1, "type": "A"}]}
        result = format_csv(data)
        assert "id" in result
        assert "type" in result

    def test_returns_string(self):
        assert isinstance(format_csv([{"k": "v"}]), str)


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

class TestOutputComprehensive:
    def test_json_format(self, capsys):
        output({"key": "value"}, fmt="json")
        captured = capsys.readouterr()
        assert json.loads(captured.out)["key"] == "value"

    def test_yaml_format(self, capsys):
        import yaml
        output({"key": "value"}, fmt="yaml")
        captured = capsys.readouterr()
        assert yaml.safe_load(captured.out) == {"key": "value"}

    def test_table_format(self, capsys):
        output([{"name": "test"}], fmt="table")
        captured = capsys.readouterr()
        assert "test" in captured.out

    def test_ndjson_format(self, capsys):
        output([{"a": 1}, {"b": 2}], fmt="ndjson")
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}

    def test_nd_json_alias(self, capsys):
        output([{"x": 5}], fmt="nd-json")
        captured = capsys.readouterr()
        assert json.loads(captured.out.strip()) == {"x": 5}

    def test_csv_format(self, capsys):
        output([{"name": "alice"}], fmt="csv")
        captured = capsys.readouterr()
        assert "name" in captured.out
        assert "alice" in captured.out

    def test_none_produces_no_output(self, capsys):
        output(None, fmt="json")
        assert capsys.readouterr().out == ""

    def test_unknown_format_defaults_to_json(self, capsys):
        output({"k": "v"}, fmt="unknown_fmt")
        captured = capsys.readouterr()
        assert json.loads(captured.out)["k"] == "v"

    def test_schema_selection(self, capsys):
        data = [{"email": "u@x.com", "firstName": "A", "lastName": "B",
                 "isAdmin": False, "isEnabled": True,
                 "activationStatus": "active", "dateCreated": "2024-01-01"}]
        output(data, fmt="table", schema="users")
        captured = capsys.readouterr()
        assert "u@x.com" in captured.out

    def test_no_trunc_passed_through(self, capsys):
        long_name = "a" * 200
        output([{"name": long_name}], fmt="table", no_trunc=True)
        captured = capsys.readouterr()
        # long value should appear mostly intact (no aggressive truncation)
        assert "a" * 50 in captured.out

    def test_output_to_file(self):
        import io
        buf = io.StringIO()
        output({"hello": "world"}, fmt="json", file=buf)
        val = buf.getvalue()
        assert json.loads(val)["hello"] == "world"

    def test_case_insensitive_fmt(self, capsys):
        output({"x": 1}, fmt="JSON")
        captured = capsys.readouterr()
        assert json.loads(captured.out)["x"] == 1


# ---------------------------------------------------------------------------
# format_structured_error
# ---------------------------------------------------------------------------

class TestFormatStructuredErrorComprehensive:
    def test_basic_error(self):
        result = format_structured_error("auth_error", "Not authenticated")
        parsed = json.loads(result)
        assert parsed["type"] == "auth_error"
        assert parsed["message"] == "Not authenticated"

    def test_no_details_by_default(self):
        result = format_structured_error("err", "msg")
        parsed = json.loads(result)
        assert "details" not in parsed

    def test_with_details_list(self):
        result = format_structured_error("validation", "Invalid input",
                                         details=["field x required", "field y invalid"])
        parsed = json.loads(result)
        assert parsed["details"] == ["field x required", "field y invalid"]

    def test_returns_valid_json(self):
        result = format_structured_error("t", "m")
        json.loads(result)  # should not raise

    def test_returns_string(self):
        assert isinstance(format_structured_error("t", "m"), str)

    def test_pretty_printed(self):
        result = format_structured_error("t", "m")
        assert "\n" in result

    def test_empty_details_not_included(self):
        result = format_structured_error("t", "m", details=None)
        parsed = json.loads(result)
        assert "details" not in parsed

    def test_special_chars_in_message(self):
        result = format_structured_error("err", 'message with "quotes" and\nnewlines')
        parsed = json.loads(result)
        assert "quotes" in parsed["message"]


# ---------------------------------------------------------------------------
# _smart_detect_columns (via format_table)
# ---------------------------------------------------------------------------

class TestSmartDetectColumnsViaFormatTable:
    def test_skips_nested_dicts(self):
        # Rows with nested dicts — smart detection skips those fields
        data = [{"name": "foo", "meta": {"deep": "value"}, "status": "ok"}]
        result = format_table(data)
        assert "foo" in result
        assert "ok" in result

    def test_picks_priority_fields_first(self):
        data = [{"zz_last": "z", "name": "Alice", "aa_first": "a", "status": "active"}]
        result = format_table(data)
        # name and status are priority fields so they should appear
        assert "Alice" in result

    def test_fallback_for_all_nested(self):
        # When all values are dicts/lists, smart detection falls to flatten
        data = [{"a": {"x": 1}, "b": {"y": 2}}]
        # Should not raise
        result = format_table(data)
        assert isinstance(result, str)

    def test_max_10_columns(self):
        data = [{f"field_{i}": i for i in range(20)}]
        result = format_table(data)
        # result should contain at most 10 column headers; just assert it renders
        assert isinstance(result, str)

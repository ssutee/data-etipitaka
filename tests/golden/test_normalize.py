from normalize import normalize_json_value


def test_timestamp_is_masked():
    value = {"created_at": "2020-01-01T00:00:00Z", "name": "x"}
    assert normalize_json_value(value) == {"created_at": "<TIMESTAMP>", "name": "x"}


def test_nested_timestamp_in_serialized_string_is_masked():
    raw = '[{"fields": {"created_at": "2020-01-01T09:30:00.123Z"}}]'
    out = normalize_json_value({"items": raw})
    assert "<TIMESTAMP>" in out["items"]
    assert "2020-01-01" not in out["items"]

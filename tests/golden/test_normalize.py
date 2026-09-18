from normalize import normalize_json_value


def test_timestamp_is_masked():
    value = {"created_at": "2020-01-01T00:00:00Z", "name": "x"}
    assert normalize_json_value(value) == {"created_at": "<TIMESTAMP>", "name": "x"}


def test_nested_timestamp_in_serialized_string_is_masked():
    raw = '[{"fields": {"created_at": "2020-01-01T09:30:00.123Z"}}]'
    out = normalize_json_value({"items": raw})
    assert "<TIMESTAMP>" in out["items"]
    assert "2020-01-01" not in out["items"]


def test_webauthn_challenges_are_masked():
    value = {"challenge_id": "abc", "options": {"challenge": "xyz", "rpId": "data.etipitaka.com"}}
    assert normalize_json_value(value) == {
        "challenge_id": "<CHALLENGE>",
        "options": {"challenge": "<CHALLENGE>", "rpId": "data.etipitaka.com"},
    }


def test_desktop_pairing_codes_are_masked_but_the_origin_survives():
    # Only the random code inside verification_url is masked: its origin and
    # path are the part worth snapshotting, since building them from the wrong
    # setting would send desktop users to the wrong host.
    value = {
        "device_code": "raw-device-code",
        "user_code": "K7QP-4M2X",
        "verification_url": "https://data.etipitaka.com/desktop/?code=K7QP-4M2X",
        "interval": 5,
        "expires_in": 600,
    }
    assert normalize_json_value(value) == {
        "device_code": "<CHALLENGE>",
        "user_code": "<CHALLENGE>",
        "verification_url": "https://data.etipitaka.com/desktop/?code=<USER_CODE>",
        "interval": 5,
        "expires_in": 600,
    }

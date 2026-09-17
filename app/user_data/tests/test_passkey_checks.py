import pytest

from user_data.checks import (check_passkey_android_config, check_passkey_session_engine,
                              check_passkey_web_origin)


def _valid_fingerprint():
    return ':'.join(['AB'] * 32)


def test_valid_config_passes(settings):
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.E-Tipitaka-Plus'
    settings.PASSKEY_ANDROID_CERT_SHA256 = [_valid_fingerprint()]
    assert check_passkey_android_config(None) == []


def test_empty_pair_passes(settings):
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = []
    assert check_passkey_android_config(None) == []


@pytest.mark.parametrize('fingerprint', [
    'AB:CD',        # too short -- decodes to 2 bytes, not 32
    'A' * 63,       # odd-length hex string
    'zz' * 32,      # right length but not hex digits
], ids=['short', 'odd-length', 'non-hex'])
def test_bad_fingerprint_fails_with_expected_id(settings, fingerprint):
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.E-Tipitaka-Plus'
    settings.PASSKEY_ANDROID_CERT_SHA256 = [fingerprint]

    errors = check_passkey_android_config(None)

    assert [e.id for e in errors] == ['user_data.E002']


def test_package_without_fingerprint_fails(settings):
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.E-Tipitaka-Plus'
    settings.PASSKEY_ANDROID_CERT_SHA256 = []

    errors = check_passkey_android_config(None)

    assert [e.id for e in errors] == ['user_data.E001']


def test_fingerprint_without_package_fails(settings):
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = [_valid_fingerprint()]

    errors = check_passkey_android_config(None)

    assert [e.id for e in errors] == ['user_data.E001']


# --- check_passkey_web_origin ------------------------------------------------

def test_web_origin_passes_with_defaults(settings):
    # No override: PASSKEY_WEB_ORIGIN/PASSKEY_RP_ID fall back to
    # OAUTH_ISSUER_URL and its hostname, which necessarily agree.
    settings.PASSKEY_WEB_ORIGIN = ''
    settings.PASSKEY_RP_ID = ''
    assert check_passkey_web_origin(None) == []


@pytest.mark.parametrize('origin', [
    'not-a-url',      # no scheme -- urlparse gives it none
    'https://',        # scheme but no host
    'ftp://example.com',  # wrong scheme
], ids=['no-scheme', 'no-host', 'wrong-scheme'])
def test_web_origin_rejects_unparseable_origin(settings, origin):
    settings.PASSKEY_WEB_ORIGIN = origin

    errors = check_passkey_web_origin(None)

    assert [e.id for e in errors] == ['user_data.E003']


def test_web_origin_accepts_matching_rp_id(settings):
    settings.PASSKEY_WEB_ORIGIN = 'https://example.com'
    settings.PASSKEY_RP_ID = 'example.com'
    assert check_passkey_web_origin(None) == []


def test_web_origin_accepts_rp_id_as_registrable_suffix(settings):
    settings.PASSKEY_WEB_ORIGIN = 'https://login.example.com'
    settings.PASSKEY_RP_ID = 'example.com'
    assert check_passkey_web_origin(None) == []


def test_web_origin_rejects_mismatched_rp_id(settings):
    settings.PASSKEY_WEB_ORIGIN = 'https://example.com'
    settings.PASSKEY_RP_ID = 'other.com'

    errors = check_passkey_web_origin(None)

    assert [e.id for e in errors] == ['user_data.E004']


def test_web_origin_rejects_rp_id_that_is_only_a_substring(settings):
    # 'ample.com' is a substring of 'example.com' but not a registrable
    # suffix of it (no '.' boundary) -- must not be accepted as one.
    settings.PASSKEY_WEB_ORIGIN = 'https://example.com'
    settings.PASSKEY_RP_ID = 'ample.com'

    errors = check_passkey_web_origin(None)

    assert [e.id for e in errors] == ['user_data.E004']


# --- check_passkey_session_engine --------------------------------------------

def test_session_engine_passes_for_db_backend(settings):
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.db'
    assert check_passkey_session_engine(None) == []


def test_session_engine_fails_for_other_backends(settings):
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

    errors = check_passkey_session_engine(None)

    assert [e.id for e in errors] == ['user_data.E005']

import base64

import pytest

from user_data import passkey_config


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def test_rp_id_defaults_to_issuer_host(settings):
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'
    settings.PASSKEY_RP_ID = ''
    assert passkey_config.rp_id() == 'data.etipitaka.com'


def test_rp_id_override(settings):
    settings.PASSKEY_RP_ID = 'localhost'
    assert passkey_config.rp_id() == 'localhost'


def test_web_origin_defaults_to_issuer(settings):
    settings.OAUTH_ISSUER_URL = 'https://data.etipitaka.com'
    settings.PASSKEY_WEB_ORIGIN = ''
    assert passkey_config.web_origin() == 'https://data.etipitaka.com'


def test_web_origin_override_drops_trailing_slash(settings):
    settings.PASSKEY_WEB_ORIGIN = 'http://localhost:1338/'
    assert passkey_config.web_origin() == 'http://localhost:1338'


def test_android_origin_from_colon_hex_fingerprint():
    fingerprint = ':'.join(['AB'] * 32)
    assert passkey_config.android_origin(fingerprint) == (
        'android:apk-key-hash:' + _b64url(bytes([0xAB]) * 32))


@pytest.mark.parametrize('fingerprint', ['AB:CD', 'not-hex'])
def test_android_origin_rejects_non_sha256_fingerprint(fingerprint):
    with pytest.raises(ValueError):
        passkey_config.android_origin(fingerprint)


def test_expected_origins_lists_web_then_android(settings):
    settings.PASSKEY_WEB_ORIGIN = 'https://data.etipitaka.com'
    settings.PASSKEY_ANDROID_CERT_SHA256 = [':'.join(['01'] * 32)]
    assert passkey_config.expected_origins() == [
        'https://data.etipitaka.com',
        'android:apk-key-hash:' + _b64url(bytes([1]) * 32)]


def test_settings_defaults(settings):
    assert settings.PASSKEY_RP_NAME == 'E-Tipitaka'
    assert settings.PASSKEY_CHALLENGE_TTL == 300
    assert 'A6DJDJ7527.com.watnapp.E-Tipitaka-Plus' in settings.PASSKEY_IOS_APP_IDS
    assert 'passkey' in settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']

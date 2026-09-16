import pytest

from user_data.checks import check_passkey_android_config


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

"""Relying-party configuration for passkeys, read from settings at call time."""
import base64
from urllib.parse import urlparse

from django.conf import settings


def rp_id():
    return settings.PASSKEY_RP_ID or urlparse(settings.OAUTH_ISSUER_URL).hostname


def web_origin():
    return (settings.PASSKEY_WEB_ORIGIN or settings.OAUTH_ISSUER_URL).rstrip('/')


def android_origin(fingerprint):
    """Colon-hex SHA-256 signing-cert fingerprint -> WebAuthn origin of the Android app."""
    raw = bytes.fromhex(fingerprint.replace(':', '').strip())
    if len(raw) != 32:
        raise ValueError('expected a SHA-256 certificate fingerprint')
    return 'android:apk-key-hash:' + base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def expected_origins():
    # iOS native apps report https://<rp id>, so the web origin covers them.
    return [web_origin()] + [android_origin(fp) for fp in settings.PASSKEY_ANDROID_CERT_SHA256]

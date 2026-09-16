"""Boot-time validation for passkey (WebAuthn) settings.

Registered with Django's system-check framework (see UserDataConfig.ready)
so a bad PASSKEY_ANDROID_* configuration fails `manage.py check` -- and
therefore the deploy check gate -- with a clear message, instead of
surfacing later as a 500 at login time or a silently 404'd assetlinks file.
"""
from django.conf import settings
from django.core.checks import Error, register

from user_data import passkey_config


@register()
def check_passkey_android_config(app_configs, **kwargs):
    errors = []

    package = settings.PASSKEY_ANDROID_PACKAGE
    fingerprints = settings.PASSKEY_ANDROID_CERT_SHA256

    if bool(package) != bool(fingerprints):
        errors.append(Error(
            'PASSKEY_ANDROID_PACKAGE and PASSKEY_ANDROID_CERT_SHA256 must '
            'both be set or both left empty.',
            hint=(
                'Set both env vars to add the Android app as a passkey '
                'origin (also feeds the /.well-known/assetlinks.json '
                'response), or leave both unset to disable it.'
            ),
            id='user_data.E001',
        ))

    for fingerprint in fingerprints:
        try:
            # Reuses the exact rule passkey_config.android_origin applies at
            # request time, so "passes check" and "works at login" agree.
            passkey_config.android_origin(fingerprint)
        except ValueError:
            errors.append(Error(
                'PASSKEY_ANDROID_CERT_SHA256 entry %r is not a 32-byte '
                'SHA-256 certificate fingerprint.' % (fingerprint,),
                hint=(
                    'Use the colon- or non-colon-separated hex SHA-256 '
                    'signing certificate fingerprint (64 hex characters).'
                ),
                id='user_data.E002',
            ))

    return errors

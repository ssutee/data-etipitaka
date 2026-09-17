"""Boot-time validation for passkey (WebAuthn) settings.

Registered with Django's system-check framework (see UserDataConfig.ready)
so a bad PASSKEY_* configuration fails `manage.py check` -- and therefore
the deploy check gate (see deploy.sh) -- with a clear message, instead of
surfacing later as a 500 at login time, a silently 404'd assetlinks file,
or (worse) every WebAuthn ceremony failing verification with the same
generic "Unable to log in" 400 a wrong credential would also produce.
"""
from urllib.parse import urlparse

from django.conf import settings
from django.core.checks import Error, register
from django.core.exceptions import ImproperlyConfigured

from user_data import passkey_config
from user_data.account_tokens import check_session_engine


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


@register()
def check_passkey_web_origin(app_configs, **kwargs):
    """Validate PASSKEY_WEB_ORIGIN (or its OAUTH_ISSUER_URL fallback) and
    the relying-party ID derived from it.

    Every WebAuthn ceremony calls passkey_config.rp_id() and
    passkey_config.web_origin() (via config.expected_origins()) to build
    the options it sends the browser and to verify what comes back --
    reusing those exact functions here, rather than re-reading the raw env
    vars, keeps "passes check" and "works at login" in agreement the same
    way check_passkey_android_config already does for the Android pair.

    A mismatch here doesn't 500 or 404 -- verify_authentication_response
    and verify_registration_response just fail (a rp_id hash or origin
    that doesn't match what they were told to expect), which every caller
    maps to the same generic "Unable to log in with provided credentials"
    400 a wrong credential produces. With no LOGGING configuration, that
    leaves no trace at all: every single login, signup, registration and
    recovery ceremony fails, indistinguishably from user error.
    """
    errors = []

    origin = passkey_config.web_origin()
    parsed = urlparse(origin)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        errors.append(Error(
            'PASSKEY_WEB_ORIGIN (or its OAUTH_ISSUER_URL fallback), %r, '
            'must be an absolute http:// or https:// URL with a hostname.'
            % (origin,),
            hint=(
                'Set PASSKEY_WEB_ORIGIN to the exact origin the login/'
                'signup/recovery pages are served from (scheme + host '
                '[+ port], no path), e.g. https://data.etipitaka.com.'
            ),
            id='user_data.E003',
        ))
        # Nothing usable to compare rp_id against.
        return errors

    hostname = parsed.hostname
    rp_id = passkey_config.rp_id()
    if rp_id != hostname and not hostname.endswith('.' + rp_id):
        errors.append(Error(
            'PASSKEY_RP_ID %r is not the web origin\'s hostname (%r) or a '
            'registrable suffix of it.' % (rp_id, hostname),
            hint=(
                'Per the WebAuthn spec, the relying-party ID must equal '
                'the origin\'s effective domain or be a registrable '
                'domain suffix of it, or every ceremony will fail. Set '
                'PASSKEY_RP_ID to that hostname (or a parent domain of '
                'it), or fix PASSKEY_WEB_ORIGIN to match.'
            ),
            id='user_data.E004',
        ))

    return errors


@register()
def check_passkey_session_engine(app_configs, **kwargs):
    """Passkey/password recovery deletes the caller's other sessions by
    reading and deleting their rows directly (see
    account_tokens.delete_user_sessions), which requires plain, uncached
    'db' sessions -- check_session_engine() already enforces this, but only
    lazily, the first time recovery actually runs, so a misconfiguration
    would otherwise surface as a 500 on /account/recover/passkey/begin/ --
    exactly when someone who has lost their device is trying to get back
    in. Reuses that exact check so "passes check" and "works at recovery"
    agree, the same way check_passkey_android_config does for the Android
    pair.

    settings.SESSION_ENGINE isn't declared in settings.py at all -- the
    project relies on Django's own default, which happens to already be
    'django.contrib.sessions.backends.db'. Declaring it explicitly there
    is worth considering so this isn't silently one Django-version-default
    change (or one careless local_settings.py override) away from breaking.
    """
    try:
        check_session_engine()
    except ImproperlyConfigured as exc:
        return [Error(str(exc), hint=(
            "Set SESSION_ENGINE = 'django.contrib.sessions.backends.db' "
            '(Django\'s own default -- see settings.py) and remove any '
            'override to a different engine.'
        ), id='user_data.E005')]
    return []

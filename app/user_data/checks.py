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
    # A WebAuthn/RFC 6454 origin is scheme + host [+ port] ONLY -- a
    # path, query or fragment isn't part of it and isn't meaningful here
    # (e.g. PASSKEY_WEB_ORIGIN=https://data.etipitaka.com/login parses
    # "successfully" but is not the origin any browser will ever report,
    # so it would fail expected_origin on every single ceremony).
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        errors.append(Error(
            'PASSKEY_WEB_ORIGIN (or its OAUTH_ISSUER_URL fallback), %r, '
            'must be an absolute http:// or https:// URL with a hostname '
            'and nothing else -- no path (other than a bare "/"), query '
            'or fragment.' % (origin,),
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
    if not rp_id:
        errors.append(Error(
            'PASSKEY_RP_ID could not be determined: it is unset, and '
            'OAUTH_ISSUER_URL (%r) has no scheme, so urlparse(...).hostname '
            'is empty too.' % (settings.OAUTH_ISSUER_URL,),
            hint=(
                'Set PASSKEY_RP_ID explicitly, or fix OAUTH_ISSUER_URL to '
                'be an absolute http:// or https:// URL.'
            ),
            id='user_data.E006',
        ))
        # Nothing left that can be safely compared against hostname.
        return errors

    if rp_id != 'localhost' and '.' not in rp_id:
        errors.append(Error(
            'PASSKEY_RP_ID %r has no dot and is not "localhost".' % (rp_id,),
            hint=(
                'A bare, single-label relying-party ID (e.g. a bare TLD '
                'like "com") is never a legitimate registrable domain -- '
                'the naive suffix check below can even be fooled into '
                'accepting one (e.g. "com" looks like a "suffix" of any '
                '*.com hostname). Set PASSKEY_RP_ID to a real registrable '
                'domain, or "localhost" for local development.'
            ),
            id='user_data.E007',
        ))
        return errors

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

    settings.SESSION_ENGINE is declared explicitly in settings.py (as
    'django.contrib.sessions.backends.db', matching Django's own default)
    specifically so this can't silently drift -- this check exists for the
    remaining way it still could: a local_settings.py override (imported
    at the bottom of settings.py) replacing it with something else.
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

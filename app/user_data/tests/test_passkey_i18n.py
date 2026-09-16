from pathlib import Path

import pytest
from django.core import mail
from django.template.loader import render_to_string
from django.utils import translation

# Derived straight from the source (grep for `{% trans %}`, `{% blocktrans %}`
# and `_(...)` across the passkey templates/views -- see the docstring below
# for why this can't just be copied from the implementation plan.
#
# NOTE: the plan this task came from ships a NEW_MSGIDS list that went stale
# while Tasks 6-21 were implemented:
#   - 'Create a new passkey on this device to sign in again.' never existed;
#     password_reset_confirm.html's real blocktrans names the account
#     (Task 16 review decision, so a reset-link holder sees whose account a
#     new passkey would bind to), giving the msgid below instead.
#   - 'Malformed request.' (passkey_views.py, drf_handlers.py),
#     'You have reached the maximum number of passkeys.' (passkey_views.py)
#     and 'Enter your current password.' (account_security.html) exist in
#     code but were missing from the plan's list entirely.
#
# Task 23 added two client-side strings, rendered into window.i18n by
# base.html and read by passkey.js's errorMessage() on an HTTP 429. The
# '{seconds}' in passkeyRateLimitedWait is a literal token passkey.js
# substitutes itself with String.replace(), not Django interpolation --
# see test_rate_limited_wait_translation_keeps_seconds_token below.
LOCALE_DIR = Path(__file__).resolve().parents[2] / 'locale' / 'th' / 'LC_MESSAGES'
PO_PATH = LOCALE_DIR / 'django.po'
MO_PATH = LOCALE_DIR / 'django.mo'

NEW_MSGIDS = [
    'Malformed request.',
    'A passkey was added to your E-Tipitaka account',
    'Passkey registration failed.',
    'Re-authentication failed.',
    'Passkey not found.',
    'Enter a name for this passkey.',
    'Your account must keep at least one way to sign in.',
    'You have reached the maximum number of passkeys.',
    'Enter a valid username. This value may contain only letters, numbers, and '
    '@/./+/-/_ characters.',
    'Sign in with a passkey',
    'Create account with a passkey',
    'Sign up with a password instead',
    'Sign-in and security',
    'This browser does not support passkeys.',
    'Passkeys',
    'Name',
    'Type',
    'Last used',
    'You have no passkeys yet.',
    'Current password',
    'Enter your current password.',
    'Add a passkey',
    'Remove password',
    'Never',
    'Synced',
    'This device only',
    'Rename',
    'New name for this passkey',
    'Your account has a password.',
    'Your account has no password. You sign in with a passkey.',
    'Security',
    'The passkey request was cancelled.',
    'Too many attempts. Please wait a moment and try again.',
    'Too many attempts. Please wait {seconds} seconds and try again.',
    'Create a new passkey for %(username)s to sign in again.',
    'Create a new passkey',
    'Or set a new password:',
    'Hello %(username)s,',
    'We received a request to recover your E-Tipitaka account.',
    'Open the link below to set a new password or create a new passkey:',
    'If you did not ask for this, you can ignore this e-mail.',
    'A new passkey named "%(passkey_name)s" was added to your E-Tipitaka account.',
    'You can review your passkeys here:',
    'If this was not you, recover your account now and remove the passkey:',
]


@pytest.mark.parametrize('msgid', NEW_MSGIDS)
def test_passkey_string_has_thai_translation(msgid):
    with translation.override('th'):
        assert translation.gettext(msgid) != msgid


def test_all_new_msgids_have_thai_translations():
    """One assertion covering every NEW_MSGIDS entry at once, so a future
    string change (an edited msgid, a stale plan copied verbatim again)
    shows the whole gap in one failure instead of one parametrize case at a
    time."""
    with translation.override('th'):
        missing = [msgid for msgid in NEW_MSGIDS if translation.gettext(msgid) == msgid]
    assert not missing


def test_rate_limited_wait_translation_keeps_seconds_token():
    """'{seconds}' is not Django interpolation -- passkey.js splices the
    retry-after value in with String.replace('{seconds}', ...) after
    gettext runs. If a translation drops or mistypes the literal token, the
    message silently shows no number instead of erroring, so this is
    checked on its own rather than trusting the general "differs from the
    English" assertion above to catch it."""
    with translation.override('th'):
        translated = translation.gettext(
            'Too many attempts. Please wait {seconds} seconds and try again.')
    assert '{seconds}' in translated


def test_compiled_mo_is_not_older_than_po_source():
    """The container has no gettext tools to recompile django.mo, so pytest
    can only catch a forgotten `msgfmt` by comparing file times -- it cannot
    verify the .mo's *content* matches the .po beyond what the translation
    tests above already exercise at runtime."""
    assert MO_PATH.stat().st_mtime >= PO_PATH.stat().st_mtime


def test_passkey_added_email_renders_in_thai():
    with translation.override('th'):
        body = render_to_string('email/passkey_added.txt', {
            'username': 'alice', 'passkey_name': 'Phone',
            'security_url': 'https://x/account/security/', 'reset_url': 'https://x/password_reset/'})
    assert 'สวัสดี alice' in body
    assert '"Phone"' in body
    assert 'https://x/account/security/' in body


@pytest.mark.django_db
def test_recovery_email_renders_in_thai(client, alice):
    """The password-reset email goes through the real view (AccountRecoveryForm
    -> PasswordResetView.form_valid -> send_mail), not render_to_string, so
    that the uid/token/user context PasswordResetForm.save builds is exactly
    what production sends -- a hand-built context could drift from it. No
    language cookie is set: LanguageMiddleware defaults an anonymous request
    to Thai (see test_i18n.py's test_no_cookie_defaults_to_thai), matching
    every other request in test_recovery.py."""
    mail.outbox.clear()
    response = client.post('/password_reset/', {'email': alice.email})
    assert response.status_code == 302
    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert 'สวัสดี alice' in body
    assert 'เราได้รับคำขอกู้คืนบัญชี E-Tipitaka ของคุณ' in body
    assert '/reset/' in body

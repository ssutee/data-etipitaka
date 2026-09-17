import ast
import gettext
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
    # Task 27: notify on passkey deletion and password removal.
    'A passkey was deleted from your E-Tipitaka account',
    'Your password was removed from your E-Tipitaka account',
    'The passkey named "%(passkey_name)s" was deleted from your E-Tipitaka account.',
    'If this was not you, recover your account now:',
    'Your password was removed from your E-Tipitaka account. You now sign in '
    'with a passkey only.',
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


def _po_catalog(path):
    """Parse django.po into the {key: msgstr} shape gettext.GNUTranslations
    builds from a compiled .mo: plain msgid -> str, msgctxt as
    'ctxt\\x04msgid', plural forms as (msgid, n). Mirrors what msgfmt keeps:
    the header, fuzzy entries, obsolete '#~' entries and untranslated
    entries never reach the .mo."""
    entries, entry, field, fuzzy = [], {}, None, False
    for raw in path.read_text(encoding='utf-8').splitlines() + ['']:
        line = raw.strip()
        if not line:
            if 'msgid' in entry and not fuzzy:
                entries.append(entry)
            entry, field, fuzzy = {}, None, False
        elif line.startswith('#'):
            fuzzy = fuzzy or (line.startswith('#,') and 'fuzzy' in line)
        elif line.startswith('"'):
            entry[field] += ast.literal_eval(line)
        else:
            field, _, value = line.partition(' ')
            entry[field] = ast.literal_eval(value)

    catalog = {}
    for entry in entries:
        if entry['msgid'] == '':
            continue
        key = entry['msgctxt'] + '\x04' + entry['msgid'] if 'msgctxt' in entry else entry['msgid']
        if 'msgid_plural' in entry:
            forms = {int(f[len('msgstr['):-1]): v for f, v in entry.items() if f.startswith('msgstr[')}
            if forms and all(forms.values()):
                catalog.update({(key, n): v for n, v in forms.items()})
        elif entry.get('msgstr'):
            catalog[key] = entry['msgstr']
    return catalog


def test_compiled_mo_matches_po_source():
    """Catches a forgotten `msgfmt` after editing django.po. Compares content,
    not file times: git does not preserve mtimes, so on a fresh checkout (CI)
    the .mo can land a fraction of a millisecond "older" than the .po and an
    mtime check fails at random. This needs no gettext tools either -- the
    container has none -- only the stdlib reader Django itself uses."""
    with MO_PATH.open('rb') as fp:
        compiled = {k: v for k, v in gettext.GNUTranslations(fp)._catalog.items() if k != ''}
    source = _po_catalog(PO_PATH)
    stale = sorted(str(k) for k in source if compiled.get(k) != source[k])
    orphaned = sorted(str(k) for k in compiled.keys() - source.keys())
    assert not stale, 'django.mo is out of date for: %s' % stale
    assert not orphaned, 'django.mo has entries no longer in django.po: %s' % orphaned


def test_passkey_added_email_renders_in_thai():
    with translation.override('th'):
        body = render_to_string('email/passkey_added.txt', {
            'username': 'alice', 'passkey_name': 'Phone',
            'security_url': 'https://x/account/security/', 'reset_url': 'https://x/password_reset/'})
    assert 'สวัสดี alice' in body
    assert '"Phone"' in body
    assert 'https://x/account/security/' in body


def test_passkey_deleted_email_renders_in_thai():
    with translation.override('th'):
        body = render_to_string('email/passkey_deleted.txt', {
            'username': 'alice', 'passkey_name': 'Phone',
            'security_url': 'https://x/account/security/', 'reset_url': 'https://x/password_reset/'})
    assert 'สวัสดี alice' in body
    assert '"Phone"' in body
    assert 'https://x/account/security/' in body
    assert 'https://x/password_reset/' in body


def test_password_removed_email_renders_in_thai():
    with translation.override('th'):
        body = render_to_string('email/password_removed.txt', {
            'username': 'alice',
            'security_url': 'https://x/account/security/', 'reset_url': 'https://x/password_reset/'})
    assert 'สวัสดี alice' in body
    assert 'https://x/account/security/' in body
    assert 'https://x/password_reset/' in body


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

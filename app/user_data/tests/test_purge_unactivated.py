import datetime
import io

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.utils import timezone

from user_data.management.commands.purge_unactivated import Command
from user_data.models import Passkey

pytestmark = pytest.mark.django_db

OLD_ENOUGH = datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE, hours=1)
TOO_RECENT = datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE / 2)


def _add_passkey(user, suffix=None):
    return Passkey.objects.create(
        user=user,
        credential_id='cred-%s' % (suffix or user.username),
        public_key=b'fake-public-key',
        name='Test Passkey',
    )


def _stranded_passkey_signup(username='ghost', email='ghost@example.com', age=OLD_ENOUGH,
                             with_passkey=True):
    """A user shaped exactly like one signup_finish leaves behind when its
    verification email never gets read: inactive, no login ever, no
    usable password (passkey-only), with the passkey it registered.
    """
    user = User.objects.create_user(username, email)
    user.set_unusable_password()
    user.is_active = False
    user.date_joined = timezone.now() - age
    user.save()
    if with_passkey:
        _add_passkey(user)
    return user


def _run(*args):
    out = io.StringIO()
    call_command('purge_unactivated', *args, stdout=out)
    return out.getvalue()


def test_deletes_stranded_passkey_signup():
    user = _stranded_passkey_signup()

    output = _run()

    assert not User.objects.filter(pk=user.pk).exists()
    assert 'ghost' in output
    assert 'Deleted 1' in output


def test_dry_run_deletes_nothing_but_reports_it():
    user = _stranded_passkey_signup()

    output = _run('--dry-run')

    assert User.objects.filter(pk=user.pk).exists()
    assert 'Would delete' in output
    assert 'ghost' in output


def test_dry_run_lists_a_multi_passkey_user_only_once():
    # passkeys__isnull=False joins to Passkey; without .distinct() a user
    # with N passkeys would appear N times in the queryset (and so in the
    # dry-run listing).
    user = _stranded_passkey_signup(with_passkey=False)
    _add_passkey(user, suffix='a')
    _add_passkey(user, suffix='b')
    _add_passkey(user, suffix='c')

    output = _run('--dry-run')

    assert output.count('Would delete') == 1
    assert 'Dry run: 1 account(s)' in output


def test_leaves_active_user_alone():
    user = _stranded_passkey_signup(username='active_ghost', email='active_ghost@example.com')
    user.is_active = True
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_recently_joined_user_alone():
    user = _stranded_passkey_signup(username='fresh_ghost', email='fresh_ghost@example.com',
                                    age=TOO_RECENT)

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_password_signup_user_alone():
    # Shaped like a pending *password* signup (rest_register): inactive,
    # never logged in, old enough, no passkey -- but has a real, usable
    # password.
    user = User.objects.create_user('pending_password', 'pending_password@example.com',
                                    'pw12345678')
    user.is_active = False
    user.date_joined = timezone.now() - OLD_ENOUGH
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_user_with_login_history_alone():
    user = _stranded_passkey_signup(username='logged_in_ghost',
                                    email='logged_in_ghost@example.com')
    user.last_login = timezone.now() - OLD_ENOUGH
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_account_with_no_passkey_alone():
    # Inactive, unusable password, never logged in, old enough -- but
    # never actually registered a passkey (shouldn't normally happen, but
    # nothing guarantees it can't). This command's whole justification is
    # "passkey-only signup with no recovery path", so it must not assume a
    # match without one.
    user = _stranded_passkey_signup(username='passkeyless_ghost',
                                    email='passkeyless_ghost@example.com', with_passkey=False)

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_inactive_staff_account_with_no_passkey_alone():
    user = _stranded_passkey_signup(username='staff_ghost', email='staff_ghost@example.com',
                                    with_passkey=False)
    user.is_staff = True
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_staff_account_alone_even_with_a_passkey():
    # Isolates is_staff=False: otherwise identical to a real candidate.
    user = _stranded_passkey_signup(username='staff_with_passkey',
                                    email='staff_with_passkey@example.com')
    user.is_staff = True
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_leaves_superuser_account_alone_even_with_a_passkey():
    # Isolates is_superuser=False: otherwise identical to a real candidate.
    user = _stranded_passkey_signup(username='superuser_with_passkey',
                                    email='superuser_with_passkey@example.com')
    user.is_superuser = True
    user.save()

    _run()

    assert User.objects.filter(pk=user.pk).exists()


def test_no_candidates_reports_and_does_not_error():
    output = _run()
    assert 'No stranded unactivated accounts found.' in output


def test_only_deletes_matching_users_leaves_others():
    stranded = _stranded_passkey_signup()
    active = _stranded_passkey_signup(username='active2', email='active2@example.com')
    active.is_active = True
    active.save()

    _run()

    assert not User.objects.filter(pk=stranded.pk).exists()
    assert User.objects.filter(pk=active.pk).exists()


# --- race safety: the SELECT and the DELETE must agree on current state ----
#
# Command._candidates() is called twice: once to build the listing (the
# "SELECT"), once more -- filtered to those same ids -- right before the
# DELETE. These tests monkeypatch that second call to mutate the row in
# between, deterministically reproducing "something else committed a
# change to this account after it was selected but before it was deleted"
# without needing real concurrency.

def _racy_candidates(mutate):
    """Return a _candidates replacement that runs `mutate()` on its 2nd
    call (the delete-time re-check), simulating a concurrent write that
    lands in the gap between the SELECT and the DELETE.
    """
    calls = {'n': 0}
    original = Command._candidates

    def racy(self, User, cutoff):
        calls['n'] += 1
        if calls['n'] == 2:
            mutate()
        return original(self, User, cutoff)
    return racy


def test_race_activated_between_select_and_delete_is_not_deleted(monkeypatch):
    user = _stranded_passkey_signup()

    def mutate():
        fresh = User.objects.get(pk=user.pk)
        fresh.is_active = True
        fresh.save()

    monkeypatch.setattr(Command, '_candidates', _racy_candidates(mutate))

    output = _run()

    assert User.objects.filter(pk=user.pk, is_active=True).exists()
    assert 'Deleted 0' in output
    assert 'no longer matched at delete time' in output


def test_race_password_set_between_select_and_delete_is_not_deleted(monkeypatch):
    user = _stranded_passkey_signup()

    def mutate():
        fresh = User.objects.get(pk=user.pk)
        fresh.set_password('newpass12345')  # still inactive, still no login
        fresh.save()

    monkeypatch.setattr(Command, '_candidates', _racy_candidates(mutate))

    output = _run()

    fresh = User.objects.get(pk=user.pk)
    assert fresh.has_usable_password()
    assert 'Deleted 0' in output
    assert 'no longer matched at delete time' in output


def test_race_logged_in_between_select_and_delete_is_not_deleted(monkeypatch):
    user = _stranded_passkey_signup()

    def mutate():
        fresh = User.objects.get(pk=user.pk)
        fresh.last_login = timezone.now()
        fresh.save()

    monkeypatch.setattr(Command, '_candidates', _racy_candidates(mutate))

    output = _run()

    assert User.objects.filter(pk=user.pk).exists()
    assert 'Deleted 0' in output
    assert 'no longer matched at delete time' in output

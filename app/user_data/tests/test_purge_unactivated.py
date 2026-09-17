import datetime
import io

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.utils import timezone

pytestmark = pytest.mark.django_db

OLD_ENOUGH = datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE, hours=1)
TOO_RECENT = datetime.timedelta(seconds=settings.EMAIL_VERIFICATION_MAX_AGE / 2)


def _stranded_passkey_signup(username='ghost', email='ghost@example.com', age=OLD_ENOUGH):
    """A user shaped exactly like one signup_finish leaves behind when its
    verification email never gets read: inactive, no login ever, no
    usable password (passkey-only).
    """
    user = User.objects.create_user(username, email)
    user.set_unusable_password()
    user.is_active = False
    user.date_joined = timezone.now() - age
    user.save()
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
    # never logged in, old enough -- but has a real, usable password.
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

"""Passkey management on a signed-in account: list, rename, delete, drop password."""
import re

from django.contrib.auth import get_user_model
from django.db import transaction

from .models import Passkey
from .passkey_service import (AAGUID_NAMES, PasskeyError, bump_passkey_epoch,
                              check_password, clean_name, send_passkey_deleted_email,
                              send_password_removed_email)


class NotFound(PasskeyError):
    """No passkey with that id belongs to the caller."""


class InvalidName(PasskeyError):
    """Rename with an empty or non-string name."""


class LockoutGuard(PasskeyError):
    """The change would leave the account with no way to sign in."""


class WrongPassword(PasskeyError):
    """The confirming password did not match."""


# The pk is a plain int4 AutoField: 1-10 ASCII digits, capped at 2147483647.
_PASSKEY_ID_RE = re.compile(r'^[0-9]{1,10}$')
_MAX_PASSKEY_ID = 2147483647


def passkey_to_dict(passkey):
    return {
        'id': passkey.pk,
        'name': passkey.name,
        'authenticator': AAGUID_NAMES.get(passkey.aaguid, ''),
        'backed_up': passkey.backed_up,
        'created_at': passkey.created_at.isoformat(),
        'last_used_at': passkey.last_used_at.isoformat() if passkey.last_used_at else None,
    }


def list_passkeys(user):
    return {'has_password': user.has_usable_password(),
            'passkeys': [passkey_to_dict(p) for p in user.passkeys.order_by('created_at', 'pk')]}


def _parse_passkey_id(passkey_id):
    """Accept only a real (non-bool) int, or a string of 1-10 ASCII digits.

    int(passkey_id) alone would accept far more than an id ever is: True
    (-> 1), 1.9 (-> 1), ' 7 ' (whitespace-trimmed), or non-ASCII digits like
    the Arabic-Indic '٧'. A plain [0-9] character class (not \\d, which
    matches those non-ASCII digits too) rules all of that out. Returns None
    for anything that isn't a valid id, including one above 2147483647 --
    the ceiling of the pk's int4 AutoField.
    """
    if isinstance(passkey_id, bool):
        return None
    if isinstance(passkey_id, int):
        value = passkey_id
    elif isinstance(passkey_id, str) and _PASSKEY_ID_RE.fullmatch(passkey_id):
        value = int(passkey_id)
    else:
        return None
    return value if 0 <= value <= _MAX_PASSKEY_ID else None


def _own(user, passkey_id):
    value = _parse_passkey_id(passkey_id)
    if value is None:
        raise NotFound()
    try:
        return Passkey.objects.get(pk=value, user=user)
    except Passkey.DoesNotExist as exc:
        raise NotFound() from exc


def rename_passkey(user, passkey_id, name):
    """Ownership is resolved before the name is validated: another user's
    id is NotFound even when the supplied name would also be invalid."""
    passkey = _own(user, passkey_id)
    cleaned = clean_name(name)
    if not cleaned:
        raise InvalidName()
    # A conditional update, not passkey.save(update_fields=...): the row
    # can be deleted between _own's lookup and here (e.g. a concurrent
    # delete_passkey), and save(update_fields=...) would raise
    # DatabaseError (a 500) on a vanished row instead of the clean
    # NotFound a renamed-out-from-under-you passkey deserves.
    if not Passkey.objects.filter(pk=passkey.pk, user=user).update(name=cleaned):
        raise NotFound()
    passkey.name = cleaned
    return passkey


def delete_passkey(user, passkey_id):
    """Delete, unless it is the only passkey of an account without a password.

    Also bumps PasskeyEpoch, inside this same transaction and under this
    same lock: a delete must move the counter forward exactly like an add
    does, or deleting the passkey that killed a reset token could quietly
    revive it. See passkey_service.bump_passkey_epoch.

    The notification email is sent last, strictly after this function's
    own transaction.atomic() block has returned (so only once the delete
    has actually committed) -- never from inside it. send_passkey_deleted_
    email is itself best-effort (see passkey_service._send_security_email),
    so a mail outage here can never turn a successful delete into a 500 or,
    worse, roll it back: someone holding a stolen session must not be able
    to suppress the owner's own notification just by knocking out mail
    delivery first.
    """
    with transaction.atomic():
        locked = get_user_model().objects.select_for_update().get(pk=user.pk)
        passkey = _own(locked, passkey_id)
        if not locked.has_usable_password() and locked.passkeys.count() == 1:
            raise LockoutGuard()
        # A queryset delete, not passkey.delete(): both tolerate the row
        # already being gone (Model.delete() would too), but filtering by
        # pk+user here is the explicit statement of what's being deleted,
        # matching the pk+user lookup _own already did.
        Passkey.objects.filter(pk=passkey.pk, user=locked).delete()
        bump_passkey_epoch(locked)
    send_passkey_deleted_email(locked, passkey.name)


def remove_password(user, password):
    """Make the password unusable; allowed only while a passkey exists.

    This changes the password hash, which invalidates the signed-in
    session's auth-hash check. The caller -- the Task 12 view -- must call
    update_session_auth_hash(request, locked) with the user this returns,
    or the request's own session will be signed out on its next request.

    The notification email is sent last, strictly after this function's
    own transaction.atomic() block has returned (so only once the removal
    has actually committed) -- never from inside it, and best-effort like
    delete_passkey's own notification above: see that function's docstring
    for why.
    """
    with transaction.atomic():
        locked = get_user_model().objects.select_for_update().get(pk=user.pk)
        if not locked.has_usable_password() or not locked.passkeys.exists():
            raise LockoutGuard()
        if not check_password(locked, password):
            raise WrongPassword()
        locked.set_unusable_password()
        locked.save(update_fields=['password'])
    send_password_removed_email(locked)
    return locked

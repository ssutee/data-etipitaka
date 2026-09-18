"""Desktop sign-in pairing handshakes.

A wxPython process cannot produce a WebAuthn credential this server will
accept -- the only allowed origin is https://data.etipitaka.com and origins are
minted by the browser or the OS. So the desktop app delegates the ceremony to
the system browser and collects the resulting token here: begin() issues a
secret device code plus a human-readable user code, the browser confirms the
user code against what the app is displaying, and redeem() hands over the
token.

The device code is the app's secret and is never displayed or stored in the
clear; only its SHA-256 goes in the database.
"""
import hashlib
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import DesktopPairing

log = logging.getLogger(__name__)

# Crockford-style: no 0/1/I/L/O/U, so a code read off a screen and typed (or
# read aloud) cannot be ambiguous.
CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'
CODE_LENGTH = 8


class PairingError(Exception):
    """Unknown, expired or already-redeemed pairing."""


def new_user_code():
    return ''.join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def format_user_code(code):
    """Canonical code -> the form shown to a human: K7QP4M2X -> K7QP-4M2X."""
    if len(code) != CODE_LENGTH:
        raise ValueError('expected a %d-character code' % CODE_LENGTH)
    half = CODE_LENGTH // 2
    return code[:half] + '-' + code[half:]


def normalise_user_code(raw):
    """Anything a user or URL supplied -> canonical code, or None if invalid.

    Keeps only alphanumerics, so every separator a code can pick up on its way
    through a browser, a chat app or a PDF -- ASCII and non-breaking spaces,
    tabs, newlines, and hyphens autocorrected into en/em dashes -- is dropped
    rather than rejected.
    """
    if not isinstance(raw, str):
        return None
    code = ''.join(ch for ch in raw if ch.isalnum()).upper()
    if len(code) != CODE_LENGTH or not set(code) <= set(CODE_ALPHABET):
        return None
    return code


def _hash(device_code):
    return hashlib.sha256(device_code.encode()).hexdigest()


_MAX_CODE_ATTEMPTS = 5


def begin():
    """Issue a pairing. Returns (device_code, row); only the hash is stored.

    Expired rows are purged here, the same way passkey_challenges.create()
    purges its own -- there is no separate sweeper process.
    """
    now = timezone.now()
    DesktopPairing.objects.filter(expires_at__lte=now).delete()
    device_code = secrets.token_urlsafe(32)
    expires_at = now + timedelta(seconds=settings.PASSKEY_DESKTOP_TTL)
    for _attempt in range(_MAX_CODE_ATTEMPTS):
        try:
            with transaction.atomic():
                row = DesktopPairing.objects.create(
                    device_code_hash=_hash(device_code),
                    user_code=new_user_code(),
                    expires_at=expires_at)
        except IntegrityError:
            continue  # user_code collided with a live row; draw another
        return device_code, row
    # Five straight collisions in a ~39-bit space is not bad luck. Either the
    # live-row count has grown far beyond anything this table should hold, or
    # the device code itself collided on the primary key -- which would mean a
    # broken entropy source. Both need a human, so say so loudly.
    log.error('desktop pairing: exhausted %d user code attempts', _MAX_CODE_ATTEMPTS)
    raise PairingError('exhausted %d user code attempts' % _MAX_CODE_ATTEMPTS)


def find_pending(raw_user_code):
    """The live, still-undecided pairing for this user code, or None."""
    code = normalise_user_code(raw_user_code)
    if code is None:
        return None
    return (DesktopPairing.objects
            .filter(user_code=code, status=DesktopPairing.PENDING,
                    expires_at__gt=timezone.now())
            .first())


def approve(row, user):
    """Bind the pairing to the signed-in user, if it is still pending.

    A conditional update rather than save(update_fields=...): between
    find_pending() and here the row can be decided by another tab or deleted
    outright by a concurrent redeem(). save() would raise DatabaseError on a
    vanished row (a 500 on the confirmation page) and would happily flip an
    already-decided row's status back. Mirrors passkey_manage.rename_passkey().

    Returns True if this call is the one that decided the pairing.
    """
    return DesktopPairing.objects.filter(
        pk=row.pk, status=DesktopPairing.PENDING,
    ).update(status=DesktopPairing.APPROVED, user=user) == 1


def deny(row):
    """Refuse the pairing, if it is still pending. See approve() on why this is
    a conditional update. Returns True if this call is the one that decided it.
    """
    return DesktopPairing.objects.filter(
        pk=row.pk, status=DesktopPairing.PENDING,
    ).update(status=DesktopPairing.DENIED) == 1

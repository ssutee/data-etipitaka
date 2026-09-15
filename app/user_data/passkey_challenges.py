"""Single-use WebAuthn ceremony challenges, stored in the database.

No cache is shared across the gunicorn workers and native clients carry no
session cookie, so the state between a ceremony's begin and finish calls
lives in WebAuthnChallenge rows.
"""
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import WebAuthnChallenge


class ChallengeError(Exception):
    """Unknown, expired, reused, wrong-purpose or wrong-user challenge."""


def create(purpose, user=None, payload=None):
    now = timezone.now()
    WebAuthnChallenge.objects.filter(expires_at__lte=now).delete()
    return WebAuthnChallenge.objects.create(
        id=secrets.token_urlsafe(32), challenge=secrets.token_bytes(32),
        purpose=purpose, user=user, payload=payload or {},
        expires_at=now + timedelta(seconds=settings.PASSKEY_CHALLENGE_TTL))


def consume(challenge_id, purpose, user=None):
    """Delete and return the challenge, or raise ChallengeError.

    The row is gone before the caller verifies anything, so a failed
    verification burns it too and a concurrent replay finds nothing. Call
    this outside any enclosing transaction.atomic(): a rollback there would
    resurrect the row.
    """
    if not isinstance(challenge_id, str) or not challenge_id:
        raise ChallengeError()
    with transaction.atomic():
        row = (WebAuthnChallenge.objects.select_for_update()
               .filter(pk=challenge_id, purpose=purpose, expires_at__gt=timezone.now())
               .first())
        if row is None:
            raise ChallengeError()
        row.delete()
    if user is not None and row.user_id != user.pk:
        raise ChallengeError()
    row.challenge = bytes(row.challenge)
    return row

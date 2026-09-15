from datetime import timedelta

import pytest
from django.utils import timezone

from user_data import passkey_challenges as challenges
from user_data.models import WebAuthnChallenge

pytestmark = pytest.mark.django_db


def _expire(row):
    WebAuthnChallenge.objects.filter(pk=row.id).update(
        expires_at=timezone.now() - timedelta(seconds=1))


def test_create_issues_random_challenge_with_ttl(alice, settings):
    settings.PASSKEY_CHALLENGE_TTL = 300
    before = timezone.now()
    row = challenges.create(WebAuthnChallenge.REGISTER, user=alice, payload={'a': 1})
    assert isinstance(row.challenge, bytes) and len(row.challenge) == 32
    assert len(row.id) >= 40
    assert (row.purpose, row.user, row.payload) == ('register', alice, {'a': 1})
    assert before + timedelta(seconds=299) < row.expires_at
    assert row.expires_at <= timezone.now() + timedelta(seconds=300)


def test_consume_returns_row_once():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    got = challenges.consume(row.id, WebAuthnChallenge.LOGIN)
    assert got.challenge == row.challenge
    assert isinstance(got.challenge, bytes)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.LOGIN)


def test_consume_rejects_expired():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    _expire(row)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.LOGIN)


def test_consume_rejects_wrong_purpose():
    row = challenges.create(WebAuthnChallenge.LOGIN)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.REGISTER)


def test_consume_rejects_other_user_and_burns_row(alice, bob):
    row = challenges.create(WebAuthnChallenge.REGISTER, user=alice)
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(row.id, WebAuthnChallenge.REGISTER, user=bob)
    assert not WebAuthnChallenge.objects.filter(pk=row.id).exists()


@pytest.mark.parametrize('bad', [None, '', 123, ['x']])
def test_consume_rejects_non_string_ids(bad):
    with pytest.raises(challenges.ChallengeError):
        challenges.consume(bad, WebAuthnChallenge.LOGIN)


def test_create_purges_expired_rows():
    old = challenges.create(WebAuthnChallenge.LOGIN)
    _expire(old)
    challenges.create(WebAuthnChallenge.LOGIN)
    assert not WebAuthnChallenge.objects.filter(pk=old.id).exists()

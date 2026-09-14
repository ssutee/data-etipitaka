import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from user_data.models import Passkey, PasskeyUserHandle, WebAuthnChallenge

pytestmark = pytest.mark.django_db


def _passkey(user, credential_id='cred-1'):
    return Passkey.objects.create(user=user, credential_id=credential_id,
                                  public_key=b'\x01\x02', name='Phone')


def test_passkey_defaults(alice):
    passkey = _passkey(alice)
    passkey.refresh_from_db()
    assert passkey.sign_count == 0
    assert passkey.transports == []
    assert passkey.backed_up is False
    assert passkey.aaguid == ''
    assert passkey.last_used_at is None
    assert passkey.created_at is not None
    assert bytes(passkey.public_key) == b'\x01\x02'
    assert list(alice.passkeys.all()) == [passkey]


def test_passkey_credential_id_is_unique(alice, bob):
    _passkey(alice)
    with pytest.raises(IntegrityError), transaction.atomic():
        _passkey(bob)


def test_user_handle_one_per_user(alice):
    PasskeyUserHandle.objects.create(user=alice, handle=b'h' * 32)
    with pytest.raises(IntegrityError), transaction.atomic():
        PasskeyUserHandle.objects.create(user=alice, handle=b'i' * 32)


def test_challenge_row_round_trip(alice):
    row = WebAuthnChallenge.objects.create(
        id='abc', challenge=b'c' * 32, purpose=WebAuthnChallenge.REGISTER,
        user=alice, payload={'k': 'v'}, expires_at=timezone.now())
    row.refresh_from_db()
    assert bytes(row.challenge) == b'c' * 32
    assert row.payload == {'k': 'v'}
    assert {p for p, _label in WebAuthnChallenge.PURPOSES} == {
        'login', 'register', 'signup', 'recover'}


def test_deleting_user_cascades(alice):
    _passkey(alice)
    PasskeyUserHandle.objects.create(user=alice, handle=b'h' * 32)
    alice.delete()
    assert Passkey.objects.count() == 0
    assert PasskeyUserHandle.objects.count() == 0

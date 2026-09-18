from datetime import timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.utils import timezone

from user_data import desktop_pairing
from user_data.models import DesktopPairing


@pytest.mark.django_db
def test_pairing_defaults_to_pending():
    row = DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        expires_at=timezone.now())
    assert row.status == DesktopPairing.PENDING
    assert row.user is None


@pytest.mark.django_db
def test_user_code_is_unique():
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        expires_at=timezone.now())
    with pytest.raises(IntegrityError), transaction.atomic():
        DesktopPairing.objects.create(
            device_code_hash='b' * 64, user_code='K7QP4M2X',
            expires_at=timezone.now())


@pytest.mark.django_db
def test_deleting_the_user_deletes_the_pairing():
    user = User.objects.create_user('alice', password='x')
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='K7QP4M2X',
        user=user, expires_at=timezone.now())
    user.delete()
    assert DesktopPairing.objects.count() == 0


def test_new_user_code_shape():
    code = desktop_pairing.new_user_code()
    assert len(code) == 8
    assert set(code) <= set(desktop_pairing.CODE_ALPHABET)


def test_new_user_code_varies():
    # Guards against a regression that draws one character and repeats it:
    # that keeps the length and alphabet correct but destroys the entropy.
    codes = {desktop_pairing.new_user_code() for _ in range(20)}
    assert len(codes) > 1
    assert any(len(set(code)) > 1 for code in codes)


def test_alphabet_excludes_ambiguous_characters():
    assert not (set('01OI') & set(desktop_pairing.CODE_ALPHABET))


def test_format_and_normalise_round_trip():
    assert desktop_pairing.format_user_code('K7QP4M2X') == 'K7QP-4M2X'
    assert desktop_pairing.normalise_user_code('k7qp-4m2x') == 'K7QP4M2X'
    assert desktop_pairing.normalise_user_code(' K7QP 4M2X ') == 'K7QP4M2X'


def test_normalise_rejects_rubbish():
    assert desktop_pairing.normalise_user_code('') is None
    assert desktop_pairing.normalise_user_code('!!!!') is None
    assert desktop_pairing.normalise_user_code('K7QP4M2') is None      # too short
    assert desktop_pairing.normalise_user_code('K7QP4M2XY') is None    # too long
    assert desktop_pairing.normalise_user_code(None) is None
    assert desktop_pairing.normalise_user_code(123) is None
    assert desktop_pairing.normalise_user_code('K7QP4M2O') is None     # O not in alphabet
    assert desktop_pairing.normalise_user_code('K7QP4M2L') is None     # L not in alphabet


def test_normalise_strips_exotic_separators():
    assert desktop_pairing.normalise_user_code('K7QP\xa04M2X') == 'K7QP4M2X'   # NBSP
    assert desktop_pairing.normalise_user_code('K7QP　4M2X') == 'K7QP4M2X'   # full-width
    assert desktop_pairing.normalise_user_code('K7QP\t4M2X\n') == 'K7QP4M2X'
    assert desktop_pairing.normalise_user_code('K7QP–4M2X') == 'K7QP4M2X'   # en dash


@pytest.mark.django_db
def test_begin_returns_a_device_code_and_stores_only_its_hash():
    device_code, row = desktop_pairing.begin()
    assert len(device_code) >= 40
    assert row.device_code_hash == desktop_pairing._hash(device_code)
    assert DesktopPairing.objects.filter(device_code_hash=row.device_code_hash).exists()
    # The plaintext code must appear nowhere in the table.
    assert not DesktopPairing.objects.filter(user_code=device_code).exists()


@pytest.mark.django_db
def test_begin_sets_expiry_from_settings(settings):
    # A non-default TTL on purpose: with the production value (600) this test
    # would pass even if begin() ignored the setting and hardcoded it.
    settings.PASSKEY_DESKTOP_TTL = 123
    before = timezone.now()
    _code, row = desktop_pairing.begin()
    assert row.expires_at >= before + timedelta(seconds=122)
    assert row.expires_at <= timezone.now() + timedelta(seconds=124)


@pytest.mark.django_db
def test_begin_purges_expired_rows():
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code='AAAAAAAA',
        expires_at=timezone.now() - timedelta(seconds=1))
    desktop_pairing.begin()
    assert not DesktopPairing.objects.filter(device_code_hash='a' * 64).exists()


@pytest.mark.django_db
def test_begin_retries_on_user_code_collision():
    taken = 'K7QP4M2X'
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code=taken,
        expires_at=timezone.now() + timedelta(seconds=600))
    with patch.object(desktop_pairing, 'new_user_code',
                      side_effect=[taken, 'ZZZZ2222']):
        _code, row = desktop_pairing.begin()
    assert row.user_code == 'ZZZZ2222'


@pytest.mark.django_db
def test_begin_raises_when_every_code_collides():
    taken = 'K7QP4M2X'
    DesktopPairing.objects.create(
        device_code_hash='a' * 64, user_code=taken,
        expires_at=timezone.now() + timedelta(seconds=600))
    with patch.object(desktop_pairing, 'new_user_code', return_value=taken):
        with pytest.raises(desktop_pairing.PairingError):
            desktop_pairing.begin()

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

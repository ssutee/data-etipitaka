import pytest
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.utils import timezone

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

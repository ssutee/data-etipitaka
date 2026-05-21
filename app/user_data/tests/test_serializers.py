import pytest
from django.contrib.auth.models import User
from user_data.serializers import RegisterSerializer, LoginSerializer

pytestmark = pytest.mark.django_db


def test_register_creates_inactive_user():
    s = RegisterSerializer(data={"email": "n@example.com", "username": "newbie",
                                 "password1": "pw12345678", "password2": "pw12345678"})
    assert s.is_valid(), s.errors
    user = s.save()
    assert user.is_active is False
    assert user.check_password("pw12345678")


def test_register_rejects_password_mismatch():
    s = RegisterSerializer(data={"email": "n@example.com", "username": "newbie",
                                 "password1": "pw12345678", "password2": "different"})
    assert not s.is_valid()
    assert "password" in s.errors


def test_login_rejects_inactive_user():
    u = User(username="ghost", email="g@example.com", is_active=False)
    u.set_password("pw12345678")
    u.save()
    s = LoginSerializer(data={"username": "ghost", "password": "pw12345678"})
    assert not s.is_valid()

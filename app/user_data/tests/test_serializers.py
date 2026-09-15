import pytest
from django.contrib.auth.models import User
from user_data import serializers as serializers_module
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


def test_register_rejects_weak_password():
    # AUTH_PASSWORD_VALIDATORS must be enforced (e.g. the all-numeric and
    # minimum-length validators), as the old allauth signup did.
    s = RegisterSerializer(data={"email": "n@example.com", "username": "newbie",
                                 "password1": "12345678", "password2": "12345678"})
    assert not s.is_valid()
    assert "password" in s.errors


def test_login_rejects_inactive_user():
    u = User(username="ghost", email="g@example.com", is_active=False)
    u.set_password("pw12345678")
    u.save()
    s = LoginSerializer(data={"username": "ghost", "password": "pw12345678"})
    assert not s.is_valid()


def test_register_rejects_duplicate_username():
    User.objects.create_user("taken", "t@example.com", "pw12345678")
    s = RegisterSerializer(data={"email": "other@example.com", "username": "taken",
                                 "password1": "pw12345678", "password2": "pw12345678"})
    assert not s.is_valid()
    assert "username" in s.errors


def test_register_rejects_duplicate_email():
    User.objects.create_user("someone", "dup@example.com", "pw12345678")
    s = RegisterSerializer(data={"email": "dup@example.com", "username": "newbie",
                                 "password1": "pw12345678", "password2": "pw12345678"})
    assert not s.is_valid()
    assert "email" in s.errors


def test_login_rejects_bad_credentials():
    User.objects.create_user("realuser", "r@example.com", "pw12345678")
    s = LoginSerializer(data={"username": "realuser", "password": "wrongpass"})
    assert not s.is_valid()


def test_login_rejects_authenticated_inactive_user(monkeypatch):
    # The default ModelBackend returns None for inactive users, so the
    # explicit is_active guard in LoginSerializer.validate is only reachable
    # when a backend authenticates an inactive user. Simulate that case.
    inactive = User(username="inactive", email="i@example.com", is_active=False)
    inactive.set_password("pw12345678")
    inactive.save()
    monkeypatch.setattr(serializers_module, "authenticate", lambda **kw: inactive)
    s = LoginSerializer(data={"username": "inactive", "password": "pw12345678"})
    assert not s.is_valid()
    assert "non_field_errors" in s.errors


from user_data.serializers import AccountIdentitySerializer


@pytest.mark.parametrize('username', ['bad name', 'semi;colon', 'x' * 151])
def test_identity_rejects_invalid_usernames(username):
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': username})
    assert not s.is_valid()
    assert 'username' in s.errors


def test_identity_accepts_valid_new_user():
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': 'new.user+1'})
    assert s.is_valid(), s.errors


def test_identity_rejects_taken_username_and_email():
    User.objects.create_user('alice', 'alice@example.com', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'alice@example.com', 'username': 'alice'})
    assert not s.is_valid()
    assert set(s.errors) == {'username', 'email'}


def test_register_serializer_rejects_invalid_username():
    s = RegisterSerializer(data={'email': 'n@example.com', 'username': 'bad name',
                                 'password1': 'pw12345678', 'password2': 'pw12345678'})
    assert not s.is_valid()
    assert 'username' in s.errors

import threading

import pytest
from django.contrib.auth.models import User
from django.db import connection
from rest_framework.serializers import ValidationError as DRFValidationError
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


def test_identity_email_accepts_max_length():
    # User.email is a varchar(254); build a syntactically valid address of
    # exactly that length ('@example.com' is 12 chars).
    email = 'a' * 242 + '@example.com'
    assert len(email) == 254
    s = AccountIdentitySerializer(data={'email': email, 'username': 'newbie'})
    assert s.is_valid(), s.errors


def test_identity_email_rejects_over_max_length():
    email = 'a' * 243 + '@example.com'
    assert len(email) == 255
    s = AccountIdentitySerializer(data={'email': email, 'username': 'newbie'})
    assert not s.is_valid()
    assert 'email' in s.errors


# --- case-insensitive / normalised identity matching -------------------------

def test_identity_rejects_username_differing_only_by_case():
    User.objects.create_user('newbie', 'first@example.com', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'second@example.com', 'username': 'Newbie'})
    assert not s.is_valid()
    assert 'username' in s.errors


def test_identity_normalizes_fullwidth_username_and_rejects_it():
    """The fullwidth 'ｎｅｗｂｉｅ' (U+FF4E...) NFKC-normalises to plain
    'newbie' -- Django's own AbstractUser.clean() would normalise it the
    same way, but create_user() never calls full_clean(), so without this
    the fullwidth spelling would slip through as a distinct account."""
    User.objects.create_user('newbie', 'first@example.com', 'pw12345678')
    fullwidth = 'ｎｅｗｂｉｅ'
    s = AccountIdentitySerializer(data={'email': 'second@example.com', 'username': fullwidth})
    assert not s.is_valid()
    assert 'username' in s.errors


def test_identity_rejects_email_differing_only_by_case():
    User.objects.create_user('someone', 'N@x.com', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'n@x.com', 'username': 'newbie'})
    assert not s.is_valid()
    assert 'email' in s.errors


def test_identity_accepts_distinct_username_and_email():
    """Sanity check alongside the collision tests above: two genuinely
    different identities are never rejected by the new case-insensitive
    matching."""
    User.objects.create_user('alice', 'alice@example.com', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'bob@example.com', 'username': 'bob'})
    assert s.is_valid(), s.errors


def test_identity_normalizes_username_in_validated_data():
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': 'ｎｅｗｂｉｅ'})
    assert s.is_valid(), s.errors
    assert s.validated_data['username'] == 'newbie'


def test_register_stores_the_normalized_username():
    """The normalised spelling -- not the caller's raw fullwidth one -- is
    what actually ends up on the created row."""
    s = RegisterSerializer(data={'email': 'n@example.com', 'username': 'ｎｅｗｂｉｅ',
                                 'password1': 'pw12345678', 'password2': 'pw12345678'})
    assert s.is_valid(), s.errors
    user = s.save()
    assert user.username == 'newbie'


def test_validate_email_does_not_treat_two_blank_emails_as_colliding():
    """An empty email can never actually reach validate_email through the
    public serializer interface: EmailField defaults to required=True,
    allow_blank=False, so a blank/missing 'email' is already rejected by
    field-level validation (see test_identity_rejects_missing_email and
    test_identity_rejects_blank_email below) before this method would ever
    run. This calls the method directly, bypassing that field-level check
    entirely, to pin down the defensive guard itself: it must return ''
    unchanged rather than ever reporting a blank email as "already taken"
    by some other blank-email row."""
    User.objects.create_user('someone', '', 'pw12345678')
    s = AccountIdentitySerializer(data={'email': 'n@example.com', 'username': 'newbie'})
    assert s.validate_email('') == ''


def test_identity_rejects_missing_email():
    s = AccountIdentitySerializer(data={'username': 'newbie'})
    assert not s.is_valid()
    assert 'email' in s.errors


def test_identity_rejects_blank_email():
    s = AccountIdentitySerializer(data={'email': '', 'username': 'newbie'})
    assert not s.is_valid()
    assert 'email' in s.errors


# --- the same-email race, password-signup path --------------------------------

@pytest.mark.django_db(transaction=True)
def test_concurrent_register_serializer_creates_for_same_email_yield_one_account():
    """Two real threads both pass is_valid() for the same email (neither
    account exists yet) and then both call .save() at the same moment.
    Without RegisterSerializer.create's lock_signup_email + re-check, both
    could commit -- User.email carries no DB uniqueness constraint -- so
    exactly one of the two threads must succeed and the other must see the
    'email already exists' validation error, mirroring
    test_finish_signup_two_concurrent_signups_same_email_yield_one_account
    in test_passkey_service.py for the password-signup path."""
    start = threading.Barrier(2)
    results = {}

    def _create(name, username):
        try:
            s = RegisterSerializer(data={'email': 'dup@example.com', 'username': username,
                                         'password1': 'pw12345678', 'password2': 'pw12345678'})
            assert s.is_valid(), s.errors
            start.wait(timeout=5)
            s.save()
            results[name] = 'ok'
        except DRFValidationError as exc:
            results[name] = ('rejected', exc.detail)
        except Exception as exc:  # pragma: no cover - surfaced via the assertion below
            results[name] = repr(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=_create, args=('a', 'racer-a')),
              threading.Thread(target=_create, args=('b', 'racer-b'))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    outcomes = [v if isinstance(v, str) else v[0] for v in results.values()]
    assert outcomes.count('ok') == 1, results
    assert outcomes.count('rejected') == 1, results
    assert User.objects.filter(email='dup@example.com').count() == 1

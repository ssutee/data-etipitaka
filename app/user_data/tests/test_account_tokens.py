"""Tests for user_data.account_tokens.revoke_all_tokens."""
from datetime import timedelta

import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from oauth2_provider.models import (AccessToken, Grant, IDToken, RefreshToken,
                                    get_access_token_model, get_grant_model,
                                    get_id_token_model, get_refresh_token_model)
from rest_framework.authtoken.models import Token

from user_data.account_tokens import delete_user_sessions, revoke_all_tokens

from .conftest import make_oauth_token

pytestmark = pytest.mark.django_db


def _grant(user, application, code):
    return Grant.objects.create(
        user=user, application=application, code=code,
        expires=timezone.now() + timedelta(minutes=5),
        redirect_uri='https://app.example/cb', scope='etipitaka:read')


def _id_token(user, application):
    return IDToken.objects.create(
        user=user, application=application,
        expires=timezone.now() + timedelta(minutes=5), scope='etipitaka:read')


def test_revoke_all_tokens_removes_drf_and_oauth_tokens(alice, bob):
    access = make_oauth_token(alice)
    RefreshToken.objects.create(user=alice, application=access.application,
                                token='r-1', access_token=access)
    _grant(alice, access.application, 'c-alice')
    _id_token(alice, access.application)

    bob_access = make_oauth_token(bob)
    RefreshToken.objects.create(user=bob, application=bob_access.application,
                                token='r-bob', access_token=bob_access)
    _grant(bob, bob_access.application, 'c-bob')
    _id_token(bob, bob_access.application)

    revoke_all_tokens(alice)

    assert not Token.objects.filter(user=alice).exists()
    assert not AccessToken.objects.filter(user=alice).exists()
    assert not RefreshToken.objects.filter(user=alice).exists()
    assert not Grant.objects.filter(user=alice).exists()
    assert not IDToken.objects.filter(user=alice).exists()

    assert Token.objects.filter(user=bob).exists()
    assert AccessToken.objects.filter(user=bob).exists()
    assert RefreshToken.objects.filter(user=bob).exists()
    assert Grant.objects.filter(user=bob).exists()
    assert IDToken.objects.filter(user=bob).exists()


def test_revoke_all_tokens_blocks_further_api_access(api, alice):
    """A live bearer token stops authenticating once revoked -- not just
    deleted from the table, but actually rejected by the API."""
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    assert api.get('/rest-auth/user/').status_code == 200

    revoke_all_tokens(alice)

    resp = api.get('/rest-auth/user/')
    assert resp.status_code == 401


# Table names, not model classes: each captured query is raw SQL and this
# keeps the ordering assertion robust to whichever swappable model
# OAUTH2_PROVIDER_*_MODEL points at.
_TABLES_IN_EXPECTED_ORDER = [
    ('token', Token._meta.db_table),
    ('grant', get_grant_model()._meta.db_table),
    ('refresh', get_refresh_token_model()._meta.db_table),
    ('access', get_access_token_model()._meta.db_table),
    ('idtoken', get_id_token_model()._meta.db_table),
]


def test_revoke_all_tokens_deletes_grant_before_refresh_and_access(alice):
    """Deletion order matters for two concurrency reasons documented in
    account_tokens.py: Grant must go before RefreshToken/AccessToken so a
    racing auth-code exchange finds the grant gone (invalid_grant) rather
    than completing after we think we've revoked everything; RefreshToken
    must go before AccessToken so a refresh token rotated concurrently
    is not left pointing at an access token we already deleted."""
    access = make_oauth_token(alice)
    RefreshToken.objects.create(user=alice, application=access.application,
                                token='r-1', access_token=access)
    Grant.objects.create(user=alice, application=access.application, code='c-order',
                         expires=timezone.now() + timedelta(minutes=5),
                         redirect_uri='https://app.example/cb', scope='etipitaka:read')
    IDToken.objects.create(user=alice, application=access.application,
                           expires=timezone.now() + timedelta(minutes=5),
                           scope='etipitaka:read')

    with CaptureQueriesContext(connection) as ctx:
        revoke_all_tokens(alice)

    seen = []
    for query in ctx.captured_queries:
        sql = query['sql']
        if not sql.startswith('DELETE'):
            continue
        for label, table in _TABLES_IN_EXPECTED_ORDER:
            if table in sql and label not in seen:
                seen.append(label)
                break
    assert seen == ['token', 'grant', 'refresh', 'access', 'idtoken']


# --- delete_user_sessions ----------------------------------------------------

def _login_session(user, expiry_seconds=1209600):
    """A real, decodable session row carrying the same keys
    django.contrib.auth.login() would set -- not a Client(), so tests can
    freely create more than one session per user and control expiry."""
    store = SessionStore()
    store[SESSION_KEY] = str(user.pk)
    store[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
    store[HASH_SESSION_KEY] = user.get_session_auth_hash()
    store.set_expiry(expiry_seconds)
    store.save()
    return store.session_key


def test_delete_user_sessions_deletes_only_that_users_sessions(alice, bob):
    alice_key1 = _login_session(alice)
    alice_key2 = _login_session(alice)
    bob_key = _login_session(bob)

    delete_user_sessions(alice)

    assert not Session.objects.filter(session_key=alice_key1).exists()
    assert not Session.objects.filter(session_key=alice_key2).exists()
    assert Session.objects.filter(session_key=bob_key).exists()


def test_delete_user_sessions_keeps_the_given_session_key(alice):
    keep_key = _login_session(alice)
    drop_key = _login_session(alice)

    delete_user_sessions(alice, keep_session_key=keep_key)

    assert Session.objects.filter(session_key=keep_key).exists()
    assert not Session.objects.filter(session_key=drop_key).exists()


def test_delete_user_sessions_ignores_expired_and_corrupt_rows(alice):
    live_key = _login_session(alice)
    expired_key = _login_session(alice)
    Session.objects.filter(session_key=expired_key).update(
        expire_date=timezone.now() - timedelta(days=1))
    corrupt = Session.objects.create(
        session_key='not-a-real-session-key', session_data='garbage-not-signed-data',
        expire_date=timezone.now() + timedelta(days=1))

    delete_user_sessions(alice)  # must not raise

    assert not Session.objects.filter(session_key=live_key).exists()
    # the expired row is outside the live-session scan and the corrupt one
    # decodes to {} (never matches alice's pk) -- both are left alone
    assert Session.objects.filter(session_key=expired_key).exists()
    assert Session.objects.filter(pk=corrupt.pk).exists()


def test_delete_user_sessions_requires_db_backed_engine(alice, settings):
    settings.SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    with pytest.raises(ImproperlyConfigured):
        delete_user_sessions(alice)

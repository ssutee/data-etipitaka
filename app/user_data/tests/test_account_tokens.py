"""Tests for user_data.account_tokens: revoke_all_tokens and lock_user_tokens."""
import threading
import time
from datetime import timedelta

import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from oauth2_provider.models import (AccessToken, Grant, IDToken, RefreshToken,
                                    get_access_token_model, get_grant_model,
                                    get_id_token_model, get_refresh_token_model)
from rest_framework.authtoken.models import Token

from user_data import account_tokens
from user_data.account_tokens import (delete_user_sessions, lock_signup_email,
                                      lock_user_tokens, revoke_all_tokens)

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


# --- lock_user_tokens ---------------------------------------------------------

@pytest.mark.django_db(transaction=True)
def test_lock_user_tokens_requires_an_atomic_block(alice):
    """Taken in autocommit, pg_advisory_xact_lock releases before the
    caller's next statement even runs -- transaction=True (no wrapping
    atomic() of its own, unlike the plain `db` fixture) is what lets this
    test actually observe that, rather than always passing because
    pytest-django's own test-isolation transaction is open."""
    with pytest.raises(RuntimeError):
        lock_user_tokens(alice.pk)


def test_lock_user_tokens_issues_the_advisory_lock(alice):
    with CaptureQueriesContext(connection) as ctx:
        with transaction.atomic():
            lock_user_tokens(alice.pk)
    assert any('pg_advisory_xact_lock' in q['sql'] and str(alice.pk) in q['sql']
              for q in ctx.captured_queries)


def test_revoke_all_tokens_locks_before_any_delete(alice):
    access = make_oauth_token(alice)
    RefreshToken.objects.create(user=alice, application=access.application,
                                token='r-lock', access_token=access)

    with CaptureQueriesContext(connection) as ctx:
        revoke_all_tokens(alice)

    statements = [q['sql'] for q in ctx.captured_queries]
    lock_index = next(i for i, sql in enumerate(statements) if 'pg_advisory_xact_lock' in sql)
    delete_indexes = [i for i, sql in enumerate(statements) if sql.startswith('DELETE')]
    assert delete_indexes  # sanity: there is something to compare the lock against
    assert lock_index < min(delete_indexes)


@pytest.mark.django_db(transaction=True)
def test_lock_user_tokens_serialises_per_user_locks(alice, bob):
    """A second connection's revoke_all_tokens(alice) must block for as
    long as a first connection holds alice's own advisory lock open --
    proving the lock actually serialises entry, not just runs a query
    Postgres ignores -- while revoke_all_tokens(bob), a different lock
    key, must be completely unaffected."""
    holder_ready = threading.Event()
    release_holder = threading.Event()
    outcome = {}

    def _hold_alices_lock():
        try:
            with transaction.atomic():
                lock_user_tokens(alice.pk)
                holder_ready.set()
                release_holder.wait(timeout=5)
        finally:
            connection.close()

    def _probe(name, user):
        try:
            holder_ready.wait(timeout=5)
            start = time.monotonic()
            revoke_all_tokens(user)
            outcome[name] = time.monotonic() - start
        finally:
            connection.close()

    holder = threading.Thread(target=_hold_alices_lock)
    alice_prober = threading.Thread(target=_probe, args=('alice', alice))
    bob_prober = threading.Thread(target=_probe, args=('bob', bob))
    holder.start()
    alice_prober.start()
    bob_prober.start()
    try:
        bob_prober.join(timeout=5)
        assert 'bob' in outcome  # a different user's lock never blocks on alice's
        assert outcome['bob'] < 1.0

        time.sleep(0.3)
        assert 'alice' not in outcome  # still waiting on alice's held lock

        release_holder.set()
        alice_prober.join(timeout=5)
        assert 'alice' in outcome
    finally:
        release_holder.set()  # in case an assertion above failed first
        holder.join(timeout=5)
        alice_prober.join(timeout=5)
        bob_prober.join(timeout=5)


# --- lock_signup_email -------------------------------------------------------

@pytest.mark.django_db(transaction=True)
def test_lock_signup_email_requires_an_atomic_block():
    """Same guard as lock_user_tokens, and for the same reason -- see that
    test's own docstring for why transaction=True is needed to observe it."""
    with pytest.raises(RuntimeError):
        lock_signup_email('n@example.com')


def test_lock_signup_email_issues_the_advisory_lock():
    with CaptureQueriesContext(connection) as ctx:
        with transaction.atomic():
            lock_signup_email('n@example.com')
    assert any('pg_advisory_xact_lock' in q['sql'] for q in ctx.captured_queries)


def test_lock_signup_email_key_is_stable_across_calls():
    """The lock key must be deterministic across separate Python processes
    (different web workers), so it cannot come from Python's salted
    builtin hash() -- pin down that two independent calls (which, in a
    real deployment, could run in different processes) agree."""
    assert account_tokens._email_lock_key('n@example.com') == \
        account_tokens._email_lock_key('n@example.com')


def test_lock_signup_email_key_matches_after_case_and_nfkc_normalisation():
    """Two spellings AccountIdentitySerializer.validate_email's own
    _unicode_ci_compare treats as the same email -- differing only by case,
    or by NFKC-equivalent fullwidth characters -- must take the same lock,
    or the lock could fail to serialise the very race it exists to close."""
    assert account_tokens._email_lock_key('N@X.com') == \
        account_tokens._email_lock_key('n@x.com')
    assert account_tokens._email_lock_key('ｎ@x.com') == \
        account_tokens._email_lock_key('n@x.com')


@pytest.mark.django_db(transaction=True)
def test_lock_signup_email_serialises_matching_emails_not_different_ones():
    """Mirrors test_lock_user_tokens_serialises_per_user_locks: a second
    connection locking the *same* email must block for as long as a first
    connection holds it, while a *different* email is unaffected."""
    holder_ready = threading.Event()
    release_holder = threading.Event()
    outcome = {}

    def _hold_lock():
        try:
            with transaction.atomic():
                lock_signup_email('dup@example.com')
                holder_ready.set()
                release_holder.wait(timeout=5)
        finally:
            connection.close()

    def _probe(name, email):
        try:
            holder_ready.wait(timeout=5)
            start = time.monotonic()
            with transaction.atomic():
                lock_signup_email(email)
            outcome[name] = time.monotonic() - start
        finally:
            connection.close()

    holder = threading.Thread(target=_hold_lock)
    same_prober = threading.Thread(target=_probe, args=('same', 'DUP@example.com'))
    other_prober = threading.Thread(target=_probe, args=('other', 'other@example.com'))
    holder.start()
    same_prober.start()
    other_prober.start()
    try:
        other_prober.join(timeout=5)
        assert 'other' in outcome  # a different email never blocks on dup@example.com
        assert outcome['other'] < 1.0

        time.sleep(0.3)
        assert 'same' not in outcome  # still waiting on the held lock for the same email

        release_holder.set()
        same_prober.join(timeout=5)
        assert 'same' in outcome
    finally:
        release_holder.set()  # in case an assertion above failed first
        holder.join(timeout=5)
        same_prober.join(timeout=5)
        other_prober.join(timeout=5)


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


def test_delete_user_sessions_deletes_across_multiple_chunks(alice, bob, monkeypatch):
    """The delete runs in filter(session_key__in=...) chunks, not one
    query for the whole match set -- pin that a match set bigger than one
    chunk still gets deleted completely, not just its first chunk."""
    monkeypatch.setattr(account_tokens, '_SESSION_DELETE_CHUNK', 2)
    alice_keys = [_login_session(alice) for _ in range(5)]
    bob_key = _login_session(bob)

    delete_user_sessions(alice)

    for key in alice_keys:
        assert not Session.objects.filter(session_key=key).exists()
    assert Session.objects.filter(session_key=bob_key).exists()


@pytest.mark.parametrize('engine', [
    'django.contrib.sessions.backends.cached_db',
    'django.contrib.sessions.backends.signed_cookies',
])
def test_delete_user_sessions_requires_plain_db_engine(alice, settings, engine):
    """Only plain 'db' is supported -- 'cached_db' keeps the same
    server-side row but also risks serving a stale cache entry that
    re-populates from a not-yet-committed row (see check_session_engine's
    docstring), and signed_cookies/a plain cache keep no server-side row
    at all."""
    settings.SESSION_ENGINE = engine
    with pytest.raises(ImproperlyConfigured):
        delete_user_sessions(alice)


def test_delete_user_sessions_skips_non_dict_payload(alice):
    """A session row need not decode to a dict -- SessionBase.decode() will
    happily hand back whatever JSON-serializable object was encoded, e.g.
    a bare list -- and .get(SESSION_KEY) on that would raise. The scan
    must skip it, not crash."""
    encoded = SessionStore().encode([1, 2, 3])
    row = Session.objects.create(session_key='list-payload-session', session_data=encoded,
                                 expire_date=timezone.now() + timedelta(days=1))

    delete_user_sessions(alice)  # must not raise

    assert Session.objects.filter(pk=row.pk).exists()


def test_delete_user_sessions_skips_session_key_that_is_not_a_valid_pk(alice):
    """A SESSION_KEY that can't even be coerced through the pk field at
    all (not just one that fails to match) must be skipped, not raise --
    the same 'never abort the scan' guarantee as a non-dict payload."""
    store = SessionStore()
    store[SESSION_KEY] = 'not-a-valid-pk'
    store[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
    store[HASH_SESSION_KEY] = alice.get_session_auth_hash()
    store.save()
    key = store.session_key

    delete_user_sessions(alice)  # must not raise

    assert Session.objects.filter(session_key=key).exists()


def test_delete_user_sessions_matches_non_canonical_pk_encoding(alice):
    """Django's own session-auth lookup coerces the stored SESSION_KEY
    through the user model's pk field (_meta.pk.to_python), so a
    zero-padded "02" authenticates exactly like "2" would for pk=2 --
    the scan has to use the same coercion, not a bare string compare, or
    it would silently leave a session like this one behind."""
    store = SessionStore()
    store[SESSION_KEY] = '0%d' % alice.pk
    store[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
    store[HASH_SESSION_KEY] = alice.get_session_auth_hash()
    store.save()
    key = store.session_key

    delete_user_sessions(alice)

    assert not Session.objects.filter(session_key=key).exists()

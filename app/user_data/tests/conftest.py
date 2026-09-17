import os
import secrets
import sqlite3
from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from oauth2_provider.models import AccessToken, Application
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data.models import UserData, SyncData, Sharing
from user_data.tests.soft_authenticator import SoftAuthenticator


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def alice(db):
    user = User.objects.create_user('alice', 'alice@example.com', 'alicepass123')
    Token.objects.create(user=user)
    return user


@pytest.fixture
def bob(db):
    user = User.objects.create_user('bob', 'bob@example.com', 'bobpass123')
    Token.objects.create(user=user)
    return user


@pytest.fixture
def auth_alice(api, alice):
    api.credentials(HTTP_AUTHORIZATION='Token ' + alice.auth_token.key)
    return api


def make_syncdata(user, name='s.json', platform='ios'):
    return SyncData.objects.create(user=user, name=name, platform=platform,
                                   file='%s/%s/%s' % (user.username, platform, name))


def make_userdata(user, deleted=False, platform='ios', name='d.json'):
    return UserData.objects.create(user=user, platform=platform, deleted=deleted,
                                   file='%s/%s/%s' % (user.username, platform, name))


@pytest.fixture
def media_tmp(settings, tmp_path):
    """Redirect MEDIA_ROOT to a temp dir so content DBs never touch app/media."""
    settings.MEDIA_ROOT = str(tmp_path)
    return tmp_path


@pytest.fixture
def canon_dir(settings, tmp_path):
    """Point CANON_RESOURCES_DIR at an empty temp dir for canon tests."""
    d = tmp_path / 'canon'
    d.mkdir()
    settings.CANON_RESOURCES_DIR = str(d)
    return d


def make_canon_edition(canon_dir, filename, rows):
    """Write a canon edition SQLite file. rows: (volume, page, items, content)."""
    dest = os.path.join(str(canon_dir), filename)
    conn = sqlite3.connect(dest)
    conn.execute('CREATE TABLE main (volume VARCHAR(2), page VARCHAR(4), '
                 'items TEXT, content TEXT)')
    conn.executemany('INSERT INTO main VALUES (?,?,?,?)', rows)
    conn.commit()
    conn.close()
    return dest


def make_canon_dict(canon_dir, filename, table, columns, rows):
    """Write a dictionary SQLite file with the given columns and rows."""
    dest = os.path.join(str(canon_dir), filename)
    conn = sqlite3.connect(dest)
    cols_ddl = ','.join('%s TEXT' % c for c in columns)
    conn.execute('CREATE TABLE %s (%s)' % (table, cols_ddl))
    conn.executemany('INSERT INTO %s VALUES (%s)'
                     % (table, ','.join('?' * len(columns))), rows)
    conn.commit()
    conn.close()
    return dest


def make_content_db(user, filename, table, schema_sql, rows, platform='ios'):
    """Create a SyncData row backed by a real SQLite file under MEDIA_ROOT."""
    from django.conf import settings
    rel = '%s/%s/%s' % (user.username, platform, filename)
    dest = os.path.join(settings.MEDIA_ROOT, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    conn = sqlite3.connect(dest)
    conn.execute(schema_sql)
    if rows:
        placeholders = ','.join('?' * len(rows[0]))
        conn.executemany('INSERT INTO %s VALUES (%s)' % (table, placeholders), rows)
    conn.commit()
    conn.close()
    sd = SyncData(user=user, name=filename, platform=platform)
    sd.file.name = rel
    sd.save()
    return sd


def make_oauth_token(user, scope='etipitaka:read', seconds=3600, resource=None):
    """Create a django-oauth-toolkit access token for `user` (public client).

    `resource` is the RFC 8707 audience list the token is bound to; clients
    such as ChatGPT always send one, so unrestricted tokens are not the only
    shape production sees.
    """
    app = Application.objects.create(
        name='test-app', client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris='https://app.example/cb',
        client_secret='', hash_client_secret=False)
    return AccessToken.objects.create(
        user=user, application=app, scope=scope,
        token='t-' + secrets.token_hex(16),
        expires=timezone.now() + timedelta(seconds=seconds),
        resource=resource or [])


@pytest.fixture
def oauth_alice(api, alice):
    """APIClient sending alice's OAuth bearer token with the read scope."""
    tok = make_oauth_token(alice)
    api.credentials(HTTP_AUTHORIZATION='Bearer ' + tok.token)
    return api


@pytest.fixture(autouse=True)
def _passkey_settings(settings):
    """Pin the relying party so a dev PASSKEY_* override never leaks into tests."""
    settings.PASSKEY_RP_ID = 'data.etipitaka.com'
    settings.PASSKEY_WEB_ORIGIN = 'https://data.etipitaka.com'
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = []


@pytest.fixture
def authenticator():
    return SoftAuthenticator()


def add_passkey(user, authenticator, name=None):
    """Register `authenticator` as a passkey of `user` through the real service."""
    from user_data import passkey_service
    challenge_id, options = passkey_service.begin_register(user)
    return passkey_service.finish_register(user, challenge_id,
                                           authenticator.register(options), name=name)


def login_assertion(authenticator, **tamper):
    """(challenge_id, credential) for a fresh login challenge."""
    from user_data import passkey_service
    challenge_id, options = passkey_service.begin_login()
    return challenge_id, authenticator.assert_(options, **tamper)

import os
import sqlite3

import pytest
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from user_data.models import UserData, SyncData, Sharing


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

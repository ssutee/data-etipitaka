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

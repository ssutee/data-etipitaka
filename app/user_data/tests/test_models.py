import pytest
from django.contrib.auth.models import User

from user_data.models import UserData, SyncData, Sharing, user_directory_path

pytestmark = pytest.mark.django_db


class _Stub(object):
    def __init__(self, username, platform):
        self.user = type('U', (), {'username': username})()
        self.platform = platform


def test_user_directory_path_builds_username_platform_filename():
    instance = _Stub('alice', 'ios')
    assert user_directory_path(instance, 'data.json') == 'alice/ios/data.json'


def test_userdata_defaults():
    user = User.objects.create_user('u1', 'u1@example.com', 'pw12345678')
    row = UserData.objects.create(user=user, platform='ios', file='u1/ios/a.json')
    assert row.deleted is False
    assert row.created_at is not None


def test_syncdata_checksum_is_optional():
    user = User.objects.create_user('u2', 'u2@example.com', 'pw12345678')
    row = SyncData.objects.create(user=user, name='a.json', platform='ios',
                                  file='u2/ios/a.json')
    assert row.checksum is None


def test_sharing_reverse_accessors():
    owner = User.objects.create_user('owner', 'o@example.com', 'pw12345678')
    follower = User.objects.create_user('follower', 'f@example.com', 'pw12345678')
    Sharing.objects.create(owner=owner, follower=follower)
    assert owner.sharing_owners.count() == 1
    assert follower.sharing_followers.count() == 1

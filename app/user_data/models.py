from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

from urlparse import urljoin

def user_directory_path(instance, filename):
    return '%s/%s/%s' % (instance.user.username, instance.platform, filename)

class UserData(models.Model):
    user = models.ForeignKey(User, null=True)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)

class SyncData(models.Model):
    user = models.ForeignKey(User, null=True)
    name = models.TextField()
    checksum = models.TextField(blank=True, null=True)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)

class Sharing(models.Model):
    owner = models.ForeignKey(User, null=True, related_name='sharing_owners')
    follower = models.ForeignKey(User, null=True, related_name='sharing_followers')


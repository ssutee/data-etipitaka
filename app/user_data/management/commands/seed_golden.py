# -*- coding: utf-8 -*-
import os
import shutil

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from rest_framework.authtoken.models import Token

from user_data.models import UserData, SyncData, Sharing

ALICE_TOKEN = "a1ce000000000000000000000000000000000001"
BOB_TOKEN = "b0b0000000000000000000000000000000000002"
SEED_DIR = os.path.join(os.path.dirname(__file__), "seed_files")


class Command(BaseCommand):
    help = "Create the deterministic golden-test dataset (idempotent)."

    def handle(self, *args, **options):
        # Wipe prior golden data. Keep superusers.
        Sharing.objects.all().delete()
        SyncData.objects.all().delete()
        UserData.objects.all().delete()
        Token.objects.all().delete()
        User.objects.filter(is_superuser=False).delete()

        alice = self._user(1001, "alice", "alice@example.com", "alicepass123")
        bob = self._user(1002, "bob", "bob@example.com", "bobpass123")

        Token.objects.create(key=ALICE_TOKEN, user=alice)
        Token.objects.create(key=BOB_TOKEN, user=bob)

        # bob owns sync data; alice follows bob (so alice may download bob's data).
        self._syncdata(2001, bob, "sync_alice.json", "ios", "2020-01-01T00:00:00+00:00")
        self._syncdata(2002, alice, "sync_alice.json", "ios", "2020-01-02T00:00:00+00:00")
        Sharing.objects.create(id=4001, owner=bob, follower=alice)

        # alice has two UserData rows: one live, one soft-deleted.
        self._userdata(3001, alice, "data_alice.json", "ios", False)
        self._userdata(3002, alice, "data_alice.json", "ios", True)

        self.stdout.write("seed_golden: done")

    def _user(self, pk, username, email, password):
        user = User(pk=pk, username=username, email=email, is_active=True)
        user.set_password(password)
        user.save()
        return user

    def _place(self, rel_path, src_name):
        dest = os.path.join(settings.MEDIA_ROOT, rel_path)
        parent = os.path.dirname(dest)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        shutil.copy(os.path.join(SEED_DIR, src_name), dest)
        return rel_path

    def _syncdata(self, pk, user, src_name, platform, created_at):
        rel = "%s/%s/%s" % (user.username, platform, src_name)
        self._place(rel, src_name)
        row = SyncData(pk=pk, user=user, name=src_name, platform=platform,
                       checksum="seedchecksum")
        row.file.name = rel
        row.save()
        SyncData.objects.filter(pk=pk).update(created_at=created_at)

    def _userdata(self, pk, user, src_name, platform, deleted):
        rel = "%s/%s/%s" % (user.username, platform, src_name)
        self._place(rel, src_name)
        row = UserData(pk=pk, user=user, platform=platform, deleted=deleted)
        row.file.name = rel
        row.save()
        UserData.objects.filter(pk=pk).update(created_at="2020-01-03T00:00:00+00:00")

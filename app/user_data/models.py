from django.db import models
from django.contrib.auth.models import User


def user_directory_path(instance, filename):
    return '%s/%s/%s' % (instance.user.username, instance.platform, filename)


class UserData(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)


class SyncData(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    name = models.TextField()
    checksum = models.TextField(blank=True, null=True)
    platform = models.TextField()
    file = models.FileField(upload_to=user_directory_path)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)


class Sharing(models.Model):
    owner = models.ForeignKey(User, null=True, related_name='sharing_owners',
                              on_delete=models.CASCADE)
    follower = models.ForeignKey(User, null=True, related_name='sharing_followers',
                                 on_delete=models.CASCADE)


class Passkey(models.Model):
    """One WebAuthn credential; a user may register several."""
    user = models.ForeignKey(User, related_name='passkeys', on_delete=models.CASCADE)
    credential_id = models.CharField(max_length=1400, unique=True)  # base64url
    public_key = models.BinaryField()  # COSE-encoded
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.CharField(max_length=36, blank=True)
    backed_up = models.BooleanField(default=False)
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class PasskeyEpoch(models.Model):
    """Monotonic per-user counter, bumped on every passkey add or delete.

    Exists solely so recovery.AccountRecoveryTokenGenerator can mix in a
    value that only ever increases. The *current* passkey set (e.g. its
    newest pk) is state that can go back down: add a passkey (correctly
    killing an outstanding reset token), then delete that same passkey,
    and "newest pk" reverts to whatever it was before -- quietly reviving
    a token that adding the passkey was supposed to have killed for good.
    A monotonic counter cannot revert that way. See
    passkey_service.bump_passkey_epoch for the only two write paths
    (passkey add via _store_passkey, passkey delete via
    passkey_manage.delete_passkey), both of which bump this inside the
    same transaction as the passkey change, while already holding the
    user row's FOR UPDATE lock.
    """
    user = models.OneToOneField(User, related_name='passkey_epoch', on_delete=models.CASCADE)
    value = models.PositiveBigIntegerField(default=0)


class PasskeyUserHandle(models.Model):
    """Random WebAuthn user.id for an account (never the pk)."""
    user = models.OneToOneField(User, related_name='passkey_handle',
                                on_delete=models.CASCADE)
    handle = models.BinaryField(max_length=64, unique=True)


class WebAuthnChallenge(models.Model):
    """Single-use state for one begin/finish ceremony."""
    LOGIN = 'login'
    REGISTER = 'register'
    SIGNUP = 'signup'
    RECOVER = 'recover'
    PURPOSES = [(LOGIN, 'login'), (REGISTER, 'register'),
                (SIGNUP, 'signup'), (RECOVER, 'recover')]

    id = models.CharField(primary_key=True, max_length=64)
    challenge = models.BinaryField()
    purpose = models.CharField(max_length=16, choices=PURPOSES)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    payload = models.JSONField(default=dict, blank=True)
    expires_at = models.DateTimeField(db_index=True)


class DesktopPairing(models.Model):
    """One desktop sign-in handshake (see user_data/desktop_pairing.py).

    The desktop app holds the device code; only its SHA-256 is stored here, so
    reading this table never yields a code that could be polled for a token --
    the same reasoning as DRF tokens not being reversible from a session.

    user_code is stored canonically (uppercase, no separator); the dash in
    K7QP-4M2X is presentation only.
    """
    PENDING, APPROVED, DENIED = 'pending', 'approved', 'denied'
    STATUSES = [(PENDING, PENDING), (APPROVED, APPROVED), (DENIED, DENIED)]

    device_code_hash = models.CharField(primary_key=True, max_length=64)
    user_code = models.CharField(max_length=8, unique=True)
    status = models.CharField(max_length=8, choices=STATUSES, default=PENDING)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)

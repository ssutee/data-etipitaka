"""Desktop sign-in pairing handshakes.

A wxPython process cannot produce a WebAuthn credential this server will
accept -- the only allowed origin is https://data.etipitaka.com and origins are
minted by the browser or the OS. So the desktop app delegates the ceremony to
the system browser and collects the resulting token here: begin() issues a
secret device code plus a human-readable user code, the browser confirms the
user code against what the app is displaying, and redeem() hands over the
token.

The device code is the app's secret and is never displayed or stored in the
clear; only its SHA-256 goes in the database.
"""
import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import DesktopPairing

# Crockford-style: no 0/O/1/I, so a code read off a screen and typed (or read
# aloud) cannot be ambiguous.
CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'
CODE_LENGTH = 8


class PairingError(Exception):
    """Unknown, expired or already-redeemed pairing."""


def new_user_code():
    return ''.join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def format_user_code(code):
    """Canonical code -> the form shown to a human: K7QP4M2X -> K7QP-4M2X."""
    half = CODE_LENGTH // 2
    return code[:half] + '-' + code[half:]


def normalise_user_code(raw):
    """Anything a user or URL supplied -> canonical code, or None if invalid."""
    if not isinstance(raw, str):
        return None
    code = raw.replace('-', '').replace(' ', '').upper()
    if len(code) != CODE_LENGTH or not set(code) <= set(CODE_ALPHABET):
        return None
    return code


def _hash(device_code):
    return hashlib.sha256(device_code.encode()).hexdigest()

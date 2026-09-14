"""Software WebAuthn authenticator for tests.

Produces real `none`-attestation registration responses and ES256-signed
assertions in the WebAuthn JSON shape that browsers, iOS and Android send, so
tests exercise py_webauthn's actual verification instead of mocking it. Each
call takes keyword knobs that tamper with exactly one property.
"""
import base64
import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

DEFAULT_ORIGIN = 'https://data.etipitaka.com'


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


class SoftAuthenticator:
    """One authenticator holding one credential (like one passkey)."""

    def __init__(self, aaguid=b'\x00' * 16):
        self.aaguid = aaguid
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.user_handle = None
        self.sign_count = 0

    def _cose_public_key(self):
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2,    # kty: EC2
            3: -7,   # alg: ES256
            -1: 1,   # crv: P-256
            -2: numbers.x.to_bytes(32, 'big'),
            -3: numbers.y.to_bytes(32, 'big'),
        })

    @staticmethod
    def _client_data(kind, challenge_b64, origin):
        return json.dumps({'type': kind, 'challenge': challenge_b64,
                           'origin': origin, 'crossOrigin': False}).encode()

    @staticmethod
    def _flags(uv, backed_up, extra=0):
        flags = FLAG_UP | extra
        if uv:
            flags |= FLAG_UV
        if backed_up:
            flags |= FLAG_BE | FLAG_BS
        return flags

    def register(self, options, origin=DEFAULT_ORIGIN, rp_id=None, uv=True,
                 backed_up=True):
        """Answer PublicKeyCredentialCreationOptionsJSON (a dict)."""
        rp_id = rp_id or options['rp']['id']
        self.user_handle = unb64url(options['user']['id'])
        client_data = self._client_data('webauthn.create', options['challenge'], origin)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(uv, backed_up, FLAG_AT)])
            + struct.pack('>I', self.sign_count)
            + self.aaguid
            + struct.pack('>H', len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        return {
            'id': b64url(self.credential_id),
            'rawId': b64url(self.credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': b64url(client_data),
                'attestationObject': b64url(attestation),
                'transports': ['internal', 'hybrid'],
            },
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }

    def assert_(self, options, origin=DEFAULT_ORIGIN, rp_id=None, uv=True,
                backed_up=True, user_handle=None, omit_user_handle=False,
                sign_count=None, corrupt_signature=False):
        """Answer PublicKeyCredentialRequestOptionsJSON (a dict).

        The counter goes up by one unless `sign_count` pins it; pinning 0 on
        every call models a synced passkey, which never counts.
        """
        rp_id = rp_id or options['rpId']
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        client_data = self._client_data('webauthn.get', options['challenge'], origin)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(uv, backed_up)])
            + struct.pack('>I', sign_count)
        )
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        response = {
            'clientDataJSON': b64url(client_data),
            'authenticatorData': b64url(auth_data),
            'signature': b64url(signature),
        }
        if not omit_user_handle:
            response['userHandle'] = b64url(user_handle or self.user_handle)
        return {
            'id': b64url(self.credential_id),
            'rawId': b64url(self.credential_id),
            'type': 'public-key',
            'response': response,
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }

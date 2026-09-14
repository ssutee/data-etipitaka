"""OAuth resource-server token check.

The remote MCP server never issues tokens; it asks Django whether the bearer
token it received is valid by forwarding that token to /api/oauth/verify/.

The SDK re-checks the returned token's absolute `expires_at` on every
request, so the short cache kept here never extends a token's lifetime — it
only delays *revocation* becoming effective, by at most CACHE_TTL_SECONDS.
"""
import hashlib
import logging
import time

import httpx
from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60
CACHE_MAX_ENTRIES = 512


class DjangoTokenVerifier:
    """Implements the mcp TokenVerifier protocol against the Django verify endpoint."""

    def __init__(self, base_url, timeout=10):
        self.url = base_url.rstrip('/') + '/api/oauth/verify/'
        self.timeout = timeout
        self._cache = {}  # sha256(token) -> (expires_monotonic, AccessToken)

    async def verify_token(self, token: str) -> AccessToken | None:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1].model_copy(deep=True)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.url, headers={'Authorization': 'Bearer ' + token})
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            log.warning('token verify failed (%s) for %s…', exc, key[:8])
            return None
        if resp.status_code == 401:
            return None
        if resp.status_code != 200:
            log.warning('token verify got status %s for %s…',
                         resp.status_code, key[:8])
            return None
        try:
            body = resp.json()
            if not body.get('active'):
                log.warning('token verify got inactive for %s…', key[:8])
                return None
            user_id = body.get('user_id')
            access = AccessToken(
                token=token,
                client_id=body.get('client_id') or '',
                scopes=list(body.get('scopes') or []),
                expires_at=body.get('expires_at'),
                subject=str(user_id) if user_id is not None else None,
            )
        except Exception as exc:
            log.warning('token verify got malformed body (%s) for %s…',
                         exc, key[:8])
            return None
        if len(self._cache) >= CACHE_MAX_ENTRIES:
            self._cache.clear()
        self._cache[key] = (now + CACHE_TTL_SECONDS, access)
        return access.model_copy(deep=True)

import os
import stat
from pathlib import Path

import httpx


class AuthError(Exception):
    pass


class Authenticator:
    """Obtains and caches a DRF token, minting from web credentials once."""

    def __init__(self, base_url, username=None, password=None, token=None,
                 cache_path=None, timeout=30):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self._explicit_token = token
        self.timeout = timeout
        self.cache_path = Path(cache_path) if cache_path else (
            Path.home() / '.config' / 'etipitaka-mcp' / 'token')

    def _read_cache(self):
        try:
            return self.cache_path.read_text().strip() or None
        except OSError:
            return None

    def _write_cache(self, token):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(token)
        os.chmod(self.cache_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    def _mint(self):
        if self._explicit_token:
            return self._explicit_token
        if not (self.username and self.password):
            raise AuthError('no credentials: set ETIPITAKA_TOKEN or '
                            'ETIPITAKA_USERNAME + ETIPITAKA_PASSWORD')
        try:
            resp = httpx.post(self.base_url + '/rest-auth/login/',
                              data={'username': self.username,
                                    'password': self.password},
                              timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise AuthError('login request failed: %s' % exc)
        if resp.status_code != 200:
            raise AuthError('login failed (HTTP %s)' % resp.status_code)
        return resp.json()['key']

    def token(self, *, refresh=False):
        if not refresh:
            cached = self._read_cache()
            if cached:
                return cached
        token = self._mint()
        self._write_cache(token)
        return token

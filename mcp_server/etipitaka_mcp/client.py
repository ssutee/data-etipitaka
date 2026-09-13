import httpx


class ContentClient:
    """Calls the Django Content REST API, attaching the auth token."""

    def __init__(self, auth, timeout=30):
        self.auth = auth
        self.timeout = timeout

    def _get(self, path, params=None):
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.auth.base_url + path
        token = self.auth.token()
        resp = httpx.get(url, params=clean,
                         headers={'Authorization': 'Token %s' % token},
                         timeout=self.timeout)
        if resp.status_code == 401:
            token = self.auth.token(refresh=True)
            resp = httpx.get(url, params=clean,
                             headers={'Authorization': 'Token %s' % token},
                             timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def list_bookmarks(self, **params):
        return self._get('/api/content/bookmarks/', params)

    def list_highlights(self, **params):
        return self._get('/api/content/highlights/', params)

    def list_tags(self, **params):
        return self._get('/api/content/tags/', params)

    def list_history(self, **params):
        return self._get('/api/content/history/', params)

    def list_lexicon(self, **params):
        return self._get('/api/content/lexicon/', params)

    def get_summary(self):
        return self._get('/api/content/summary/')

    def whoami(self):
        return self._get('/rest-auth/user/')


class CanonClient:
    """Calls the public /api/canon/* REST API. No auth (canon is public)."""

    def __init__(self, base_url, timeout=30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def _get(self, path, params=None):
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        resp = httpx.get(self.base_url + path, params=clean, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def editions(self):
        return self._get('/api/canon/editions/')

    def search(self, **params):
        return self._get('/api/canon/search/', params)

    def passage(self, **params):
        return self._get('/api/canon/passage/', params)

    def resolve(self, **params):
        return self._get('/api/canon/resolve/', params)

    def dictionary(self, **params):
        return self._get('/api/canon/dictionary/', params)

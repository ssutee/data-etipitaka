import httpx


class EtipitakaAPIError(RuntimeError):
    """A ContentClient or CanonClient REST call failed. Carries no internal URL."""


def _raise_for_status(resp, path):
    """Convert a failed response into an error that carries no internal URL.

    httpx's own message embeds the full URL, which in the deployed stack is
    an internal address the MCP caller must never see. The request path is
    ours and safe to name.
    """
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError:
        if resp.status_code == 401:
            raise EtipitakaAPIError(
                '%s: the access token was rejected (401); refresh it '
                'and retry.' % path) from None
        raise EtipitakaAPIError(
            '%s: request failed (status %d).' % (path, resp.status_code)) from None


class ContentClient:
    """Calls the Django Content REST API with a caller-supplied credential.

    `token_provider()` returns the credential for the current call: in stdio
    mode the user's DRF token (scheme "Token"); in http mode the OAuth bearer
    of the request being served (scheme "Bearer"). `refresh()` optionally
    re-mints once on 401 (stdio only); when absent a 401 is raised.
    """

    def __init__(self, base_url, token_provider, refresh=None, scheme='Token',
                 timeout=30):
        self.base_url = base_url.rstrip('/')
        self.token_provider = token_provider
        self.refresh = refresh
        self.scheme = scheme
        self.timeout = timeout

    def _headers(self, token):
        return {'Authorization': '%s %s' % (self.scheme, token)}

    def _get(self, path, params=None):
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.base_url + path
        resp = httpx.get(url, params=clean, headers=self._headers(self.token_provider()),
                         timeout=self.timeout)
        if resp.status_code == 401 and self.refresh is not None:
            resp = httpx.get(url, params=clean, headers=self._headers(self.refresh()),
                             timeout=self.timeout)
        _raise_for_status(resp, path)
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
        _raise_for_status(resp, path)
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

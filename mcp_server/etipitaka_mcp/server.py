from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .auth import Authenticator
from .client import CanonClient, ContentClient
from .config import load_config
from .verifier import DjangoTokenVerifier

REQUIRED_SCOPE = 'etipitaka:read'

cfg = load_config()


def _request_token():
    """Bearer token of the MCP request currently being served (http mode)."""
    access = get_access_token()
    if access is None:
        raise ValueError('no authenticated request token')
    return access.token


if cfg.transport == 'http':
    if not (cfg.issuer_url and cfg.resource_url):
        raise SystemExit('ETIPITAKA_TRANSPORT=http needs ETIPITAKA_ISSUER_URL '
                         'and ETIPITAKA_RESOURCE_URL')
    # Resource server: the SDK validates bearer tokens via the verifier,
    # answers unauthenticated calls with 401 + WWW-Authenticate, enforces the
    # scope, and publishes RFC 9728 metadata naming the issuer.
    mcp = FastMCP(
        'etipitaka',
        auth=AuthSettings(
            issuer_url=cfg.issuer_url,
            resource_server_url=cfg.resource_url,
            required_scopes=[REQUIRED_SCOPE],
            # v1 relies on scope + issuer; DOT tokens carry no resource claim.
            validate_token_resource=False,
        ),
        token_verifier=DjangoTokenVerifier(cfg.base_url),
        host=cfg.http_host,
        port=cfg.http_port,
        streamable_http_path='/mcp',
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=cfg.allowed_hosts),
    )
    _content = ContentClient(cfg.base_url, _request_token, scheme='Bearer')
else:
    mcp = FastMCP('etipitaka')
    _auth = Authenticator(cfg.base_url, cfg.username, cfg.password, cfg.token)
    _content = ContentClient(cfg.base_url, _auth.token,
                             refresh=lambda: _auth.token(refresh=True))

_canon = CanonClient(cfg.base_url)


# --- personal data (plain impls) ---
def _list_bookmarks(**kw):
    return _content.list_bookmarks(**kw)


def _list_highlights(**kw):
    return _content.list_highlights(**kw)


def _list_tags(**kw):
    return _content.list_tags(**kw)


def _list_history(**kw):
    return _content.list_history(**kw)


def _list_lexicon(**kw):
    return _content.list_lexicon(**kw)


def _get_summary():
    return _content.get_summary()


def _whoami():
    return _content.whoami()


# --- canon (plain impls; served remotely by the Django /api/canon/* API) ---
def _search_canon(query, edition=None, volume=None, limit=20, offset=0):
    edition = edition or cfg.default_edition
    if not edition:
        raise ValueError('no edition given and ETIPITAKA_DEFAULT_EDITION unset')
    return _canon.search(edition=edition, query=query, volume=volume,
                         limit=limit, offset=offset)


def _get_passage(edition, volume, page):
    return _canon.passage(edition=edition, volume=volume, page=page)


def _resolve_reference(platform, code, volume, page):
    return _canon.resolve(platform=platform, code=code, volume=volume, page=page)


def _list_editions():
    return _canon.editions()


def _lookup_dictionary(term, dictionary='pali_thai', match='exact', limit=20):
    return _canon.dictionary(term=term, dictionary=dictionary, match=match, limit=limit)


# --- MCP tool registrations ---
@mcp.tool()
def list_bookmarks(platform: str | None = None, code: int | None = None,
                   volume: int | None = None, page: int | None = None,
                   important: int | None = None, query: str | None = None,
                   limit: int = 50, offset: int = 0) -> dict:
    """List the user's bookmarks (canon locations with notes)."""
    return _list_bookmarks(platform=platform, code=code, volume=volume, page=page,
                           important=important, q=query, limit=limit, offset=offset)


@mcp.tool()
def list_highlights(platform: str | None = None, code: int | None = None,
                    volume: int | None = None, page: int | None = None,
                    query: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    """List the user's highlighted passages (selected text + notes)."""
    return _list_highlights(platform=platform, code=code, volume=volume, page=page,
                            q=query, limit=limit, offset=offset)


@mcp.tool()
def list_tags(platform: str | None = None, query: str | None = None,
              limit: int = 50, offset: int = 0) -> dict:
    """List the user's tags."""
    return _list_tags(platform=platform, q=query, limit=limit, offset=offset)


@mcp.tool()
def list_history(platform: str | None = None, starred: int | None = None,
                 query: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    """List the user's search/reading history."""
    return _list_history(platform=platform, starred=starred, q=query,
                         limit=limit, offset=offset)


@mcp.tool()
def list_lexicon(platform: str | None = None, query: str | None = None,
                 limit: int = 50, offset: int = 0) -> dict:
    """List the user's saved dictionary (lexicon) terms."""
    return _list_lexicon(platform=platform, q=query, limit=limit, offset=offset)


@mcp.tool()
def get_summary() -> dict:
    """Per-type, per-platform counts of the user's data."""
    return _get_summary()


@mcp.tool()
def whoami() -> dict:
    """The authenticated user's pk, username, email."""
    return _whoami()


@mcp.tool()
def list_editions() -> dict:
    """Available canon editions (key, name, present) and dictionary keys."""
    return _list_editions()


@mcp.tool()
def search_canon(query: str, edition: str | None = None, volume: int | None = None,
                 limit: int = 20, offset: int = 0) -> dict:
    """Substring-search one canon edition; returns matching pages with snippets."""
    return _search_canon(query, edition=edition, volume=volume,
                         limit=limit, offset=offset)


@mcp.tool()
def get_passage(edition: str, volume: int, page: int) -> dict:
    """Full text of one canon page in the given edition."""
    return _get_passage(edition, volume, page)


@mcp.tool()
def resolve_reference(platform: str, code: int, volume: int, page: int) -> dict:
    """Resolve a personal item's (platform, code, volume, page) to canon text."""
    return _resolve_reference(platform, code, volume, page)


@mcp.tool()
def lookup_dictionary(term: str, dictionary: str = 'pali_thai',
                      match: str = 'exact', limit: int = 20) -> dict:
    """Look up a term in pali_thai / pali_english / thai; match exact|prefix|contains."""
    return _lookup_dictionary(term, dictionary=dictionary, match=match, limit=limit)


def main():
    mcp.run(transport='streamable-http' if cfg.transport == 'http' else 'stdio')


if __name__ == '__main__':
    main()

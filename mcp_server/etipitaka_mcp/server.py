import os

from mcp.server.fastmcp import FastMCP

from . import canon_reader
from . import canon_registry as reg
from .auth import Authenticator
from .client import ContentClient
from .config import load_config

cfg = load_config()
mcp = FastMCP('etipitaka')

_auth = Authenticator(cfg.base_url, cfg.username, cfg.password, cfg.token)
_content = ContentClient(_auth)


def _require_resources():
    if not cfg.resources_dir or not os.path.isdir(cfg.resources_dir):
        raise ValueError('canon unavailable: set ETIPITAKA_RESOURCES_DIR '
                         'to the E-Tipitaka resources folder')
    return cfg.resources_dir


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


# --- canon (plain impls) ---
def _search_canon(query, edition=None, volume=None, limit=20, offset=0):
    rdir = _require_resources()
    edition = edition or cfg.default_edition
    if not edition:
        raise ValueError('no edition given and ETIPITAKA_DEFAULT_EDITION unset')
    items, total = canon_reader.search(rdir, edition, query, volume=volume,
                                       limit=limit, offset=offset)
    return {'items': items, 'count': total, 'limit': limit, 'offset': offset}


def _get_passage(edition, volume, page):
    rdir = _require_resources()
    row = canon_reader.get_page(rdir, edition, volume, page)
    if row is None:
        raise ValueError('passage not found: %s vol %s page %s'
                         % (edition, volume, page))
    return row


def _resolve_reference(platform, code, volume, page):
    rdir = _require_resources()
    edition = reg.edition_for(platform, code)
    row = canon_reader.get_page(rdir, edition, volume, page)
    if row is None:
        raise ValueError('passage not found for %s code %s vol %s page %s'
                         % (platform, code, volume, page))
    return row


def _list_editions():
    rdir = cfg.resources_dir
    editions = [{'key': k, 'name': m['name'],
                 'present': bool(rdir) and os.path.exists(os.path.join(rdir, m['filename']))}
                for k, m in reg.EDITIONS.items()]
    return {'editions': editions, 'dictionaries': list(reg.DICTIONARIES),
            'default_edition': cfg.default_edition}


def _lookup_dictionary(term, dictionary='pali_thai', match='exact', limit=20):
    rdir = _require_resources()
    entries = canon_reader.lookup(rdir, dictionary, term, match=match, limit=limit)
    return {'entries': entries, 'count': len(entries)}


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
    mcp.run()


if __name__ == '__main__':
    main()

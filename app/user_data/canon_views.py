# -*- coding: utf-8 -*-
"""Public, read-only canon API.

The canon is public Buddhist scripture, so these endpoints require no auth
(AllowAny, no authentication classes -> no session/CSRF involvement). They read
the SQLite editions/dictionaries under settings.CANON_RESOURCES_DIR via the
read-only canon_reader. Edition/dictionary keys are validated against the
trusted registry; only bound values reach SQL.
"""
import os

from django.conf import settings
from django.http import JsonResponse
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import AllowAny

from . import canon_reader
from . import canon_registry as reg

DEFAULT_LIMIT = 20
MAX_LIMIT = 200


def _resources_dir():
    return settings.CANON_RESOURCES_DIR


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _limit(request):
    return max(1, min(_int(request.GET.get('limit'), DEFAULT_LIMIT), MAX_LIMIT))


def _offset(request):
    return max(0, _int(request.GET.get('offset'), 0))


def _err(message, status):
    return JsonResponse({'detail': message}, status=status)


def _public(view):
    return api_view(['GET'])(authentication_classes(())(
        permission_classes((AllowAny,))(view)))


@_public
def editions(request):
    """Available editions (key, name, present) and dictionary keys."""
    rdir = _resources_dir()
    eds = [{'key': k, 'name': m['name'],
            'present': os.path.exists(os.path.join(rdir, m['filename']))}
           for k, m in reg.EDITIONS.items()]
    dicts = [{'key': k, 'present': os.path.exists(os.path.join(rdir, m['filename']))}
             for k, m in reg.DICTIONARIES.items()]
    return JsonResponse({'editions': eds, 'dictionaries': dicts})


@_public
def search(request):
    """Substring-search one edition; returns matching pages with snippets."""
    edition = request.GET.get('edition')
    query = request.GET.get('query') or request.GET.get('q')
    if not edition or edition not in reg.EDITIONS:
        return _err('unknown or missing edition', 400)
    if not query:
        return _err('missing query', 400)
    volume = request.GET.get('volume')
    volume = _int(volume, None) if volume not in (None, '') else None
    limit, offset = _limit(request), _offset(request)
    try:
        items, total = canon_reader.search(_resources_dir(), edition, query,
                                           volume=volume, limit=limit, offset=offset)
    except reg.RegistryError:
        return _err('edition not available on server', 503)
    return JsonResponse({'items': items, 'count': total,
                         'limit': limit, 'offset': offset})


@_public
def passage(request):
    """Full text of one page in the given edition."""
    edition = request.GET.get('edition')
    volume = request.GET.get('volume')
    page = request.GET.get('page')
    if not edition or edition not in reg.EDITIONS:
        return _err('unknown or missing edition', 400)
    if _int(volume, None) is None or _int(page, None) is None:
        return _err('volume and page are required integers', 400)
    try:
        row = canon_reader.get_page(_resources_dir(), edition, int(volume), int(page))
    except reg.RegistryError:
        return _err('edition not available on server', 503)
    if row is None:
        return _err('passage not found', 404)
    return JsonResponse(row)


@_public
def resolve(request):
    """Resolve a personal item's (platform, code, volume, page) to canon text."""
    platform = request.GET.get('platform')
    code = request.GET.get('code')
    volume = request.GET.get('volume')
    page = request.GET.get('page')
    if _int(volume, None) is None or _int(page, None) is None:
        return _err('volume and page are required integers', 400)
    try:
        edition = reg.edition_for(platform, code)
    except reg.RegistryError as exc:
        return _err(str(exc), 400)
    try:
        row = canon_reader.get_page(_resources_dir(), edition, int(volume), int(page))
    except reg.RegistryError:
        return _err('edition not available on server', 503)
    if row is None:
        return _err('passage not found', 404)
    return JsonResponse(row)


@_public
def dictionary(request):
    """Look up a term in pali_thai / pali_english / thai; match exact|prefix|contains."""
    term = request.GET.get('term')
    key = request.GET.get('dictionary') or 'pali_thai'
    match = request.GET.get('match') or 'exact'
    if not term:
        return _err('missing term', 400)
    if key not in reg.DICTIONARIES:
        return _err('unknown dictionary', 400)
    if match not in ('exact', 'prefix', 'contains'):
        return _err('match must be exact|prefix|contains', 400)
    limit = _limit(request)
    try:
        entries = canon_reader.lookup(_resources_dir(), key, term,
                                      match=match, limit=limit)
    except reg.RegistryError:
        return _err('dictionary not available on server', 503)
    return JsonResponse({'entries': entries, 'count': len(entries)})

from django.http import JsonResponse
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from .sqlite_reader import read_table

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

# `allowed`, `search_cols`, `table` and these filenames are interpolated into
# SQL as identifiers by sqlite_reader — keep them fixed, server-defined values,
# never request-derived. Only param *values* are bound.
DB_TABLES = {
    'bookmarks':  ('bookmark.sqlite', 'bookmark'),
    'highlights': ('highlight.sqlite', 'highlight'),
    'tags':       ('tag.sqlite', 'tag'),
    'history':    ('history.sqlite', 'history'),
    'lexicon':    ('saved_lexicon.sqlite', 'lexicon'),
}


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _paging(request):
    limit = max(1, min(_int(request.GET.get('limit'), DEFAULT_LIMIT), MAX_LIMIT))
    offset = max(0, _int(request.GET.get('offset'), 0))
    return limit, offset


def _filters(request, allowed):
    out = {}
    for param, col in allowed.items():
        val = request.GET.get(param)
        if val not in (None, ''):
            out[col] = val
    return out


def _list(request, db_filename, table, *, allowed, search_cols):
    limit, offset = _paging(request)
    platform = request.GET.get('platform') or None
    filters = _filters(request, allowed)
    q = request.GET.get('q')
    search = (search_cols, q) if q else None
    rows, total = read_table(request.user, db_filename, table, filters=filters,
                             search=search, platform=platform,
                             limit=limit, offset=offset)
    return JsonResponse({'items': rows, 'count': total,
                         'limit': limit, 'offset': offset})


def _content_endpoint(allowed, search_cols, key):
    db_filename, table = DB_TABLES[key]

    @api_view(['GET'])
    @authentication_classes((TokenAuthentication, SessionAuthentication))
    @permission_classes((IsAuthenticated,))
    def view(request):
        return _list(request, db_filename, table,
                     allowed=allowed, search_cols=search_cols)
    view.__name__ = key
    return view


bookmarks = _content_endpoint(
    {'code': 'code', 'volume': 'volume', 'page': 'page', 'important': 'important'},
    ['note'], 'bookmarks')

highlights = _content_endpoint(
    {'code': 'code', 'volume': 'volume', 'page': 'page'},
    ['selection', 'note'], 'highlights')

tags = _content_endpoint({}, ['name'], 'tags')

history = _content_endpoint({'starred': 'starred'}, ['keywords'], 'history')

lexicon = _content_endpoint({}, ['head'], 'lexicon')


@api_view(['GET'])
@authentication_classes((TokenAuthentication, SessionAuthentication))
@permission_classes((IsAuthenticated,))
def summary(request):
    counts, platforms = {}, set()
    for key, (db_filename, table) in DB_TABLES.items():
        rows, _ = read_table(request.user, db_filename, table,
                             limit=10 ** 9, offset=0)
        per = {}
        for row in rows:
            p = row['platform']
            per[p] = per.get(p, 0) + 1
            platforms.add(p)
        counts[key] = per
    return JsonResponse({'username': request.user.username,
                         'platforms': sorted(platforms), 'counts': counts})

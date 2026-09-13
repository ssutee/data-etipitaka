import sqlite3

from . import canon_registry as reg


class CanonError(Exception):
    pass


def _open_ro(path):
    return sqlite3.connect('file:%s?mode=ro&immutable=1' % path, uri=True)


def _snippet(content, term, width=80):
    if not term:
        return content[:width]
    idx = content.lower().find(term.lower())
    if idx < 0:
        return content[:width]
    start = max(0, idx - width // 2)
    end = min(len(content), idx + len(term) + width // 2)
    return ('…' if start else '') + content[start:end] + ('…' if end < len(content) else '')


def search(resources_dir, edition_key, query, *, volume=None, limit=20, offset=0):
    path = reg.edition_path(resources_dir, edition_key)  # raises RegistryError if missing
    where, params = 'content LIKE ?', ['%' + query + '%']
    if volume is not None:
        where += ' AND volume = ?'
        params.append('%02d' % int(volume))
    conn = _open_ro(path)
    try:
        total = conn.execute('SELECT COUNT(*) FROM main WHERE ' + where,
                             params).fetchone()[0]
        cur = conn.execute(
            'SELECT volume, page, items, content FROM main WHERE ' + where
            + ' ORDER BY volume, page LIMIT ? OFFSET ?', params + [limit, offset])
        items = [{'edition': edition_key, 'volume': v, 'page': p, 'items': it,
                  'snippet': _snippet(c or '', query)}
                 for (v, p, it, c) in cur.fetchall()]
        return items, total
    finally:
        conn.close()


def get_page(resources_dir, edition_key, volume, page):
    path = reg.edition_path(resources_dir, edition_key)
    conn = _open_ro(path)
    try:
        sql = 'SELECT volume, page, items, content FROM main WHERE volume=? AND page=?'
        row = conn.execute(sql, ('%02d' % int(volume), '%04d' % int(page))).fetchone()
        if row is None:  # unpadded fallback for editions that store raw values
            row = conn.execute(sql, (str(volume), str(page))).fetchone()
        if row is None:
            return None
        return {'edition': edition_key, 'volume': row[0], 'page': row[1],
                'items': row[2], 'content': row[3]}
    finally:
        conn.close()


def lookup(resources_dir, dictionary_key, term, *, match='exact', limit=20):
    meta = reg.DICTIONARIES.get(dictionary_key)
    if not meta:
        raise CanonError('unknown dictionary: %r' % dictionary_key)
    path = reg.dictionary_path(resources_dir, dictionary_key)
    head, table, cols = meta['head'], meta['table'], meta['columns']
    if match == 'exact':
        clause, param = head + ' = ?', term
    elif match == 'prefix':
        clause, param = head + ' LIKE ?', term + '%'
    elif match == 'contains':
        clause, param = head + ' LIKE ?', '%' + term + '%'
    else:
        raise CanonError('bad match mode: %r' % match)
    conn = _open_ro(path)
    try:
        cur = conn.execute(
            'SELECT %s FROM %s WHERE %s LIMIT ?' % (','.join(cols), table, clause),
            (param, limit))
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()

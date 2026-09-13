import os
import sqlite3
from datetime import datetime, timezone

# Columns holding a Unix-epoch float we normalize to ISO-8601.
_TIMESTAMP_COLUMNS = {'created'}


def _iso(value):
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return value


def _open_ro(path):
    return sqlite3.connect('file:%s?mode=ro&immutable=1' % path, uri=True)


def _table_exists(conn, table):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _build_where(filters, search):
    clauses, params = [], []
    for col, val in (filters or {}).items():
        clauses.append('%s = ?' % col)
        params.append(val)
    if search:
        cols, term = search
        clauses.append('(%s)' % ' OR '.join('%s LIKE ?' % c for c in cols))
        params.extend(['%' + term + '%'] * len(cols))
    if not clauses:
        return '', []
    return ' WHERE ' + ' AND '.join(clauses), params


def read_table(user, db_filename, table, *, filters=None, search=None,
               platform=None, limit=50, offset=0):
    """Read `table` from each of `user`'s `db_filename` SyncData files.

    Returns (rows, total). Rows are dicts tagged with 'platform'. Timestamp
    columns are normalized to ISO-8601. Missing files, missing tables and
    corrupt databases are skipped. Only the calling user's rows are ever read.
    """
    qs = user.syncdata_set.filter(name=db_filename)
    if platform:
        qs = qs.filter(platform=platform)

    where_sql, where_params = _build_where(filters, search)
    all_rows, total = [], 0
    for sd in qs:
        path = sd.file.path
        if not os.path.exists(path):
            continue
        try:
            conn = _open_ro(path)
        except sqlite3.Error:
            continue
        try:
            if not _table_exists(conn, table):
                continue
            total += conn.execute(
                'SELECT COUNT(*) FROM %s%s' % (table, where_sql), where_params
            ).fetchone()[0]
            cur = conn.execute('SELECT * FROM %s%s' % (table, where_sql), where_params)
            cols = [c[0] for c in cur.description]
            ts_cols = _TIMESTAMP_COLUMNS & set(cols)
            for raw in cur.fetchall():
                row = dict(zip(cols, raw))
                for tc in ts_cols:
                    row[tc] = _iso(row[tc])
                row['platform'] = sd.platform
                all_rows.append(row)
        except sqlite3.DatabaseError:
            continue
        finally:
            conn.close()

    return all_rows[offset:offset + limit], total

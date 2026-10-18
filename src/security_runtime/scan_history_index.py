"""Rebuildable history index, compatible with the original two-column writer.

Triggers retain only row identities, including writes made by an older Runtime.
Maintenance and dirty-row merging are bounded. An incomplete/unusable index
falls back to the original streaming query, never to a truncated history.
"""
from __future__ import annotations

import json
from pathlib import Path


CONTRACT = 'scan-history-index-v1'
BACKFILL_LIMIT = 128
DIRTY_READ_LIMIT = 128
WORKSPACE_LIMIT = 256
INPUT_BYTES = 8_000_000
PATH_BYTES = 32_768
_TRIGGERS = ('scan_history_insert', 'scan_history_update', 'scan_history_delete')
_TABLES = ('scan_history_index', 'scan_history_dirty', 'scan_history_meta')
_COLUMNS = dict(scan_history_index={'scan_id', 'source_rowid', 'workspace_path'},
                scan_history_dirty={'source_rowid'}, scan_history_meta={'name', 'value'})


def _layout_known(db, names):
    return all({row[1] for row in db.execute(f'PRAGMA table_info({table})')} == columns
               for table, columns in _COLUMNS.items() if table in names)


def initialize(db):
    """Called only by a writable store, inside its schema transaction."""
    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','trigger')")}
    tracking_intact = set(_TRIGGERS).issubset(names)
    if not _layout_known(db, names):
        return
    if 'scan_history_meta' in names:
        old = db.execute("SELECT value FROM scan_history_meta WHERE name='contract'").fetchone()
        if old is not None and old[0] != CONTRACT:
            return  # An unknown cache format never changes the legacy scans table.
    db.execute('CREATE TABLE IF NOT EXISTS scan_history_index '
               '(scan_id TEXT PRIMARY KEY, source_rowid INTEGER NOT NULL UNIQUE, workspace_path TEXT NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS scan_history_workspace_order '
               'ON scan_history_index(workspace_path, source_rowid DESC)')
    db.execute('CREATE TABLE IF NOT EXISTS scan_history_dirty (source_rowid INTEGER PRIMARY KEY)')
    db.execute('CREATE TABLE IF NOT EXISTS scan_history_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
    db.execute('CREATE TRIGGER IF NOT EXISTS scan_history_insert AFTER INSERT ON scans BEGIN '
               'INSERT OR REPLACE INTO scan_history_dirty VALUES (NEW.rowid); END')
    db.execute('CREATE TRIGGER IF NOT EXISTS scan_history_update AFTER UPDATE ON scans BEGIN '
               'INSERT OR REPLACE INTO scan_history_dirty VALUES (OLD.rowid); '
               'INSERT OR REPLACE INTO scan_history_dirty VALUES (NEW.rowid); END')
    db.execute('CREATE TRIGGER IF NOT EXISTS scan_history_delete AFTER DELETE ON scans BEGIN '
               'INSERT OR REPLACE INTO scan_history_dirty VALUES (OLD.rowid); END')
    row = db.execute("SELECT value FROM scan_history_meta WHERE name='contract'").fetchone()
    if row is None:
        db.execute("INSERT INTO scan_history_meta VALUES ('contract', ?)", (CONTRACT,))
    if (not tracking_intact or not db.execute(
            "SELECT 1 FROM scan_history_meta WHERE name='seed_complete'").fetchone()):
        # Capture a fixed initial upper bound, not every old row in one write
        # transaction. Triggers retain later writes, including low rowid reuse.
        # A missing trigger means there may also be an unobserved older update;
        # re-seed the initial inventory before trusting indexed-only results.
        upper = db.execute('SELECT max(rowid) FROM scans').fetchone()[0]
        db.executemany('INSERT OR REPLACE INTO scan_history_meta VALUES (?,?)',
                       [('seed_upper', '' if upper is None else str(upper)),
                        ('seed_cursor', ''), ('seed_complete', '1' if upper is None else '0')])


def _seed_state(db):
    values = dict(db.execute("SELECT name,value FROM scan_history_meta WHERE name IN "
                             "('seed_upper','seed_cursor','seed_complete')"))
    if set(values) != {'seed_upper', 'seed_cursor', 'seed_complete'} or values['seed_complete'] not in {'0', '1'}:
        return None
    try:
        upper = int(values['seed_upper']) if values['seed_upper'] else None
        cursor = int(values['seed_cursor']) if values['seed_cursor'] else None
        if any(value is not None and not -(2**63) <= value < 2**63 for value in (upper, cursor)):
            return None
        if values['seed_complete'] == '0' and (upper is None or cursor is not None and cursor > upper):
            return None
        return values['seed_complete'] == '1', upper, cursor
    except (TypeError, ValueError):
        return None


def _ready(db):
    names = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','trigger')")}
    if not set((*_TABLES, *_TRIGGERS)).issubset(names):
        return False
    if not _layout_known(db, names):
        return False
    row = db.execute("SELECT value FROM scan_history_meta WHERE name='contract'").fetchone()
    return row is not None and row[0] == CONTRACT and _seed_state(db) is not None


def has_pending(db):
    return _ready(db) and (not _seed_state(db)[0]
        or db.execute('SELECT 1 FROM scan_history_dirty LIMIT 1').fetchone() is not None)


def _seed_batch(db, limit):
    complete, upper, cursor = _seed_state(db)
    if complete:
        return
    lower = ' AND rowid>?' if cursor is not None else ''
    parameters = (upper, cursor, limit) if cursor is not None else (upper, limit)
    rows = db.execute(f'SELECT rowid FROM scans WHERE rowid<=?{lower} ORDER BY rowid LIMIT ?',
                      parameters).fetchall()
    db.executemany('INSERT OR IGNORE INTO scan_history_dirty VALUES (?)', rows)
    if rows:
        db.execute("UPDATE scan_history_meta SET value=? WHERE name='seed_cursor'", (str(rows[-1][0]),))
    if len(rows) < limit:
        db.execute("UPDATE scan_history_meta SET value='1' WHERE name='seed_complete'")


def _path(raw):
    value = json.loads(raw)['target_profile']['path']
    if not isinstance(value, str):
        raise TypeError('Invalid stored workspace path')
    if len(value.encode('utf-8')) > PATH_BYTES:
        raise ValueError('Stored workspace path exceeds the index allowance')
    return value


def reconcile(db, limit=None):
    """Advance at most one batch in the caller's writable transaction.

    Invalid legacy records remain dirty. They must take the compatibility path
    so the original query's errors and ordering are not changed by this cache.
    """
    if not _ready(db):
        return
    limit = BACKFILL_LIMIT if limit is None else limit
    if type(limit) is not int or not 1 <= limit <= BACKFILL_LIMIT:
        raise ValueError('Invalid scan history maintenance batch')
    _seed_batch(db, limit)
    rows = db.execute('SELECT d.source_rowid,s.id,length(CAST(s.data AS BLOB)) FROM scan_history_dirty d '
                      'LEFT JOIN scans s ON s.rowid=d.source_rowid '
                      'ORDER BY d.source_rowid DESC LIMIT ?', (limit,)).fetchall()
    remaining = INPUT_BYTES
    for source_rowid, scan_id, size in rows:
        if size is None:
            db.execute('DELETE FROM scan_history_index WHERE source_rowid=?', (source_rowid,))
        else:
            if size > remaining:
                continue
            remaining -= size
            raw = db.execute('SELECT data FROM scans WHERE rowid=?', (source_rowid,)).fetchone()[0]
            try:
                path = _path(raw)
                if not isinstance(scan_id, str):
                    continue
            except (ValueError, TypeError, KeyError, RuntimeError):
                continue
            db.execute('DELETE FROM scan_history_index WHERE source_rowid=?', (source_rowid,))
            db.execute('INSERT OR REPLACE INTO scan_history_index VALUES (?,?,?)',
                       (scan_id, source_rowid, path))
        db.execute('DELETE FROM scan_history_dirty WHERE source_rowid=?', (source_rowid,))


def _compat_latest(db, workspace):
    # Stream the legacy order; a fallback must not omit an older matching scan.
    for row in db.execute('SELECT data FROM scans ORDER BY rowid DESC'):
        data = json.loads(row[0])
        if workspace is None or Path(data['target_profile']['path']).resolve() == workspace:
            return data
    return None


def _matching_workspaces(db, workspace):
    paths = db.execute('SELECT DISTINCT workspace_path FROM scan_history_index LIMIT ?',
                       (WORKSPACE_LIMIT + 1,)).fetchall()
    if len(paths) > WORKSPACE_LIMIT:
        return None
    try:
        # Resolve the stored spelling at query time, like the original code.
        # Cached absolute identities would change relative-path/junction behavior.
        return [row[0] for row in paths if Path(row[0]).resolve() == workspace]
    except (ValueError, OSError, RuntimeError):
        return None


def latest(db, workspace=None):
    """Read existing state only; all decisions share one SQLite read snapshot."""
    if not db.in_transaction:
        db.execute('BEGIN')
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'").fetchone():
        return None
    requested = Path(workspace).resolve() if workspace is not None else None
    if requested is None:
        row = db.execute('SELECT data FROM scans ORDER BY rowid DESC LIMIT 1').fetchone()
        return json.loads(row[0]) if row else None
    if not _ready(db):
        return _compat_latest(db, requested)
    if not _seed_state(db)[0]:
        return _compat_latest(db, requested)
    dirty = db.execute('SELECT d.source_rowid,length(CAST(s.data AS BLOB)) FROM scan_history_dirty d '
                       'LEFT JOIN scans s ON s.rowid=d.source_rowid '
                       'ORDER BY d.source_rowid DESC LIMIT ?', (DIRTY_READ_LIMIT + 1,)).fetchall()
    if len(dirty) > DIRTY_READ_LIMIT or sum(row[1] or 0 for row in dirty) > INPUT_BYTES:
        return _compat_latest(db, requested)
    pending = None
    try:
        for source_rowid, size in dirty:
            if size is None:
                continue
            raw = db.execute('SELECT data FROM scans WHERE rowid=?', (source_rowid,)).fetchone()[0]
            if Path(_path(raw)).resolve() == requested:
                if pending is None:
                    pending = (source_rowid, raw)
    except (ValueError, TypeError, KeyError, OSError, RuntimeError):
        return _compat_latest(db, requested)
    paths = _matching_workspaces(db, requested)
    if paths is None:
        return _compat_latest(db, requested)
    indexed = None
    if paths:
        placeholders = ','.join('?' for _ in paths)
        indexed = db.execute(
            'SELECT i.source_rowid,s.data FROM scan_history_index i '
            'JOIN scans s ON s.id=i.scan_id AND s.rowid=i.source_rowid '
            f'WHERE i.workspace_path IN ({placeholders}) '
            'AND NOT EXISTS (SELECT 1 FROM scan_history_dirty d WHERE d.source_rowid=i.source_rowid) '
            'ORDER BY i.source_rowid DESC LIMIT 1', paths).fetchone()
    newest = max((row for row in (pending, indexed) if row is not None),
                 key=lambda row: row[0], default=None)
    return json.loads(newest[1]) if newest is not None else None

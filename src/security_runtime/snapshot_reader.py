"""Bounded internal readers of sealed raw snapshots, never of live sources.

One explicit read transaction authenticates the complete entry inventory before
it is exposed. Object existence/type/length are checked at entry; object bytes
are hashed only on explicit, separately budgeted reads. This is not a typed
task-source resolver or a streaming interface for a single large object.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat

from .snapshot_store import SnapshotStoreError, _encode, _gc_canonical_path
from .closeout_state import readonly_uri


MAX_RECORD_BYTES = 65536
MAX_PATH_BYTES = 4096
MAX_CURSOR_BYTES = 32768
MAX_CONTENT_BYTES = 8_000_000
SQL_LENGTH = 73728
MAX_INTEGER = (1 << 63) - 1
ORDER = 'PATH_BINARY_V1'

_SCHEMA = {
    'captures': 'CREATE TABLE captures (ref TEXT PRIMARY KEY, task TEXT UNIQUE, data BLOB, mac TEXT)',
    'entries': 'CREATE TABLE entries (ref TEXT, seq INTEGER, path TEXT, data BLOB, mac TEXT, '
               'PRIMARY KEY(ref,seq), UNIQUE(ref,path))',
    'objects': 'CREATE TABLE objects (hash TEXT PRIMARY KEY, body BLOB NOT NULL)',
    'usage': 'CREATE TABLE usage (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER, mac TEXT)',
}
_INDEXES = {
    'sqlite_autoindex_captures_1': ('captures', ('ref',)),
    'sqlite_autoindex_captures_2': ('captures', ('task',)),
    'sqlite_autoindex_entries_1': ('entries', ('ref', 'seq')),
    'sqlite_autoindex_entries_2': ('entries', ('ref', 'path')),
    'sqlite_autoindex_objects_1': ('objects', ('hash',)),
}
_ROW = ("CASE WHEN typeof(seq)='integer' THEN seq END,"
        "CASE WHEN typeof(path)='text' AND length(CAST(path AS BLOB))<=4096 THEN path END,"
        "CASE WHEN typeof(data)='blob' AND length(data)<=65536 THEN data END,"
        "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END")


def _fail(reason):
    raise SnapshotStoreError(reason)


def _sql_error(error):
    code = getattr(error, 'sqlite_errorcode', 0) & 255
    if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        _fail('SNAPSHOT_STORAGE_BUSY')
    if code in {sqlite3.SQLITE_TOOBIG, sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
        _fail('SNAPSHOT_RECORD_INVALID')
    _fail('SNAPSHOT_STORAGE_UNAVAILABLE')


def _count(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def _path(value):
    try:
        return (isinstance(value, str) and 0 < len(value.encode()) <= MAX_PATH_BYTES
                and _gc_canonical_path(value))
    except (UnicodeError, ValueError):
        return False


def _hex(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


class SealedSnapshotReader:
    """Use only as a context manager; each response is independently bounded."""
    def __init__(self, store, ref, binding):
        self.store, self.ref, self.binding = store, ref, binding
        self._db, self._header, self._files = None, None, []
        self._closed = False

    def _pin(self, path):
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        try:
            info, actual = os.fstat(fd), path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino)
                    or (os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
                _fail('SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE')
        except BaseException:
            os.close(fd)
            raise
        self._files.append((path, fd, (info.st_dev, info.st_ino)))
        return fd

    def _sidecars(self):
        if any(os.path.lexists(str(self.store.path) + suffix) for suffix in ('-wal', '-shm')):
            _fail('SNAPSHOT_READER_UNSUPPORTED_JOURNAL')
        if os.path.lexists(str(self.store.path) + '-journal'):
            _fail('SNAPSHOT_READER_JOURNAL_BUSY')

    def _stable(self):
        try:
            self.store._paths()
            for path, fd, expected in self._files:
                actual, pinned = path.lstat(), os.fstat(fd)
                if ((actual.st_dev, actual.st_ino) != expected
                        or (pinned.st_dev, pinned.st_ino) != expected
                        or not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(pinned.st_mode)
                        or actual.st_nlink != 1 or pinned.st_nlink != 1
                        or (os.name != 'nt' and (actual.st_uid != os.getuid()
                            or pinned.st_uid != os.getuid() or actual.st_mode & 0o077
                            or pinned.st_mode & 0o077))):
                    _fail('SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE')
        except (OSError, ValueError) as error:
            if isinstance(error, SnapshotStoreError):
                raise
            _fail('SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE')

    def _diagnose_open_journal(self):
        """Read only the already pinned DB prefix after an opening SQL error."""
        try:
            self._sidecars()
            for path, fd, _ in self._files:
                if path == self.store.path:
                    os.lseek(fd, 18, os.SEEK_SET)
                    if os.read(fd, 2) == b'\x02\x02':
                        _fail('SNAPSHOT_READER_UNSUPPORTED_JOURNAL')
        except OSError:
            _fail('SNAPSHOT_STORAGE_UNAVAILABLE')

    def __enter__(self):
        if self._closed or self._db is not None:
            _fail('SNAPSHOT_READER_CLOSED')
        try:
            if not isinstance(self.ref, str) or re.fullmatch('ws2-[a-f0-9]{32}', self.ref) is None:
                _fail('SNAPSHOT_REFERENCE_INVALID')
            self.store._binding(self.binding)
            self.store._paths()
            if not self.store.path.exists() or not self.store.marker.exists():
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            self._sidecars()
            marker = self._pin(self.store.marker)
            if not hmac.compare_digest(os.read(marker, 65),
                                       self.store._mac(self.store._store_identity()).encode()):
                _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
            database = self._pin(self.store.path)
            raw = os.read(database, 100)
            if len(raw) != 100 or raw[:16] != b'SQLite format 3\0':
                _fail('SNAPSHOT_RECORD_INVALID')
            if raw[18:20] == b'\x02\x02':
                _fail('SNAPSHOT_READER_UNSUPPORTED_JOURNAL')
            if raw[18:20] != b'\x01\x01':
                _fail('SNAPSHOT_RECORD_INVALID')
            self._sidecars()
            self._db = sqlite3.connect(readonly_uri(self.store.path), uri=True, timeout=2)
            self._db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, SQL_LENGTH)
            # Configure this before any schema/database access. A concurrent
            # WAL mode switch must not make a read-only connection create a
            # shared-memory index. Read-only exclusive WAL access instead fails
            # without creating sidecars; rollback read transactions still hold
            # a shared read view and leave writers to commit after close.
            if self._db.execute('PRAGMA locking_mode=EXCLUSIVE').fetchone() != ('exclusive',):
                _fail('SNAPSHOT_STORAGE_UNAVAILABLE')
            self._db.execute('PRAGMA trusted_schema=OFF')
            self._db.execute('PRAGMA query_only=ON')
            self._db.execute('PRAGMA cache_size=-1024')
            self._db.execute('BEGIN')
            self._schema()
            # Schema access establishes this transaction's shared read view.
            self._sidecars()
            self._stable()
            self._header = self._load_header()
            self._verify_inventory()
            self._cursor_binding = dict(ref=self.ref, binding=self.store._binding(self.binding),
                store=self.store._store_identity(), root_digest=self._header['root_digest'],
                entry_count=self._header['entry_count'], order=ORDER)
            return self
        except sqlite3.Error as error:
            try:
                self._diagnose_open_journal()
            finally:
                self.close()
            _sql_error(error)
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            self.close()
            if isinstance(error, SnapshotStoreError):
                raise
            _fail('SNAPSHOT_RECORD_INVALID')
        except BaseException:
            self.close()
            raise

    def close(self):
        self._closed = True
        db, files = self._db, self._files
        self._db, self._files = None, []
        try:
            if db is not None:
                db.close()
        finally:
            for _, fd, _ in files:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def __exit__(self, *exception):
        self.close()
        return False

    def _active(self):
        if self._closed or self._db is None:
            _fail('SNAPSHOT_READER_CLOSED')
        self._stable()

    @property
    def header(self):
        self._active()
        return json.loads(_encode(self._header))

    def _schema(self):
        rows = self._db.execute("SELECT type,CASE WHEN length(name)<=128 THEN name END,"
            "CASE WHEN length(tbl_name)<=128 THEN tbl_name END,"
            "CASE WHEN sql IS NULL OR length(CAST(sql AS BLOB))<=4096 THEN sql END "
            "FROM sqlite_schema ORDER BY name LIMIT 32").fetchall()
        expected = set(_SCHEMA) | set(_INDEXES)
        if len(rows) != len(expected) or {row[1] for row in rows} != expected:
            _fail('SNAPSHOT_RECORD_INVALID')
        for kind, name, table, sql in rows:
            if name in _SCHEMA:
                if kind != 'table' or table != name or sql != _SCHEMA[name]:
                    _fail('SNAPSHOT_RECORD_INVALID')
            elif name in _INDEXES:
                if kind != 'index' or table != _INDEXES[name][0] or sql is not None:
                    _fail('SNAPSHOT_RECORD_INVALID')
                columns = self._db.execute(f'PRAGMA index_xinfo("{name}")').fetchall()
                keys = [item for item in columns if item[5]]
                if (tuple(item[2] for item in keys) != _INDEXES[name][1]
                        or any(item[3] != 0 or item[4] != 'BINARY' for item in keys)):
                    _fail('SNAPSHOT_RECORD_INVALID')
            else:
                _fail('SNAPSHOT_RECORD_INVALID')

    def _decode(self, raw, mac):
        try:
            return self.store._decode(raw, mac)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            _fail('SNAPSHOT_RECORD_INVALID')

    def _load_header(self):
        row = self._db.execute("SELECT CASE WHEN typeof(ref)='text' AND length(ref)<=36 THEN ref END,"
            "CASE WHEN typeof(task)='text' AND length(CAST(task AS BLOB))<=4096 THEN task END,"
            "CASE WHEN typeof(data)='blob' AND length(data)<=65536 THEN data END,"
            "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END FROM captures WHERE ref=?",
            (self.ref,)).fetchone()
        if row is None:
            _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
        ref, task, raw, mac = row
        header = self._decode(raw, mac)
        if (header.get('ref') != ref or ref != self.ref or not isinstance(header.get('binding'), dict)
                or task != header['binding'].get('task_ref')):
            _fail('SNAPSHOT_RECORD_INVALID')
        if _encode(header.get('binding')) != _encode(self.store._binding(self.binding)):
            _fail('SNAPSHOT_BINDING_MISMATCH')
        if header.get('state') != 'SEALED':
            _fail('SNAPSHOT_NOT_SEALED')
        required = {'ref', 'binding', 'state', 'cursor', 'entry_count', 'source_bytes', 'gap_count',
                    'last_page', 'expected_files', 'inventory_complete', 'root_digest', 'coverage_complete'}
        if (set(header) != required or not _count(header.get('entry_count'))
                or not _count(header.get('source_bytes')) or not _count(header.get('gap_count'))
                or not _hex(header.get('root_digest'))):
            _fail('SNAPSHOT_RECORD_INVALID')
        if (header.get('coverage_complete') is not True or header.get('inventory_complete') is not True
                or header['gap_count'] != 0 or type(header.get('expected_files')) is not int
                or header['expected_files'] != header['entry_count']):
            _fail('SNAPSHOT_COVERAGE_INCOMPLETE')
        if header['entry_count'] == 0:
            if header['cursor'] is not None or header['last_page'] is not None:
                _fail('SNAPSHOT_RECORD_INVALID')
        else:
            last = header['last_page']
            if (not isinstance(header['cursor'], str) or not header['cursor']
                    or len(header['cursor'].encode()) > 4096
                    or not isinstance(last, dict) or set(last) != {'previous', 'cursor', 'digest'}
                    or last['cursor'] != header['cursor'] or not _hex(last['digest'])
                    or (last['previous'] is not None and (not isinstance(last['previous'], str) or not last['previous']
                        or len(last['previous'].encode()) > 4096))):
                _fail('SNAPSHOT_RECORD_INVALID')
        return header

    def _entry(self, row):
        seq, path, raw, mac = row
        value = self._decode(raw, mac)
        if (set(value) != {'ref', 'seq', 'path', 'sha256', 'size', 'metadata'}
                or not _count(seq) or seq < 1 or value.get('seq') != seq
                or type(value.get('seq')) is not int or value.get('ref') != self.ref
                or not _path(path) or value.get('path') != path or not _hex(value.get('sha256'))
                or not _count(value.get('size')) or value['size'] > self.store.database_quota
                or not isinstance(value.get('metadata'), dict)):
            _fail('SNAPSHOT_RECORD_INVALID')
        try:
            if len(_encode(value['metadata'])) > 8192:
                _fail('SNAPSHOT_RECORD_INVALID')
        except (ValueError, TypeError, RecursionError):
            _fail('SNAPSHOT_RECORD_INVALID')
        return value

    def _verify_inventory(self):
        seen, size, last_seq, gap = 0, 0, 0, False
        for row in self._db.execute(f'SELECT {_ROW} FROM entries WHERE ref=? ORDER BY seq', (self.ref,)):
            value = self._entry(row)
            gap = gap or value['seq'] != last_seq + 1
            last_seq = value['seq']
            seen += 1
            size += value['size']
            object_info = self._db.execute('SELECT typeof(body),length(body) FROM objects WHERE hash=?',
                                           (value['sha256'],)).fetchone()
            if object_info is None:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            if object_info != ('blob', value['size']):
                _fail('SNAPSHOT_RECORD_INVALID')
        if gap or seen != self._header['entry_count'] or size != self._header['source_bytes']:
            _fail('SNAPSHOT_HISTORY_UNAVAILABLE')

    def _cursor(self, last):
        value = dict(self._cursor_binding, last_path=last)
        raw = _encode(dict(value=value, mac=self.store._mac(value)))
        cursor = base64.urlsafe_b64encode(raw).decode().rstrip('=')
        if len(cursor) > MAX_CURSOR_BYTES:
            _fail('SNAPSHOT_PAGE_BYTE_BUDGET')
        return cursor

    def _after(self, cursor):
        if cursor is None:
            return None
        try:
            if not isinstance(cursor, str) or not 0 < len(cursor) <= MAX_CURSOR_BYTES:
                raise ValueError()
            raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip('=') != cursor:
                raise ValueError()
            value = json.loads(raw)
            if (not isinstance(value, dict) or set(value) != {'value', 'mac'}
                    or not isinstance(value['value'], dict) or not _hex(value['mac'])
                    or not hmac.compare_digest(value['mac'], self.store._mac(value['value']))):
                raise ValueError()
            last = value['value'].get('last_path')
            if not _path(last) or _encode(value['value']) != _encode(dict(self._cursor_binding, last_path=last)):
                raise ValueError()
            return last
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            _fail('SNAPSHOT_CURSOR_INVALID')

    def entries_page(self, cursor=None, limit_items=256, limit_bytes=65536):
        self._active()
        if (type(limit_items) is not int or not 1 <= limit_items <= 256
                or type(limit_bytes) is not int or not 1 <= limit_bytes <= MAX_RECORD_BYTES):
            _fail('SNAPSHOT_PAGE_REQUEST_INVALID')
        after = self._after(cursor)
        try:
            clause, args = ('', (self.ref, limit_items + 1)) if after is None else (
                ' AND path COLLATE BINARY>?', (self.ref, after, limit_items + 1))
            rows = iter(self._db.execute(f'SELECT {_ROW} FROM entries WHERE ref=?{clause} '
                                        'ORDER BY path COLLATE BINARY LIMIT ?', args))
            row = next(rows, None)
            result = dict(entries=[], next_cursor=None, complete=True)
            while row is not None and len(result['entries']) < limit_items:
                value = self._entry(row)
                following = next(rows, None)
                candidate = dict(entries=[*result['entries'], value],
                    next_cursor=self._cursor(value['path']) if following is not None else None,
                    complete=following is None)
                if len(_encode(candidate)) > limit_bytes:
                    if not result['entries']:
                        _fail('SNAPSHOT_PAGE_BYTE_BUDGET')
                    return result
                result, row = candidate, following
            if len(_encode(result)) > limit_bytes:
                _fail('SNAPSHOT_PAGE_BYTE_BUDGET')
            return result
        except sqlite3.Error as error:
            _sql_error(error)

    def entry(self, path):
        self._active()
        if not _path(path):
            _fail('SNAPSHOT_PAGE_REQUEST_INVALID')
        try:
            row = self._db.execute(f'SELECT {_ROW} FROM entries WHERE ref=? AND path=?',
                                   (self.ref, path)).fetchone()
            if row is None:
                _fail('SNAPSHOT_HISTORY_UNAVAILABLE')
            return self._entry(row)
        except sqlite3.Error as error:
            _sql_error(error)

    def read_content(self, path, max_bytes=65536):
        self._active()
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_CONTENT_BYTES:
            _fail('SNAPSHOT_PAGE_REQUEST_INVALID')
        value = self.entry(path)
        if value['size'] > max_bytes:
            _fail('SNAPSHOT_CONTENT_BYTE_BUDGET')
        previous = self._db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max(SQL_LENGTH, max_bytes + 256))
        try:
            row = self._db.execute("SELECT CASE WHEN typeof(body)='blob' AND length(body)=? "
                'THEN body END FROM objects WHERE hash=?', (value['size'], value['sha256'])).fetchone()
            if (row is None or not isinstance(row[0], bytes) or len(row[0]) != value['size']
                    or hashlib.sha256(row[0]).hexdigest() != value['sha256']):
                _fail('SNAPSHOT_CONTENT_UNAVAILABLE')
            return row[0]
        except sqlite3.Error as error:
            _sql_error(error)
        finally:
            self._db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, previous)

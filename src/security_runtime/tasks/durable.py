"""Bounded, root-bound signed records for asynchronous task operations."""
from contextlib import closing, contextmanager
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from ..closeout_state import digest, encode, readonly_uri
from ..hook_state import no_links


class SignedRecords:
    max_rows = 128
    max_record_bytes = 4_000_000

    def __init__(self, hooks, root, name, *, now=time.time):
        self.hooks, self.root, self.now = hooks, Path(root).resolve(), now
        self.path = hooks.workspace_directory(self.root) / name

    def _paths(self):
        for path in (self.path, *(Path(str(self.path)+s) for s in ('-journal', '-wal', '-shm'))):
            no_links(path)
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128_000_000:
                    raise ValueError('Task operation storage unavailable')

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Task operation key unavailable')
        return key

    @contextmanager
    def transaction(self):
        self._paths()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._paths()
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, data TEXT NOT NULL, mac TEXT NOT NULL)')
            yield db

    def _decode(self, row):
        if row is None:
            return None
        key, raw, mac = row
        if not isinstance(raw, str) or not isinstance(mac, str):
            raise ValueError('Task operation storage limit exceeded')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('key') != key
                or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(mac, digest(self._key(), value))):
            raise ValueError('Task operation signature mismatch')
        return value

    def _select(self):
        return ('SELECT key, CASE WHEN length(CAST(data AS BLOB))<=' + str(self.max_record_bytes)
                + ' THEN data END, CASE WHEN length(mac)=64 THEN mac END FROM records')

    def _get(self, db, key):
        return self._decode(db.execute(self._select()+' WHERE key=?', (key,)).fetchone())

    def _all(self, db):
        rows = db.execute(self._select()+' ORDER BY rowid LIMIT ?', (self.max_rows+1,)).fetchall()
        if len(rows) > self.max_rows:
            raise ValueError('Task operation capacity exceeded')
        return [self._decode(row) for row in rows]

    def _put(self, db, key, value):
        value = dict(value, key=key, workspace=str(self.root))
        raw = encode(value)
        if len(raw) > self.max_record_bytes:
            raise ValueError('Task operation record too large')
        used = db.execute('SELECT coalesce(sum(length(CAST(data AS BLOB))),0) FROM records WHERE key<>?',
                          (key,)).fetchone()[0]
        if used+len(raw) > 96_000_000:
            raise ValueError('Task operation storage capacity exceeded')
        if not self._get(db, key) and db.execute('SELECT count(*) FROM records').fetchone()[0] >= self.max_rows:
            raise ValueError('Task operation capacity exceeded')
        db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)',
                   (key, raw.decode(), digest(self._key(), value)))
        return value

    def read(self, key):
        self._paths()
        if not self.path.exists():
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            return self._get(db, key)

    def rows(self):
        self._paths()
        if not self.path.exists():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            return self._all(db)

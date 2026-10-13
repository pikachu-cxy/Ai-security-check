"""Signed task snapshots. Private bounded local state, never a repair grant."""
from __future__ import annotations

from contextlib import closing
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time

from .closeout_state import digest, encode, readonly_uri
from .hook_state import no_links

CONTRACT = 'task-security-v1'
REF = re.compile(r'ts1-[a-f0-9]{32}')
MAX_RECORD_BYTES = 4_000_000
TTL = 24 * 3600


class TaskSecurityStore:
    def __init__(self, hooks, root, *, now=time.time):
        self.root, self.hooks, self.now = root, hooks, now
        self.path = hooks.workspace_directory(root) / 'task-security.db'

    def key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Task key cannot be verified')
        return key

    def decode(self, row):
        if not row:
            return None
        raw, mac = row
        if len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError('Task record budget exceeded')
        value = json.loads(raw)
        if (value.get('contract') != CONTRACT or not REF.fullmatch(value.get('task_ref', ''))
                or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(mac, digest(self.key(), value))):
            raise ValueError('Task state cannot be verified')
        return value

    def get(self, ref=None, *, active=False, task_key=None):
        no_links(self.path)
        if ref is not None and (not isinstance(ref, str) or not REF.fullmatch(ref)):
            raise ValueError('Invalid task reference')
        if not self.path.is_file():
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if ref:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()
            elif active:
                row = db.execute("SELECT data,mac FROM security_tasks WHERE phase IN ('ACTIVE','STATIC_RUNNING','READY','REVIEWING') ORDER BY rowid DESC LIMIT 1").fetchone()
            else:
                row = db.execute('SELECT data,mac FROM security_tasks WHERE task_key=? ORDER BY rowid DESC LIMIT 1', (task_key,)).fetchone()
            value = self.decode(row)
            if value and self.now() - value['created_at'] > TTL:
                return None
            return value

    def save(self, value, *, new=False):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE IF NOT EXISTS security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM security_tasks WHERE created<?', (self.now()-TTL,))
            old = self.decode(db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (value['task_ref'],)).fetchone())
            if (new and old) or (not new and (not old or old['generation'] != value['generation'])):
                raise ValueError('Task changed concurrently; read current task first')
            if new and db.execute('SELECT count(*) FROM security_tasks').fetchone()[0] >= 32:
                raise ValueError('Task history budget exceeded')
            value = dict(value, generation=value['generation']+1)
            raw = encode(value)
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError('Task record budget exceeded')
            db.execute('INSERT OR REPLACE INTO security_tasks VALUES(?,?,?,?,?,?)',
                       (value['task_ref'], value['task_key'], value['phase'], value['created_at'], raw.decode(), digest(self.key(), value)))
            return value

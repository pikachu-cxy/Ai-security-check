"""Signed completed execution facts awaiting a short publication lock.

This independent journal cannot authorize execution or publication. Writers
stage already completed, sanitized facts without the workspace lock; recovery
must recheck the original task, input, Hook state and attempt fence. Queries
never drain it. Acknowledgement only removes facts committed or superseded by
an authoritative target.
"""
from __future__ import annotations

from contextlib import closing
import hmac
import json
from pathlib import Path
import re
import sqlite3

from .closeout_state import digest, encode, readonly_uri
from .hook_state import no_links
from .scan_attempt import AttemptLease

CONTRACT = 'scan-publication-v1'
MAX_RECORDS = 32
MAX_RECORD_BYTES = 8_000_000
MAX_TOTAL_BYTES = 32_000_000


class ScanPublications:
    def __init__(self, hooks, root):
        self.hooks, self.root = hooks, Path(root).resolve()
        self.path = hooks.workspace_directory(self.root) / 'scan-publications.db'

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Scan publication key cannot be verified')
        return key

    def _decode(self, row):
        if row is None:
            return None
        raw, signature = row
        if not isinstance(raw, str) or len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError('Scan publication budget exceeded')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('contract') != CONTRACT
                or value.get('workspace') != str(self.root)
                or value.get('kind') not in {'TASK', 'HOOK'}
                or not isinstance(value.get('scope_key'), str)
                or not isinstance(value.get('payload'), dict)
                or not isinstance(value.get('lease'), dict)
                or set(value['lease']) != {'attempt_id', 'generation', 'lease_owner', 'cancel_generation'}
                or not isinstance(signature, str)
                or not hmac.compare_digest(signature, digest(self._key(), value))):
            raise ValueError('Scan publication cannot be verified')
        AttemptLease(**value['lease'])
        lease = value['lease']
        if (not isinstance(lease['attempt_id'], str) or re.fullmatch(r'sa1-[a-f0-9]{32}', lease['attempt_id']) is None
                or type(lease['generation']) is not int or lease['generation'] < 1
                or not isinstance(lease['lease_owner'], str) or re.fullmatch(r'[a-f0-9]{32}', lease['lease_owner']) is None
                or type(lease['cancel_generation']) is not int or lease['cancel_generation'] < 0
                or not 1 <= len(value['scope_key']) <= 128
                or any(ord(c) < 32 for c in value['scope_key'])):
            raise ValueError('Scan publication attempt cannot be verified')
        return value

    def pending(self, kind, scope_key):
        """Read only; no schema, key, lease renewal or recovery is created."""
        if kind not in {'TASK', 'HOOK'} or not isinstance(scope_key, str):
            raise ValueError('Invalid scan publication scope')
        no_links(self.path)
        if not self.path.is_file():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True, timeout=2)) as db:
            db.execute('PRAGMA query_only=ON')
            rows = db.execute('SELECT data,mac FROM scan_publications WHERE kind=? AND scope_key=? '
                              'ORDER BY rowid LIMIT ?', (kind, scope_key, MAX_RECORDS+1)).fetchall()
        if len(rows) > MAX_RECORDS:
            raise ValueError('Scan publication capacity exceeded')
        values = [self._decode(row) for row in rows]
        if any(value['kind'] != kind or value['scope_key'] != scope_key for value in values):
            raise ValueError('Scan publication index binding cannot be verified')
        return values

    def stage(self, kind, scope_key, lease, payload):
        if kind not in {'TASK', 'HOOK'} or not isinstance(lease, AttemptLease):
            raise ValueError('Invalid scan publication request')
        value = dict(contract=CONTRACT, workspace=str(self.root), kind=kind,
                     scope_key=scope_key, lease=dict(lease.__dict__), payload=payload)
        raw = encode(value)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError('Scan publication budget exceeded')
        value = json.loads(raw)  # Canonical JSON facts, independent of caller aliases/tuples.
        no_links(self.path)
        # The attempt already established this private namespace and key. This
        # journal never creates either one while a publication lock is busy.
        signature = digest(self._key(), value)
        value = self._decode((raw.decode(), signature))
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS scan_publications '
                       '(ref TEXT PRIMARY KEY,kind TEXT NOT NULL,scope_key TEXT NOT NULL,data TEXT NOT NULL,mac TEXT NOT NULL)')
            old = self._decode(db.execute('SELECT data,mac FROM scan_publications WHERE ref=?',
                                         (lease.attempt_id,)).fetchone())
            if old is not None:
                if old != value:
                    raise ValueError('Scan publication source changed')
                return old
            count, size = db.execute('SELECT count(*),coalesce(sum(length(CAST(data AS BLOB))),0) '
                                     'FROM scan_publications').fetchone()
            if count >= MAX_RECORDS or size+len(raw) > MAX_TOTAL_BYTES:
                raise ValueError('Scan publication capacity exceeded; pending facts retained')
            db.execute('INSERT INTO scan_publications VALUES(?,?,?,?,?)',
                       (lease.attempt_id, kind, scope_key, raw.decode(), signature))
        return value

    def collect(self, attempts, *, limit=8):
        """Bounded mutation-only retirement of facts that lost their lane.

        A live original generation remains recoverable regardless of task or
        journal age. Only the existing signed attempt's terminal/expired state
        or a strictly newer generation proves that publication is unavailable.
        """
        if not self.hooks.lock_held(self.root):
            raise ValueError('Scan publication workspace lock required')
        if type(limit) is not int or not 1 <= limit <= MAX_RECORDS:
            raise ValueError('Invalid scan publication collection limit')
        no_links(self.path)
        if not self.path.is_file():
            return 0
        lane = attempts.read()['lane']
        if lane is None:
            return 0
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT ref,kind,scope_key,data,mac FROM scan_publications '
                              'ORDER BY rowid LIMIT ?', (MAX_RECORDS+1,)).fetchall()
            if len(rows) > MAX_RECORDS:
                raise ValueError('Scan publication capacity exceeded')
            collected = 0
            for ref, kind, scope, raw, signature in rows:
                value = self._decode((raw, signature))
                lease = AttemptLease(**value['lease'])
                if (ref != lease.attempt_id or kind != value['kind'] or scope != value['scope_key']):
                    raise ValueError('Scan publication index binding cannot be verified')
                superseded = lane['generation'] > lease.generation
                retired = attempts._matches(lane, lease) and (
                    lane['state'] != 'ACTIVE' or attempts.now() >= lane['expires_at'])
                if superseded or retired:
                    db.execute('DELETE FROM scan_publications WHERE ref=?', (ref,))
                    collected += 1
                    if collected == limit:
                        break
            return collected

    def acknowledge(self, value):
        """Only a fenced publication/supersession may discard a pending fact."""
        if not self.hooks.lock_held(self.root):
            raise ValueError('Scan publication workspace lock required')
        no_links(self.path)
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            ref = value['lease']['attempt_id']
            old = self._decode(db.execute('SELECT data,mac FROM scan_publications WHERE ref=?', (ref,)).fetchone())
            if old is not None and old != value:
                raise ValueError('Scan publication acknowledgement changed')
            db.execute('DELETE FROM scan_publications WHERE ref=?', (ref,))

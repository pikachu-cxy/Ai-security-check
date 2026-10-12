"""Signed, bounded closeout records; reads never create or migrate state."""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .hook_state import no_links

CONTRACT = 'closeout-state-v1'
MAX_RECORDS = 512
MAX_RECORD_BYTES = 1_000_000
REF = re.compile(r'co1-[a-f0-9]{32}')


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(key, value):
    return hmac.new(key, encode(value), hashlib.sha256).hexdigest()


def readonly_uri(path):
    # Keep Windows extended paths for long state directories, but encode them
    # as a URI path, never a URI authority. SQLite decodes native backslashes.
    from urllib.parse import quote
    value = str(path.resolve())
    if value.startswith('\\\\?\\'):
        return 'file:' + quote(value, safe=':/') + '?mode=ro'
    return Path(value).as_uri() + '?mode=ro'


class CloseoutStateStore:
    def __init__(self, path: Path, key_reader, *, now=time.time):
        self.path = Path(path)
        self.key_reader = key_reader
        self.now = now

    def _write(self):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('CREATE TABLE IF NOT EXISTS closeouts '
                   '(ref TEXT PRIMARY KEY, workspace TEXT NOT NULL, request_key TEXT NOT NULL, '
                   'data TEXT NOT NULL, mac TEXT NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS closeout_requests ON closeouts(workspace, request_key)')
        db.commit()
        db.execute('BEGIN IMMEDIATE')
        return db

    def _decode(self, row, workspace):
        if row is None:
            return None
        raw, mac = row
        if len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError('Closeout state cannot be verified')
        try:
            value = json.loads(raw)
            valid = (value['contract'] == CONTRACT and value['workspace_id'] == workspace
                     and REF.fullmatch(value['closeout_ref'])
                     and hmac.compare_digest(mac, digest(self.key_reader(), value)))
        except (ValueError, KeyError, TypeError, OSError):
            valid = False
        if not valid:
            raise ValueError('Closeout state cannot be verified')
        return value

    def _row(self, db, ref, workspace):
        if not isinstance(ref, str) or REF.fullmatch(ref) is None:
            raise ValueError('Invalid closeout reference')
        value = self._decode(db.execute('SELECT data, mac FROM closeouts WHERE ref=? AND workspace=?',
                                       (ref, workspace)).fetchone(), workspace)
        if value is not None and value['closeout_ref'] != ref:
            raise ValueError('Closeout reference binding cannot be verified')
        return value

    def _save(self, db, value):
        raw = encode(value)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError('Closeout record budget exceeded')
        db.execute('INSERT OR REPLACE INTO closeouts VALUES(?,?,?,?,?)',
                   (value['closeout_ref'], value['workspace_id'], value['request_key'],
                    raw.decode(), digest(self.key_reader(), value)))

    def get(self, ref, workspace):
        no_links(self.path)
        if not isinstance(ref, str) or REF.fullmatch(ref) is None:
            raise ValueError('Invalid closeout reference')
        if not self.path.is_file():
            return None
        try:
            with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
                db.execute('PRAGMA query_only=ON')
                if not db.execute("SELECT 1 FROM sqlite_master WHERE name='closeouts' AND type='table'").fetchone():
                    return None
                return self._row(db, ref, workspace)
        except sqlite3.DatabaseError:
            raise ValueError('Closeout state cannot be read safely') from None

    def prepare(self, workspace, scope, revision, plan, *, source_scan_id=None, deferred=(), details=None):
        request_key = digest(self.key_reader(), [workspace, scope, revision, plan, source_scan_id])
        with closing(self._write()) as db, db:
            rows = db.execute('SELECT data, mac FROM closeouts WHERE workspace=? AND request_key=? ORDER BY rowid DESC',
                              (workspace, request_key)).fetchall()
            for row in rows:
                existing = self._decode(row, workspace)
                if existing['status'] in {'PENDING', 'RUNNING', 'NEEDS_RETRY'}:
                    return existing
            if db.execute('SELECT count(*) FROM closeouts WHERE workspace=?', (workspace,)).fetchone()[0] >= MAX_RECORDS:
                raise ValueError('Closeout history budget exceeded')
            value = dict(contract=CONTRACT, closeout_ref='co1-' + uuid.uuid4().hex,
                         workspace_id=workspace, request_key=request_key, scope_files=list(scope),
                         prepared_revision=revision, plan_fingerprint=plan, source_scan_id=source_scan_id,
                         deferred_providers=list(deferred), generation=1, status='PENDING',
                         coverage='UNKNOWN', attempts=0, lease_owner=None, lease_until=None,
                         receipt=None, scan_ids=[], reason=None, created_at=self.now(), updated_at=self.now())
            value.update(details=details or {}, stop_dispatches=0)
            self._save(db, value)
            return value

    def claim(self, ref, workspace, revision, plan, *, recover=False, lease_seconds=600):
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None:
                raise ValueError('Closeout does not belong to this workspace')
            if (value['status'] == 'RUNNING' and not recover
                    and value['lease_until'] > self.now()):
                return value, None
            if (value['status'] == 'COMPLETED' and value['prepared_revision'] == revision
                    and value['plan_fingerprint'] == plan):
                return value, None
            if value['prepared_revision'] != revision or value['plan_fingerprint'] != plan:
                value['generation'] += 1
            owner = uuid.uuid4().hex
            value.update(status='RUNNING', prepared_revision=revision, plan_fingerprint=plan,
                         attempts=value['attempts'] + 1, lease_owner=owner,
                         lease_until=self.now() + lease_seconds, reason=None, updated_at=self.now())
            self._save(db, value)
            return value, owner

    def finish(self, ref, workspace, generation, owner, *, status, coverage, reason=None,
               receipt=None, scan_id=None):
        if status not in {'COMPLETED', 'NEEDS_RETRY'}:
            raise ValueError('Invalid closeout transition')
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None:
                raise ValueError('Closeout does not belong to this workspace')
            # An old runner cannot clear a newer arrival or another lease.
            if value['generation'] != generation or value['lease_owner'] != owner:
                return value, False
            value.update(status=status, coverage=coverage, reason=reason, receipt=receipt,
                         lease_owner=None, lease_until=None, updated_at=self.now())
            if scan_id is not None:
                value['scan_ids'] = (value['scan_ids'] + [scan_id])[-20:]
            self._save(db, value)
            return value, True

    def mark_pending(self, ref, workspace):
        """Internal arrival primitive for future adapters; never renews authority."""
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None:
                raise ValueError('Closeout does not belong to this workspace')
            value.update(generation=value['generation'] + 1, status='PENDING',
                         lease_owner=None, lease_until=None, updated_at=self.now())
            self._save(db, value)
            return value

    def dispatch(self, ref, workspace, *, maximum=2):
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None or value['stop_dispatches'] >= maximum:
                return False
            value['stop_dispatches'] += 1
            self._save(db, value)
            return True

    def latest(self, workspace, session=None):
        no_links(self.path)
        if not self.path.exists():
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='closeouts'").fetchone():
                return None
            rows = db.execute('SELECT data, mac FROM closeouts WHERE workspace=? ORDER BY rowid DESC LIMIT ?',
                              (workspace, MAX_RECORDS)).fetchall()
        for row in rows:
            value = self._decode(row, workspace)
            if session is None or value.get('details', {}).get('session_key') == session:
                return value
        return None

    def incomplete_persistence(self, ref, workspace, generation, *, reason='CLOSURE_PERSISTENCE_INCOMPLETE'):
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is not None and value['generation'] == generation and value['status'] in {'COMPLETED', 'NEEDS_RETRY'}:
                value.update(status='NEEDS_RETRY', reason=reason)
                if value.get('receipt'):
                    value['receipt'].update(check_completed=False, risk_fix_complete=False, current_version=False,
                                            credential_closure_complete=False,
                                            persistence_status='INCOMPLETE')
                self._save(db, value)
            return value

    def revise(self, ref, workspace, scope, revision, plan, details):
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None:
                raise ValueError('Closeout does not belong to this workspace')
            # Duplicate Stop/prepare without a new arrival is idempotent.
            if (value['scope_files'] == list(scope) and value['prepared_revision'] == revision and
                    value['plan_fingerprint'] == plan and value['details'] == details):
                return value
            value.update(scope_files=list(scope), prepared_revision=revision, plan_fingerprint=plan,
                         details=details, generation=value['generation'] + 1, status='PENDING',
                         lease_owner=None, lease_until=None, receipt=None, updated_at=self.now())
            self._save(db, value)
            return value

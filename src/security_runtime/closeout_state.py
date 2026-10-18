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
        db.execute('CREATE TABLE IF NOT EXISTS closeout_effect_outbox '
                   '(id TEXT PRIMARY KEY, ref TEXT NOT NULL, workspace TEXT NOT NULL, '
                   'state TEXT NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS closeout_pending ON closeout_effect_outbox(workspace,ref,state)')
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
               receipt=None, scan_id=None, persistence=None):
        if status not in {'COMPLETED', 'NEEDS_RETRY'}:
            raise ValueError('Invalid closeout transition')
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is None:
                raise ValueError('Closeout does not belong to this workspace')
            # An old runner cannot clear a newer arrival or another lease.
            if value['generation'] != generation or value['lease_owner'] != owner:
                return value, False
            if persistence is not None:
                from .closeout_persistence import validate_effect, pending_receipt, MAX_EFFECTS, MAX_PENDING, CONTRACT
                validate_effect(persistence)
                if (persistence['closeout_ref'] != ref or persistence['workspace_id'] != workspace
                        or persistence['generation'] != generation or persistence['receipt'] != receipt
                        or persistence['status'] != status or persistence['coverage'] != coverage
                        or persistence['pending_receipt_sha256'] != digest(self.key_reader(), pending_receipt(persistence))):
                    raise ValueError('Closeout source binding cannot be verified')
                if (db.execute('SELECT count(*) FROM closeout_effect_outbox').fetchone()[0] >= MAX_EFFECTS
                        or db.execute("SELECT count(*) FROM closeout_effect_outbox WHERE state='PENDING'").fetchone()[0] >= MAX_PENDING):
                    raise ValueError('Closeout persistence capacity exceeded')
                source = dict(contract=CONTRACT, event=persistence, state='PENDING', acknowledgement=None)
                self._save_effect(db, source)
                status, reason, receipt = 'NEEDS_RETRY', 'CLOSURE_PERSISTENCE_INCOMPLETE', pending_receipt(persistence)
            value.update(status=status, coverage=coverage, reason=reason, receipt=receipt,
                         lease_owner=None, lease_until=None, updated_at=self.now())
            if scan_id is not None:
                value['scan_ids'] = (value['scan_ids'] + [scan_id])[-20:]
            self._save(db, value)
            return value, True

    def _save_effect(self, db, source):
        from .closeout_persistence import MAX_EFFECT_BYTES
        raw = encode(source)
        if len(raw) > MAX_EFFECT_BYTES:
            raise ValueError('Closeout persistence capacity exceeded')
        event = source['event']
        db.execute('INSERT OR REPLACE INTO closeout_effect_outbox VALUES(?,?,?,?,?,?)',
            (event['event_id'], event['closeout_ref'], event['workspace_id'], source['state'],
             raw.decode(), digest(self.key_reader(), source)))

    def _decode_effect(self, row, workspace, ref):
        from .closeout_persistence import validate_effect, CONTRACT, MAX_EFFECT_BYTES
        if row is None:
            return None
        event_id, state, raw, mac = row
        if len(raw.encode()) > MAX_EFFECT_BYTES:
            raise ValueError('Closeout persistence cannot be verified')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('contract') != CONTRACT or value.get('state') != state
                or state not in {'PENDING', 'APPLIED', 'SUPERSEDED'}
                or not hmac.compare_digest(mac, digest(self.key_reader(), value))):
            raise ValueError('Closeout persistence cannot be verified')
        event = value['event']
        validate_effect(event)
        if event['event_id'] != event_id or event['workspace_id'] != workspace or event['closeout_ref'] != ref:
            raise ValueError('Closeout persistence source changed')
        return value

    def pending_effects(self, ref, workspace, *, limit=8):
        """Read-only, authenticated obligations; no schema/key/repair creation."""
        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError('Invalid closeout recovery limit')
        if not isinstance(ref, str) or REF.fullmatch(ref) is None:
            raise ValueError('Invalid closeout reference')
        no_links(self.path)
        if not self.path.is_file():
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='closeout_effect_outbox'").fetchone():
                return []
            rows = db.execute("SELECT id,state,data,mac FROM closeout_effect_outbox "
                "WHERE workspace=? AND ref=? AND state='PENDING' ORDER BY rowid LIMIT ?",
                (workspace, ref, limit)).fetchall()
        return [self._decode_effect(row, workspace, ref)['event'] for row in rows]

    def acknowledge_effect(self, effect, *, outcome):
        """ACK a target, updating only the exact pending source receipt."""
        from .closeout_persistence import validate_effect, source_matches, FLAGS
        validate_effect(effect)
        if outcome not in {'APPLIED', 'SUPERSEDED'}:
            raise ValueError('Invalid closeout acknowledgement')
        with closing(self._write()) as db, db:
            row = db.execute('SELECT id,state,data,mac FROM closeout_effect_outbox WHERE id=?',
                (effect['event_id'],)).fetchone()
            source = self._decode_effect(row, effect['workspace_id'], effect['closeout_ref'])
            if source is None or source['event'] != effect:
                raise ValueError('Closeout persistence source changed')
            value = self._row(db, effect['closeout_ref'], effect['workspace_id'])
            if source['state'] != 'PENDING':
                return value, False
            accepted = source_matches(self, value, effect)
            terminal = outcome if accepted else 'SUPERSEDED'
            if accepted:
                if terminal == 'APPLIED':
                    receipt = dict(effect['receipt'], persistence_status='APPLIED',
                        persistence_sync=dict(state='APPLIED'), persistence_effect_id=effect['event_id'])
                    value.update(status=effect['status'], coverage=effect['coverage'], reason=effect['reason'],
                        receipt=receipt, updated_at=self.now())
                else:
                    value.update(status='NEEDS_RETRY', reason='SOURCE_OR_EVENT_CHANGED', updated_at=self.now())
                    value['receipt'].update({name: False for name in FLAGS})
                    value['receipt'].update(persistence_status='SUPERSEDED', persistence_sync=dict(state='SUPERSEDED'))
                self._save(db, value)
            source.update(state=terminal, acknowledgement=dict(outcome=terminal, source_accepted=accepted))
            self._save_effect(db, source)
            return value, accepted

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

    def incomplete_persistence(self, ref, workspace, generation, *, reason='CLOSURE_PERSISTENCE_INCOMPLETE',
                               expected_receipt_hash=None):
        with closing(self._write()) as db, db:
            value = self._row(db, ref, workspace)
            if value is not None and value['generation'] == generation and value['status'] in {'COMPLETED', 'NEEDS_RETRY'}:
                if (expected_receipt_hash is not None and
                        digest(self.key_reader(), value.get('receipt')) != expected_receipt_hash):
                    return value
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

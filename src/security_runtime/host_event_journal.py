"""Private, bounded event claims. A claim is never edit or repair authority.

Only a real invocation binding enables exact-call deduplication. An expired
dispatched claim stays uncertain: elapsed time is not proof that execution did
not occur. No payload, original session value, source or authorization is saved.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .closeout_state import readonly_uri
from .hook_state import identity, no_links

CONTRACT = 'host-event-journal-v1'
EVENT_REF = re.compile(r'hev1-[a-f0-9]{64}')
MAX_ROWS = 4096
RETENTION_SECONDS = 24 * 3600
LEASE_SECONDS = 300


class JournalError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


class _SignedRows:
    """Small shared persistence primitive for event and delivery facts only."""
    def __init__(self, hooks, root, filename, table, *, now=time.time, max_rows=MAX_ROWS,
                 retention_seconds=RETENTION_SECONDS):
        if (filename, table) not in {('host-events.db', 'host_events'),
                                    ('task-deliveries.db', 'task_deliveries')}:
            raise JournalError('Invalid journal namespace')
        if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
            raise JournalError('Invalid journal capacity')
        if type(retention_seconds) not in (int, float) or not math.isfinite(retention_seconds) or retention_seconds < 0:
            raise JournalError('Invalid journal retention')
        self.root, self.hooks, self.now = Path(root), hooks, now
        if not self.root.is_absolute():
            raise JournalError('Absolute journal workspace required')
        no_links(self.root)
        self.workspace = identity(os.path.normcase(str(self.root)))
        self.path = hooks.workspace_directory(self.root) / filename
        self.table, self.max_rows, self.retention_seconds = table, max_rows, retention_seconds

    def _key(self, *, write=False):
        if write:
            return self.hooks.key(self.root)
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        value = path.read_bytes()
        if len(value) != 32:
            raise JournalError('Journal key cannot be verified')
        return value

    def _decode(self, row, key, *, entry_ref):
        if row is None:
            return None
        raw, signature = row
        if not isinstance(raw, str) or len(raw.encode()) > 16_000:
            raise JournalError('Journal record budget exceeded')
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError):
            raise JournalError('Journal record cannot be verified') from None
        if (not isinstance(value, dict) or value.get('workspace') != self.workspace
                or value.get('ref') != entry_ref or not valid_digest(signature)
                or not hmac.compare_digest(signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest())
                or type(value.get('revision')) is not int or value['revision'] < 1
                or any(type(value.get(name)) not in (int, float) or not math.isfinite(value[name])
                       or value[name] < 0 for name in ('created_at', 'updated_at'))):
            raise JournalError('Journal record cannot be verified')
        return value

    def _get(self, db, entry_ref, key):
        return self._decode(db.execute(f'SELECT data,mac FROM {self.table} WHERE ref=?', (entry_ref,)).fetchone(),
                            key, entry_ref=entry_ref)

    def _all(self, db, key):
        return [self._decode((raw, mac), key, entry_ref=reference) for reference, raw, mac in
                db.execute(f'SELECT ref,data,mac FROM {self.table}').fetchall()]

    def _put(self, db, entry_ref, value, key, *, new=False):
        if new and db.execute(f'SELECT count(*) FROM {self.table}').fetchone()[0] >= self.max_rows:
            # Only verified terminal rows expire. Pending/uncertain obligations
            # cannot be dropped to admit new work.
            for old in self._all(db, key):
                self._validate(old)
                if self._collectible(old) and self.now()-old['updated_at'] > self.retention_seconds:
                    db.execute(f'DELETE FROM {self.table} WHERE ref=?', (old['ref'],))
            if db.execute(f'SELECT count(*) FROM {self.table}').fetchone()[0] >= self.max_rows:
                raise JournalError('Journal capacity unavailable; pending records retained')
        value = dict(value, revision=value.get('revision', 0)+1, updated_at=self.now())
        raw = encode(value)
        if len(raw) > 16_000:
            raise JournalError('Journal record budget exceeded')
        signature = hmac.new(key, raw, hashlib.sha256).hexdigest()
        db.execute(f'INSERT OR REPLACE INTO {self.table}(ref,data,mac) VALUES(?,?,?)',
                   (entry_ref, raw.decode(), signature))
        return value

    @staticmethod
    def _collectible(value):
        return value['state'] in {'COMPLETED', 'REPORTED', 'SUPERSEDED'}

    @contextmanager
    def _transaction(self):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = self._key(write=True)
        with closing(sqlite3.connect(self.path, timeout=.25)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            db.execute(f'CREATE TABLE IF NOT EXISTS {self.table}(ref TEXT PRIMARY KEY,data TEXT NOT NULL,mac TEXT NOT NULL)')
            yield db, key

    def _read(self, entry_ref):
        no_links(self.path)
        if not self.path.is_file():
            return None
        key = self._key()
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True, timeout=.25)) as db:
            db.execute('PRAGMA query_only=ON')
            return self._get(db, entry_ref, key)


@dataclass(frozen=True)
class EventClaim:
    event_ref: str | None
    state: str
    fence: int = 0
    token: str | None = field(default=None, repr=False)
    task_ref: str | None = None

    def facts(self):
        return dict(contract=CONTRACT, event_ref=self.event_ref, state=self.state,
                    exact_call_deduplication=self.event_ref is not None, task_ref=self.task_ref)


class HostEventJournal(_SignedRows):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'host-events.db', 'host_events', **kwargs)

    @staticmethod
    def _collectible(value):
        return (value['state'] == 'COMPLETED'
                and (value['task_target'] is None or value['task_link'] is not None))

    @staticmethod
    def applicable(event):
        from .host_events import EventKind, OperationClass
        return (event.kind == EventKind.WORKSPACE_ACTIVITY and event.operation != OperationClass.READ_ONLY
                and event.context.capabilities.supports_invocation_id
                and event.context.invocation_binding is not None)

    def _validate(self, record):
        from .host_events import EventKind, OperationClass
        from .host_lifecycle import HOSTS
        if (record is not None and (record.get('contract') != CONTRACT
                or not isinstance(record.get('ref'), str) or not EVENT_REF.fullmatch(record['ref'])
                or record.get('state') not in {'CLAIMED', 'DISPATCHED', 'COMPLETED', 'UNCERTAIN'}
                or record.get('host') not in HOSTS or record.get('phase') != EventKind.WORKSPACE_ACTIVITY.value
                or record.get('operation') not in {item.value for item in OperationClass if item != OperationClass.READ_ONLY}
                or type(record.get('fence')) is not int or record['fence'] < 1
                or not valid_digest(record.get('token_hash'))
                or not valid_digest(record.get('session')) or not valid_digest(record.get('invocation'))
                or record.get('task_target') is not None and (not isinstance(record['task_target'], str)
                    or not re.fullmatch(r'ts1-[a-f0-9]{32}', record['task_target']))
                or type(record.get('lease_until')) not in (int, float)
                or not math.isfinite(record['lease_until']))):
            raise JournalError('Invalid event journal contract')
        return record

    @staticmethod
    def _claim_valid(claim):
        return (isinstance(claim, EventClaim) and isinstance(claim.event_ref, str)
                and EVENT_REF.fullmatch(claim.event_ref) is not None
                and type(claim.fence) is int and claim.fence > 0
                and isinstance(claim.token, str) and re.fullmatch(r'[a-f0-9]{32}', claim.token) is not None)

    def claim(self, event, *, lease_seconds=LEASE_SECONDS, task_ref=None):
        event.__post_init__()
        event.context.__post_init__()
        if not self.applicable(event):
            return EventClaim(None, 'CONTENT_RECONCILIATION_ONLY')
        if event.context.workspace_identity != self.workspace:
            raise JournalError('Event workspace mismatch')
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 3600:
            raise JournalError('Invalid event lease')
        if task_ref is not None and (not isinstance(task_ref, str) or not re.fullmatch(r'ts1-[a-f0-9]{32}', task_ref)):
            raise JournalError('Invalid event task target')
        context = event.context
        binding = dict(workspace=self.workspace, host=context.host, session=context.session_binding,
                       invocation=context.invocation_binding, phase=event.kind.value)
        event_ref = 'hev1-'+digest(binding)
        with self._transaction() as (db, key):
            old = self._validate(self._get(db, event_ref, key))
            if old:
                if old['operation'] != event.operation.value:
                    return EventClaim(event_ref, 'BINDING_CONFLICT', task_ref=old['task_target'])
                if old['state'] == 'COMPLETED':
                    return EventClaim(event_ref, 'ALREADY_COMPLETED', task_ref=old['task_target'])
                if old['state'] == 'UNCERTAIN':
                    return EventClaim(event_ref, 'EXECUTION_UNCONFIRMED', task_ref=old['task_target'])
                if old['lease_until'] > self.now():
                    return EventClaim(event_ref, 'IN_PROGRESS', task_ref=old['task_target'])
                if old['state'] == 'DISPATCHED':
                    self._put(db, event_ref, dict(old, state='UNCERTAIN'), key)
                    return EventClaim(event_ref, 'EXECUTION_UNCONFIRMED', task_ref=old['task_target'])
            token = uuid.uuid4().hex
            value = dict(binding, contract=CONTRACT, ref=event_ref, operation=event.operation.value,
                         state='CLAIMED', fence=old['fence']+1 if old else 1,
                         token_hash=identity(token), lease_until=self.now()+lease_seconds,
                         created_at=old['created_at'] if old else self.now(),
                         revision=old['revision'] if old else 0, task_link=None, outcome=None,
                         task_target=old['task_target'] if old else task_ref)
            value = self._put(db, event_ref, value, key, new=old is None)
            return EventClaim(event_ref, 'CLAIMED', value['fence'], token, value['task_target'])

    def _owned(self, record, claim, *, states):
        return bool(record and claim.token is not None and record['state'] in states
                    and record['fence'] == claim.fence and hmac.compare_digest(record['token_hash'], identity(claim.token))
                    and record['lease_until'] > self.now())

    def start(self, claim):
        if not self._claim_valid(claim):
            return False
        with self._transaction() as (db, key):
            record = self._validate(self._get(db, claim.event_ref, key))
            if not self._owned(record, claim, states={'CLAIMED'}):
                return False
            self._put(db, claim.event_ref, dict(record, state='DISPATCHED'), key)
            return True

    def renew(self, claim, *, lease_seconds=LEASE_SECONDS):
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 3600:
            raise JournalError('Invalid event lease')
        if not self._claim_valid(claim):
            return False
        with self._transaction() as (db, key):
            record = self._validate(self._get(db, claim.event_ref, key))
            if not self._owned(record, claim, states={'CLAIMED', 'DISPATCHED'}):
                return False
            self._put(db, claim.event_ref, dict(record, lease_until=self.now()+lease_seconds), key)
            return True

    def complete(self, claim, result):
        if not self._claim_valid(claim):
            return False
        scan = result.get('scan_id')
        scan = scan if isinstance(scan, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,180}', scan) else None
        outcome = dict(scan_id=scan, scanner_run=result.get('execution', {}).get('scanner_run') is True)
        with self._transaction() as (db, key):
            record = self._validate(self._get(db, claim.event_ref, key))
            if not self._owned(record, claim, states={'DISPATCHED'}):
                return False
            self._put(db, claim.event_ref, dict(record, state='COMPLETED', outcome=outcome), key)
            return True

    def uncertain(self, claim):
        if not self._claim_valid(claim):
            return False
        with self._transaction() as (db, key):
            record = self._validate(self._get(db, claim.event_ref, key))
            if not self._owned(record, claim, states={'DISPATCHED'}):
                return False
            self._put(db, claim.event_ref, dict(record, state='UNCERTAIN'), key)
            return True

    def get(self, event_ref, owner):
        if not isinstance(event_ref, str) or not EVENT_REF.fullmatch(event_ref):
            raise JournalError('Invalid event reference')
        record = self._validate(self._read(event_ref))
        if record and owner != dict(host=record['host'], session=record['session']):
            raise JournalError('Event owner mismatch')
        # The fencing capability stays private even for internal readers.
        return ({key: record[key] for key in ('contract', 'ref', 'state', 'task_link', 'outcome', 'task_target')}
                if record else None)

    def ack_task(self, event_ref, owner, task_ref, *, recording='RECORDED'):
        if (not isinstance(event_ref, str) or not EVENT_REF.fullmatch(event_ref)
                or not isinstance(task_ref, str) or not re.fullmatch(r'ts1-[a-f0-9]{32}', task_ref)
                or recording not in {'RECORDED', 'FAILURE_MARKER_RECORDED', 'NO_MUTATION'}):
            raise JournalError('Invalid event task acknowledgement')
        with self._transaction() as (db, key):
            record = self._validate(self._get(db, event_ref, key))
            if not record or owner != dict(host=record['host'], session=record['session']):
                raise JournalError('Event owner mismatch')
            if record['state'] not in {'COMPLETED', 'UNCERTAIN'}:
                raise JournalError('Event has not completed or become uncertain')
            if record['task_target'] is not None and record['task_target'] != task_ref:
                raise JournalError('Event task target mismatch')
            link = dict(task_ref=task_ref, recording=recording)
            if record['task_link'] is not None:
                if record['task_link'] != link:
                    raise JournalError('Event task acknowledgement changed')
                return False
            self._put(db, event_ref, dict(record, task_link=link), key)
            return True

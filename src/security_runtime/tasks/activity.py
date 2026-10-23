"""Small signed lifecycle/activity records. Hints are not source or scan proof.

No source reads, baseline creation, scanner calls or task adoption occur here.
SQLite transactions serialize routing and arrival watermarks across processes.
"""
from contextlib import contextmanager, closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from ..closeout_state import digest, encode, readonly_uri
from ..hook_state import no_links
from .ownership import valid_owner

POLICY = 'TASK_CLOSEOUT_V1'
LEGACY = 'PER_EDIT_V1'
IDLE_TTL = 7 * 86400
HARD_TTL = 30 * 86400
MAX_ROWS = 256
MAX_PATHS = 1000


def deferred(record):
    return bool(record and record.get('check_policy') == POLICY)


class ActivityStore:
    def __init__(self, hooks, root, *, now=time.time):
        self.hooks, self.root, self.now = hooks, Path(root), now
        self.path = hooks.workspace_directory(self.root) / 'task-activity.db'

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Activity key unavailable')
        return key

    def _paths(self):
        for path in (self.path, *(Path(str(self.path)+s) for s in ('-journal', '-wal', '-shm'))):
            no_links(path)
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64_000_000:
                raise ValueError('Activity state path unavailable')

    @contextmanager
    def transaction(self):
        self._paths()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._paths()
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS activity (key TEXT PRIMARY KEY, data TEXT NOT NULL, mac TEXT NOT NULL)')
            yield db

    def _get(self, db, key):
        row = db.execute('SELECT CASE WHEN length(CAST(data AS BLOB))<=160000 THEN data END,'
                         'CASE WHEN length(mac)=64 THEN mac END FROM activity WHERE key=?', (key,)).fetchone()
        if not row:
            return None
        if not isinstance(row[0], str) or not isinstance(row[1], str):
            raise ValueError('Activity record budget exceeded')
        value = json.loads(row[0])
        if (not isinstance(value, dict) or value.get('key') != key or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(row[1], digest(self._key(), value))):
            raise ValueError('Activity record cannot be verified')
        return value

    def _put(self, db, key, value):
        value = dict(value, key=key, workspace=str(self.root))
        raw = encode(value)
        if len(raw) > 160000:
            raise ValueError('Activity record budget exceeded')
        if not self._get(db, key) and db.execute('SELECT count(*) FROM activity').fetchone()[0] >= MAX_ROWS:
            # Pending state must not be evicted to make a new task look clean.
            raise ValueError('Activity capacity unavailable')
        db.execute('INSERT OR REPLACE INTO activity VALUES(?,?,?)',
                   (key, raw.decode(), digest(self._key(), value)))
        return value

    def read(self, key):
        self._paths()
        if not self.path.exists():
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            return self._get(db, key)

    @staticmethod
    def owner_key(owner):
        if not valid_owner(owner):
            raise ValueError('Activity owner unavailable')
        return 'focus:' + hashlib.sha256(encode(owner)).hexdigest()

    def focus(self, owner):
        return self.read(self.owner_key(owner))

    def activate(self, owner, task_ref, *, expected_generation, created_at, policy=POLICY):
        if policy not in {POLICY, LEGACY}:
            raise ValueError('Unsupported routing policy')
        key = self.owner_key(owner)
        with self.transaction() as db:
            previous = self._get(db, key)
            generation = previous['generation'] if previous else 0
            if generation != expected_generation:
                raise ValueError('Task routing changed; retain original task references')
            return self._put(db, key, dict(owner=owner, task_ref=task_ref,
                generation=generation+1, created_at=created_at, policy=policy))

    def touch(self, ref, timestamp, phase):
        with self.transaction() as db:
            key = 'task:'+ref
            row = self._get(db, key) or dict(seq=0, paths=[], scope_unknown=False, events=[])
            self._put(db, key, dict(row, phase=phase,
                                   last_activity=max(timestamp, row.get('last_activity', 0))))

    def summary(self, ref):
        return self.read('task:'+ref) or dict(seq=0, paths=[], scope_unknown=False,
                                             events=[], last_activity=0)

    def record(self, owner, *, event_id=None, paths=(), scope_unknown=True):
        from ..local_evidence import _relative
        key = self.owner_key(owner)
        with self.transaction() as db:
            focus = self._get(db, key)
            if not focus:
                raise ValueError('Task routing unavailable')
            if focus.get('policy') != POLICY:
                return None  # Switched to a legacy/native repair route meanwhile.
            ref = focus.get('task_ref')
            # A replay keeps its original route even after an explicit switch.
            replay_key = 'replay:'+key
            replay = self._get(db, replay_key) or dict(events=[])
            if event_id:
                previous = next((v for v in replay['events'] if v['id'] == event_id), None)
                if previous:
                    return dict(previous, duplicate=True)
            target = 'task:'+ref if ref else 'unassigned:'+key
            value = self._get(db, target) or dict(seq=0, paths=[], scope_unknown=False, events=[])
            if value.get('phase') in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}:
                ref = None
                target = 'unassigned:'+key
                value = self._get(db, target) or dict(seq=0, paths=[], scope_unknown=False, events=[])
            if ref and self.now() > min(focus['created_at']+HARD_TTL,
                    max(focus['created_at'], value.get('last_activity', 0))+IDLE_TTL):
                raise ValueError('Original task activity expired; never rebuild its baseline')
            if event_id and event_id in value['events']:
                return dict(value, task_ref=ref, duplicate=True)
            selected = set(value['paths'])
            path_bytes = sum(len(p.encode()) for p in selected)
            unknown = bool(value['scope_unknown'] or scope_unknown)
            for name in paths:
                try:
                    name = _relative(name)
                except ValueError:
                    unknown = True
                    continue
                if name in selected:
                    continue
                if len(selected) >= MAX_PATHS or path_bytes+len(name.encode()) > 64000:
                    unknown = True
                    break
                selected.add(name)
                path_bytes += len(name.encode())
            # A bounded replay window is an optimization, never content proof.
            events = ([*value['events'], event_id][-256:] if event_id else value['events'])
            result = self._put(db, target, dict(seq=value['seq']+1, paths=sorted(selected),
                scope_unknown=unknown, events=events, last_activity=self.now(),
                routing_generation=focus['generation'], task_ref=ref, phase=value.get('phase')))
            if event_id:
                self._put(db, replay_key, dict(events=[*replay['events'],
                    dict(id=event_id, task_ref=ref, seq=result['seq'])][-256:]))
            return result

    def queue(self, ref, revision):
        key = 'queue:'+ref
        with self.transaction() as db:
            old = self._get(db, key)
            if old and old['revision'] == revision:
                return old
            return self._put(db, key, dict(task_ref=ref, revision=revision,
                state='QUEUED', queued_at=self.now()))

    def complete_queue(self, ref, revision):
        key = 'queue:'+ref
        with self.transaction() as db:
            value = self._get(db, key)
            if value and value['revision'] == revision:
                self._put(db, key, dict(value, state='COMPLETED'))


def lightweight_focus(hooks, root, owner):
    """A signed new-policy route, not the most recently active foreign task."""
    if not valid_owner(owner):
        return None
    focus = ActivityStore(hooks, root).focus(owner)
    return focus if focus and focus.get('policy') == POLICY else None


def record_event(event, hooks):
    context = event.context
    store = ActivityStore(hooks, context.workspace)
    owner = dict(host=context.host, session=context.session_binding)
    row = store.record(owner, event_id=context.invocation_binding,
                       paths=event.candidate_paths, scope_unknown=event.scope_unknown)
    if row is None:
        return None
    from ..host_event_runtime import inconclusive
    result = inconclusive('TASK_CLOSEOUT_PENDING')
    result.update(status='RECORDED_PENDING', security_task_ref=row['task_ref'],
        task_edit_check_policy=POLICY, activity_seq=row['seq'],
        workspace_mutation_observed=None, changed_file_count=None,
        scanner_skipped_reason='DEFERRED_TO_TASK_CLOSEOUT', duration_ms=0,
        next_step='Continue development; finish the original task before the development summary.')
    return {**result, **event.diagnostics()}

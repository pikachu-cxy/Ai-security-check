"""Observed-file development checks, without a before-edit workspace baseline.

The journal contains bounded routing and path hints only. Source bytes belong
to the scanner's existing immutable input lifetime, never to this journal.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

from .hook_state import no_links
from .scan_request import relative_path
from .tasks.durable import SignedRecords
from .tasks.ownership import ownership_error, valid_owner

CONTRACT = 'observed-development-check-v1'
REF = re.compile(r'dc1-[a-f0-9]{32}')
MAX_PATHS = 1000
MAX_PATH_BYTES = 64_000
MAX_EVENTS = 256
RETENTION_SECONDS = 7 * 86400
MAX_FINISH_WAIT_SECONDS = 25
TERMINAL = frozenset({'RESULTS_READY', 'PARTIAL', 'NO_OBSERVED_CHANGES', 'FAILED'})


def workspace_root(value):
    root = Path(value).absolute()
    no_links(root)
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('DEVELOPMENT_WORKSPACE_UNAVAILABLE')
    return root


def root_identity(root):
    no_links(root)
    info = Path(root).stat()
    return [info.st_dev, info.st_ino]


def owner_key(owner):
    if not valid_owner(owner):
        raise ValueError('DEVELOPMENT_OWNER_REQUIRED')
    return hashlib.sha256(json.dumps(owner, sort_keys=True).encode()).hexdigest()


def clean_paths(values, *, tolerant=False):
    if not isinstance(values, (list, tuple)) or len(values) > MAX_PATHS:
        if not tolerant:
            raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID')
        values, unknown = list(values[:MAX_PATHS]) if isinstance(values, (list, tuple)) else [], True
    else:
        unknown = False
    names, seen, size = [], set(), 0
    for name in values:
        try:
            name = relative_path(name)
            if any(char in name for char in '*?[]'):
                raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID')
            folded = os.path.normcase(name)
            if folded in seen:
                continue
            if size + len(name.encode()) > MAX_PATH_BYTES:
                raise ValueError('DEVELOPMENT_PATH_BUDGET')
        except ValueError:
            if not tolerant:
                raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID') from None
            unknown = True
            continue
        names.append(name)
        seen.add(folded)
        size += len(name.encode())
    return sorted(names), unknown


class DevelopmentCheckStore(SignedRecords):
    max_rows = 1024
    max_record_bytes = 120_000

    def __init__(self, hooks, root, *, now=time.time):
        super().__init__(hooks, workspace_root(root), 'development-checks.db', now=now)

    def load(self, ref, owner=None):
        if not isinstance(ref, str) or not REF.fullmatch(ref):
            raise ValueError('DEVELOPMENT_CHECK_REFERENCE_INVALID')
        row = self.read(ref)
        if row is None or row.get('contract') != CONTRACT or row.get('kind') != 'check':
            raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
        if row.get('root_identity') != root_identity(self.root):
            raise ValueError('DEVELOPMENT_WORKSPACE_REPLACED')
        if owner is not None and row.get('owner') != owner:
            raise ownership_error(row.get('owner'), owner)
        return row

    def fresh(self, ref, owner, scan_path):
        now = self.now()
        return dict(kind='check', contract=CONTRACT, check_ref=ref, owner=dict(owner),
            root_identity=root_identity(self.root), scan_path=str(Path(scan_path).absolute()),
            created_at=now, updated_at=now, last_event_at=now, dirty_seq=0,
            scanned_seq=0, attempted_seq=0, observed_paths=[], scope_unknown=False,
            events=[], state='OPEN', finish_requested=False, scan_id=None,
            result=None, reason_code=None, worker_ticket=None, automatic=False)

    def prune(self, db):
        """Retire old inactive metadata only; persisted scan/risk records remain."""
        rows = self._all(db)
        focused = {r['check_ref'] for r in rows if r.get('kind') == 'focus'}
        removed = {r['check_ref'] for r in rows if r.get('kind') == 'check'
            and r['state'] in TERMINAL and r['finish_requested']
            and r['check_ref'] not in focused and r['updated_at'] < self.now()-RETENTION_SECONDS}
        for row in rows:
            if row['key'] in removed or row.get('kind') == 'alias' and row['check_ref'] in removed:
                db.execute('DELETE FROM records WHERE key=?', (row['key'],))
            elif row.get('kind') == 'replay':
                events = [event for event in row['events'] if event['check_ref'] not in removed]
                if events != row['events']:
                    self._put(db, row['key'], dict(row, events=events))

    def append(self, db, row, paths, unknown, event_id):
        if event_id is not None:
            if not isinstance(event_id, str) or not 1 <= len(event_id) <= 256:
                raise ValueError('DEVELOPMENT_EVENT_INVALID')
            # Persist only an opaque digest, never arbitrary tool/user content.
            event_id = hashlib.sha256(event_id.encode()).hexdigest()
            if event_id in row['events']:
                return row, False
        selected, overflow = clean_paths(list(dict.fromkeys([*row['observed_paths'], *paths])), tolerant=True)
        row = dict(row, observed_paths=selected,
            scope_unknown=bool(row['scope_unknown'] or unknown or overflow),
            dirty_seq=row['dirty_seq']+1, updated_at=self.now(), last_event_at=self.now(),
            events=([*row['events'], event_id][-MAX_EVENTS:] if event_id else row['events']),
            state='DIRTY', reason_code=None, finish_requested=False)
        return self._put(db, row['check_ref'], row), True


def legacy_guard(hooks, root, owner, *, now=time.time):
    """Preserve selected native repairs and original v3 tasks without migration."""
    from .native_repair_intent import NativeRepairIntents
    blocked = NativeRepairIntents(hooks, root, owner, now=now).guard()
    if blocked is not None:
        return blocked
    from .tasks.activity import ActivityStore
    focus = ActivityStore(hooks, root, now=now).focus(owner)
    if not focus or not focus.get('task_ref'):
        return None
    from .tasks.security_state import TaskSecurityStore
    from .tasks.ownership import record_owner
    record = TaskSecurityStore(hooks, root, now=now).get(focus['task_ref'], headers=True)
    if record and record_owner(record) == owner and record.get('phase') not in {'COMPLETE', 'NO_CHANGES', 'INCOMPLETE'}:
        return dict(status='LEGACY_TASK_ACTIVE', task_ref=record['task_ref'],
            scanner_run=False, baseline_created=False, repair_authorized=False,
            next_action=dict(tool='finish_security_task', arguments=dict(
                task_ref=record['task_ref'], workspace_path=str(root))))
    return None


def projection(store, row):
    state, reason = row['state'], row.get('reason_code')
    if state in {'QUEUED', 'RUNNING'}:
        worker = store.read('$worker')
        if worker and worker.get('lease_until', 0) <= store.now():
            state, reason = 'INTERRUPTED', 'DEVELOPMENT_WORKER_INTERRUPTED'
    result = row.get('result') or {}
    gaps = []
    if row['scope_unknown']:
        gaps.append('UNOBSERVED_PATHS_POSSIBLE')
    if row['dirty_seq'] > row['scanned_seq']:
        gaps.append('OBSERVED_EDITS_PENDING')
    gaps.extend(result.get('gaps', []))
    return dict(contract=CONTRACT, check_ref=row['check_ref'], status=state,
        dirty_seq=row['dirty_seq'], scanned_seq=row['scanned_seq'],
        scan_id=row['scan_id'], result_available=bool(row['scan_id']),
        scope=dict(kind='OBSERVED_FILES', paths=row['observed_paths'],
            scope_unknown=row['scope_unknown'], full_project=False, expanded_to_project=False),
        gaps=list(dict.fromkeys(gaps)), reason_code=reason,
        finish_requested=row['finish_requested'], scanner_run=False,
        baseline_created=False, source_modified=False, repair_authorized=False,
        host_review_completed=False, security_proof=False,
        result_is_saved_version=bool(row['scan_id']), source_freshness='NOT_RECHECKED_ON_READ',
        execution=result.get('execution'), scan_status=result.get('status'),
        scan_coverage=result.get('coverage'),
        next_action=dict(tool='finish_development_check' if state in {'DIRTY', 'INTERRUPTED', 'FAILED'}
            else 'get_development_check', arguments=dict(
            workspace_path=str(store.root), check_ref=row['check_ref'])),
        poll_after_seconds=2 if state in {'QUEUED', 'RUNNING'} else None,
        scope_notice='只检查已观测文件及必要扫描上下文；未建立项目基线，不能判定问题是否由本次编辑引入。')


class DevelopmentCheckService:
    def __init__(self, runtime_provider, hooks, *, owner, scan_path_provider=None,
                 launcher=None, now=time.time, monotonic=time.monotonic, wait_sleep=asyncio.sleep):
        owner_key(owner)
        self.runtime_provider, self.hooks, self.owner = runtime_provider, hooks, dict(owner)
        self.scan_path_provider, self.launcher, self.now = scan_path_provider, launcher, now
        self.monotonic, self.wait_sleep = monotonic, wait_sleep

    def store(self, root):
        return DevelopmentCheckStore(self.hooks, root, now=self.now)

    def scan_path(self):
        from .storage import SQLiteStore
        value = self.scan_path_provider() if callable(self.scan_path_provider) else self.scan_path_provider
        path = Path(value or SQLiteStore.default_path()).absolute()
        no_links(path)
        return path

    def _wake(self, store):
        from .development_check_worker import launch_worker
        try:
            (self.launcher or launch_worker)(self.hooks, store.root)
        except (OSError, ValueError):
            # No arbitrary launcher output enters host context. The path journal
            # stays queued and a later explicit finish can retry it.
            with store.transaction() as db:
                for row in store._all(db):
                    if row.get('kind') == 'check' and row['state'] == 'QUEUED':
                        store._put(db, row['check_ref'], dict(row, reason_code='DEVELOPMENT_WORKER_START_FAILED'))

    def begin(self, root, task_key):
        if not isinstance(task_key, str) or not 1 <= len(task_key) <= 128 or any(ord(c) < 32 for c in task_key):
            raise ValueError('DEVELOPMENT_TASK_KEY_INVALID')
        store = self.store(root)
        blocked = legacy_guard(self.hooks, store.root, self.owner, now=self.now)
        if blocked is not None:
            return blocked
        ref = 'dc1-' + hashlib.sha256((owner_key(self.owner)+'\0'+task_key).encode()).hexdigest()[:32]
        self.hooks.key(store.root)
        with store.transaction() as db:
            store.prune(db)
            alias = store._get(db, 'alias:'+ref)
            row = store._get(db, alias['check_ref'] if alias else ref)
            if row is None:
                focus = store._get(db, 'focus:'+owner_key(self.owner))
                automatic = store._get(db, focus['check_ref']) if focus else None
                if automatic and automatic.get('automatic') and not automatic['finish_requested']:
                    row = store._put(db, automatic['check_ref'], dict(automatic, automatic=False))
                    store._put(db, 'alias:'+ref, dict(kind='alias', check_ref=row['check_ref']))
                else:
                    row = store._put(db, ref, store.fresh(ref, self.owner, self.scan_path()))
            elif row['owner'] != self.owner or row['root_identity'] != root_identity(store.root):
                raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
            if row['owner'] != self.owner or row['root_identity'] != root_identity(store.root):
                raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
            store._put(db, 'focus:'+owner_key(self.owner), dict(kind='focus', owner=self.owner, check_ref=row['check_ref']))
        return projection(store, row)

    def record(self, root, check_ref, paths, *, scope_unknown=False, event_id=None):
        if type(scope_unknown) is not bool:
            raise ValueError('DEVELOPMENT_SCOPE_INVALID')
        names, _ = clean_paths(paths)
        store = self.store(root)
        store.load(check_ref, self.owner)
        with store.transaction() as db:
            row, changed = store.append(db, store._get(db, check_ref), names, scope_unknown, event_id)
        return projection(store, store.load(check_ref, self.owner))

    def finish(self, root, check_ref):
        store = self.store(root)
        store.load(check_ref, self.owner)
        with store.transaction() as db:
            row = store._get(db, check_ref)
            state = row['state']
            worker = store._get(db, '$worker')
            running = worker and worker.get('lease_until', 0) > self.now()
            if row['dirty_seq'] == 0:
                state = 'NO_OBSERVED_CHANGES'
            elif row['dirty_seq'] > row['scanned_seq'] and (state != 'RUNNING' or not running):
                state = 'QUEUED'
            row = store._put(db, check_ref, dict(row, finish_requested=True, state=state, updated_at=self.now()))
        if state in {'QUEUED', 'RUNNING'}:
            self._wake(store)
        return projection(store, store.load(check_ref, self.owner))

    async def finish_and_wait(self, root, check_ref, wait_seconds=0):
        """Dispatch once; optionally await only saved state without holding a lock."""
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= MAX_FINISH_WAIT_SECONDS:
            raise ValueError('DEVELOPMENT_WAIT_INVALID')
        submitted = self.finish(root, check_ref)
        if wait_seconds == 0:
            return submitted
        started = self.monotonic()
        deadline = started + wait_seconds
        expected_seq = submitted['dirty_seq']
        store = self.store(root)
        polls = 0
        while True:
            # load revalidates the original owner and workspace identity. Do
            # not repeatedly deserialize an older static scan while waiting.
            row = store.load(check_ref, self.owner)
            polls += 1
            state = projection(store, row)
            if row['dirty_seq'] != expected_seq or state['status'] not in {'QUEUED', 'RUNNING'}:
                break
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                break
            await self.wait_sleep(min(state['poll_after_seconds'] or 2, remaining))
        # Reuse the normal read boundary and its full scope, gaps, version and
        # finding access, including any edit racing with the last observation.
        result = self.get(root, check_ref)
        reason = ('VERSION_CHANGED' if result['dirty_seq'] != expected_seq else
                  'TIME_BUDGET_EXHAUSTED' if result['status'] in {'QUEUED', 'RUNNING'} else
                  'STATE_AVAILABLE')
        result['closeout_wait'] = dict(contract='bounded-closeout-wait-v1',
            requested_seconds=wait_seconds, elapsed_ms=round((self.monotonic()-started)*1000, 3),
            polls=polls, requested_dirty_seq=expected_seq, stopped_reason=reason,
            scanner_dispatched_by_wait=False, host_review_completed=False)
        return result

    def get(self, root, check_ref):
        store = self.store(root)
        row = store.load(check_ref, self.owner)
        result = projection(store, row)
        if row['scan_id']:
            from .storage import ReadOnlySQLiteStore
            from .mcp_tools.presentation import _agent_result
            no_links(Path(row['scan_path']))
            scan = ReadOnlySQLiteStore(Path(row['scan_path'])).get_scan(row['scan_id'])
            if scan is None or Path(scan['target_profile']['path']).resolve() != store.root:
                result.update(reason_code='DEVELOPMENT_RESULT_UNAVAILABLE', result_available=False)
                result['gaps'].append('SAVED_RESULT_UNAVAILABLE')
            else:
                result['static_result'] = _agent_result(scan, summary=True)
                if 'findings_access' in result['static_result']:
                    result['static_result']['findings_access']['arguments']['workspace_path'] = str(store.root)
        return result


def record_hook(hooks, root, owner, paths=(), *, scope_unknown=True, event_id=None,
                scan_path=None, launcher=None):
    """Record a validated host mutation; never read project source in a hook."""
    owner_key(owner)
    names, invalid = clean_paths(paths, tolerant=True)
    service = DevelopmentCheckService(None, hooks, owner=owner,
        scan_path_provider=scan_path, launcher=launcher)
    store = service.store(root)
    blocked = legacy_guard(hooks, store.root, owner)
    if blocked is not None:
        return blocked
    hooks.key(store.root)
    key = 'focus:'+owner_key(owner)
    with store.transaction() as db:
        digest = None
        replay_key = 'replay:'+owner_key(owner)
        replay = store._get(db, replay_key) or dict(kind='replay', events=[])
        if event_id is not None:
            if not isinstance(event_id, str) or not 1 <= len(event_id) <= 256:
                raise ValueError('DEVELOPMENT_EVENT_INVALID')
            digest = hashlib.sha256(event_id.encode()).hexdigest()
            old = next((event for event in replay['events'] if event['id'] == digest), None)
            if old is not None:
                row = store._get(db, old['check_ref'])
                if row is None or row['owner'] != owner or row['root_identity'] != root_identity(store.root):
                    raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
                return projection(store, row)
        focus = store._get(db, key)
        row = store._get(db, focus['check_ref']) if focus else None
        if row and (row.get('owner') != owner or row.get('root_identity') != root_identity(store.root)):
            raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
        if row is None:
            store.prune(db)
            ref = 'dc1-'+uuid.uuid4().hex
            row = dict(store.fresh(ref, owner, service.scan_path()), automatic=True)
            store._put(db, key, dict(kind='focus', owner=dict(owner), check_ref=ref))
        row, changed = store.append(db, row, names, bool(scope_unknown or invalid), event_id)
        if digest is not None:
            store._put(db, replay_key, dict(kind='replay', events=[*replay['events'],
                dict(id=digest, check_ref=row['check_ref'])][-MAX_EVENTS:]))
    return projection(store, store.load(row['check_ref'], owner))

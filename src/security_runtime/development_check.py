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
from .user_config import analysis_requirements
from .performance_trace import timed, span

CONTRACT = 'observed-development-check-v1'
REF = re.compile(r'dc1-[a-f0-9]{32}')
MAX_EVENTS = 256
RETENTION_SECONDS = 7 * 86400
MAX_FINISH_WAIT_SECONDS = 25
MAX_PRODUCT_WAIT_SECONDS = 120
TERMINAL = frozenset({'RESULTS_READY', 'PARTIAL', 'NO_OBSERVED_CHANGES', 'FAILED'})


def note_activity(row, turn_id=None):
    """One pending editing round, stored with its existing check; no new journal."""
    turn = hashlib.sha256(turn_id.encode()).hexdigest() if turn_id else None
    old = row.get('stop_activity', {})
    if old.get('pending') and (turn is None or old.get('turn') == turn):
        return row
    # Native parallel children may share the owner's session while carrying
    # distinct turn IDs. Preserve each pending turn's original edit boundary;
    # a later read-only turn must never inherit another turn's pending edits.
    previous = list(row.get('stop_activity_previous', ()))
    restored = next((a for a in previous if turn is not None and a.get('turn') == turn), None)
    previous = [a for a in previous if a is not restored and a.get('turn') != old.get('turn')]
    if old.get('pending') and old.get('turn') is not None and old.get('turn') != turn:
        previous.append(old)
    activity = restored or dict(turn=turn, base_seq=row['dirty_seq'], pending=True)
    changed = dict(row, stop_activity=activity)
    if previous or 'stop_activity_previous' in row:
        changed['stop_activity_previous'] = previous[-8:]
    return changed


def product_wait_seconds():
    try:
        seconds = int(os.environ.get('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '20'))
    except ValueError:
        raise ValueError('DEVELOPMENT_WAIT_CONFIGURATION_INVALID') from None
    if not 0 <= seconds <= MAX_PRODUCT_WAIT_SECONDS:
        raise ValueError('DEVELOPMENT_WAIT_CONFIGURATION_INVALID')
    return seconds


def product_total_wait_seconds():
    """Overall communication deadline, not a scanner timeout or cancellation."""
    try:
        seconds = int(os.environ.get('SECURITY_RUNTIME_DEVELOPMENT_TOTAL_WAIT_SECONDS', '300'))
    except ValueError:
        raise ValueError('DEVELOPMENT_WAIT_CONFIGURATION_INVALID') from None
    if not 1 <= seconds <= 3600:
        raise ValueError('DEVELOPMENT_WAIT_CONFIGURATION_INVALID')
    return seconds


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
    if not isinstance(values, (list, tuple)):
        if not tolerant:
            raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID')
        values, unknown = [], True
    else:
        unknown = False
    names, seen = [], set()
    for name in values:
        try:
            name = relative_path(name)
            from .development_scope import excluded_artifact
            if excluded_artifact(name):
                continue
            if any(char in name for char in '*?[]'):
                raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID')
            folded = os.path.normcase(name)
            if folded in seen:
                continue
        except ValueError:
            if not tolerant:
                raise ValueError('DEVELOPMENT_PATH_SELECTION_INVALID') from None
            unknown = True
            continue
        names.append(name)
        seen.add(folded)
    return sorted(names), unknown


class DevelopmentCheckStore(SignedRecords):
    max_rows = None
    max_record_bytes = 0  # No artificial path-list storage ceiling.
    max_total_bytes = 0
    max_database_bytes = 0

    def __init__(self, hooks, root, *, now=time.time):
        super().__init__(hooks, workspace_root(root), 'development-checks.db', now=now)

    def _all(self, db):
        # Fetch in bounded pages; capacity is an admission policy, not a read limit.
        rows, cursor = [], ''
        while True:
            page = db.execute(self._select() + ' WHERE key>? ORDER BY key LIMIT 256', (cursor,)).fetchall()
            if not page:
                return rows
            rows.extend(self._decode(row) for row in page)
            cursor = page[-1][0]

    def _put(self, db, key, value):
        # Never strand existing checks: ancillary completion records can still be added.
        if value.get('kind') == 'check' and self._get(db, key) is None:
            from .user_config import read_config
            config = read_config()
            limits = config['values']['storage']
            count = db.execute('SELECT count(*) FROM records').fetchone()[0]
            if limits['development_record_limit_enabled'] and count >= limits['development_max_records']:
                from .tasks.durable import TaskOperationError
                raise TaskOperationError('TASK_OPERATION_CAPACITY_REQUIRED', observed=count,
                                         limit=limits['development_max_records'])
        return super()._put(db, key, value)

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
        from .user_config import read_config
        from .scan_preferences import snapshot
        config = snapshot()
        now = self.now()
        return dict(effective_config=config, kind='check', contract=CONTRACT, check_ref=ref, owner=dict(owner),
            root_identity=root_identity(self.root), scan_path=str(Path(scan_path).absolute()),
            created_at=now, updated_at=now, last_event_at=now, dirty_seq=0,
            scanned_seq=0, attempted_seq=0, observed_paths=[], scope_unknown=False,
            events=[], state='OPEN', finish_requested=False, scan_id=None,
            result=None, reason_code=None, worker_ticket=None, automatic=False)

    def prune(self, db):
        """Retire old inactive metadata only; persisted scan/risk records remain."""
        rows = self._all(db)
        focused = {r['check_ref'] for r in rows if r.get('kind') == 'focus'}
        undelivered = {r['check_ref'] for r in rows if r.get('kind') == 'delivery'
                       and not r.get('host_report_submitted')}
        removed = {r['check_ref'] for r in rows if r.get('kind') == 'check'
            and not r.get('has_unified_risks')
            and r['state'] in TERMINAL and r['finish_requested']
            and r['check_ref'] not in focused | undelivered
            and r['updated_at'] < self.now()-RETENTION_SECONDS}
        for row in rows:
            if (row['key'] in removed or row.get('kind') in {'alias', 'delivery', 'continuation'}
                    and row['check_ref'] in removed):
                db.execute('DELETE FROM records WHERE key=?', (row['key'],))
            elif row.get('kind') == 'replay':
                events = [event for event in row['events'] if event['check_ref'] not in removed]
                if events != row['events']:
                    self._put(db, row['key'], dict(row, events=events))

    def append(self, db, row, paths, unknown, event_id, *, explicit=True):
        paths, invalid = clean_paths(paths, tolerant=True)
        unknown = unknown or invalid
        if event_id is not None:
            if not isinstance(event_id, str) or not 1 <= len(event_id) <= 256:
                raise ValueError('DEVELOPMENT_EVENT_INVALID')
            # Persist only an opaque digest, never arbitrary tool/user content.
            event_id = hashlib.sha256(event_id.encode()).hexdigest()
            if event_id in row['events']:
                return row, False
        if not paths and not unknown:
            return self._put(db, row['check_ref'], row), False
        if row.get('finish_requested') and row['dirty_seq'] <= row['scanned_seq']:
            from .scan_preferences import snapshot
            # The saved scan/outbox owns the previous batch's scope. Keep it
            # available for review until a real edit starts the next batch.
            # Never reset an in-flight batch: its newer edits still need checking.
            row = dict(row, effective_config=snapshot(), observed_paths=[],
                explicit_paths=[], observed_directories=[], scope_unknown=False,
                scope_capacity_exceeded=False)
        selected, overflow = clean_paths(list(dict.fromkeys([*row['observed_paths'], *paths])), tolerant=True)
        protected = sorted((set(row.get('explicit_paths', [])) | (set(paths) if explicit else set())) & set(selected))
        row = dict(row, observed_paths=selected, explicit_paths=protected,
            scope_unknown=bool(row['scope_unknown'] or unknown or overflow),
            scope_capacity_exceeded=bool(row.get('scope_capacity_exceeded') or overflow),
            dirty_seq=row['dirty_seq']+1, updated_at=self.now(), last_event_at=self.now(),
            events=([*row['events'], event_id][-MAX_EVENTS:] if event_id else row['events']),
            state='DIRTY', reason_code=None, finish_requested=False,
            attempt_count=0, busy_attempts=0, next_attempt_at=0, failed_seq=None,
            failure_diagnostic=None,
            launch_failures=0, launch_retry_at=0)
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
    # Static publication and risk projection live in separate stores. The
    # public ready boundary includes both, without rerunning the scan.
    importing = (row.get('scan_id') and row['scanned_seq'] == row['dirty_seq']
                 and row.get('risk_import_status') == 'PENDING')
    if importing and state in {'RESULTS_READY', 'PARTIAL'}:
        state, reason = 'RUNNING', 'DEVELOPMENT_CANDIDATES_PENDING'
    if (row.get('risk_import_status') == 'UNAVAILABLE' and
            state in {'RESULTS_READY', 'PARTIAL'}):
        state, reason = 'PARTIAL', 'DEVELOPMENT_CANDIDATES_UNAVAILABLE'
    if state in {'QUEUED', 'RUNNING'}:
        worker = store.read('$worker')
        if worker and worker.get('lease_until', 0) <= store.now():
            state, reason = 'INTERRUPTED', 'DEVELOPMENT_WORKER_INTERRUPTED'
    result = row.get('result') or {}
    gaps = []
    if row.get('scope_capacity_exceeded'):
        gaps.append('OBSERVED_PATH_CAPACITY_EXCEEDED')
    if row['observed_paths'] and row['dirty_seq'] > row['scanned_seq']:
        gaps.append('OBSERVED_EDITS_PENDING')
    gaps.extend(result.get('gaps', []))
    if reason == 'DEVELOPMENT_CANDIDATES_UNAVAILABLE':
        gaps.append('RISK_IMPORT_UNAVAILABLE')
    # Older saved rows used observation uncertainty as a completion gate.
    # Project the recorded-file result without rescanning or changing ownership.
    if state == 'PARTIAL' and row['scan_id'] and not gaps:
        state = 'RESULTS_READY'
    observation_notes = list(row.get('file_watch_gaps', []))
    if row['scope_unknown']:
        observation_notes.append('UNOBSERVED_PATHS_POSSIBLE')
    watch = row.get('file_watch') or {}
    if watch.get('status') == 'ACTIVE' and watch.get('lease_until', 0) <= store.now():
        observation_notes.append('FILE_WATCH_INTERRUPTED')
        watch = dict(watch, status='INTERRUPTED')
    pending = state in {'QUEUED', 'RUNNING'}
    deadline = row.get('wait_deadline') if row.get('wait_seq') == row['dirty_seq'] else None
    expired = pending and deadline is not None and store.now() >= deadline
    next_tool = ('finish_development_check' if state == 'DIRTY' else
                 'wait_development_check' if pending and not expired else 'get_development_check')
    return dict(contract=CONTRACT, check_ref=row['check_ref'], status=state,
        wait_deadline=deadline, wait_deadline_exceeded=bool(expired),
        dirty_seq=row['dirty_seq'], scanned_seq=row['scanned_seq'],
        scan_id=row['scan_id'], result_available=bool(row['scan_id']),
        scope=dict(kind='OBSERVED_FILES', paths=row['observed_paths'],
            directory_observations=row.get('observed_directories', []),
            gitignored_paths=row.get('gitignored_paths', []),
            gitignore_filter_note=row.get('gitignore_filter_note'),
            generated_outputs=(result if row['scanned_seq'] == row['dirty_seq'] else {}).get('generated_outputs', dict(
                declared_roots=row.get('generated_output_roots', []), excluded_paths=[],
                protected_paths=[], gaps=[])),
            scope_unknown=bool(row['scope_unknown'] or 'FILE_WATCH_INTERRUPTED' in observation_notes),
            full_project=False, expanded_to_project=False),
        gaps=list(dict.fromkeys(gaps)), observation_notes=list(dict.fromkeys(observation_notes)), reason_code=reason,
        file_watch={name: watch[name] for name in ('contract', 'status', 'scope', 'attribution',
            'started_at', 'ended_at', 'lease_until') if name in watch},
        finish_requested=row['finish_requested'], scanner_run=False,
        baseline_created=False, source_modified=False, repair_authorized=False,
        analysis_requirements=analysis_requirements(row),
        effective_config=row.get('effective_config'),
        host_review_completed=False, security_proof=False,
        result_is_saved_version=bool(row['scan_id']), source_freshness='NOT_RECHECKED_ON_READ',
        execution=result.get('execution'), scan_status=result.get('status'),
        scan_coverage=result.get('coverage'),
        failure_diagnostic=row.get('failure_diagnostic'),
        next_action=dict(tool=next_tool, arguments=dict(
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

    def _prewarm(self, root, row, paths=()):
        # Trusted embeddings with their own launcher retain their own lifecycle.
        if self.launcher is None:
            from .scan_prewarm import start
            start(root, paths, batch=(row['check_ref'], row['scanned_seq']))

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
        finally:
            # Custom launchers belong to tests/trusted embeddings. The normal
            # product owns recovery independently of tool wait cancellation.
            if self.launcher is None:
                from .development_scheduler import supervise
                supervise(self.hooks, store.root)

    def begin(self, root, task_key):
        if not isinstance(task_key, str) or not 1 <= len(task_key) <= 128 or any(ord(c) < 32 for c in task_key):
            raise ValueError('DEVELOPMENT_TASK_KEY_INVALID')
        store = self.store(root)
        blocked = legacy_guard(self.hooks, store.root, self.owner, now=self.now)
        if blocked is not None:
            return blocked
        ref = 'dc1-' + hashlib.sha256((owner_key(self.owner)+'\0'+task_key).encode()).hexdigest()[:32]
        self.hooks.key(store.root)
        previous = store.read('focus:'+owner_key(self.owner))
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
        if previous and previous['check_ref'] != row['check_ref']:
            from .development_file_watch import stop_window
            stop_window(store, previous['check_ref'], self.owner)
        self._prewarm(store.root, row)
        return projection(store, row)

    @timed('check.record')
    def record(self, root, check_ref, paths, *, scope_unknown=False, event_id=None):
        if type(scope_unknown) is not bool:
            raise ValueError('DEVELOPMENT_SCOPE_INVALID')
        names, _ = clean_paths(paths)
        store = self.store(root)
        store.load(check_ref, self.owner)
        with store.transaction() as db:
            row, changed = store.append(db, note_activity(store._get(db, check_ref)), names, scope_unknown, event_id)
        self._prewarm(store.root, row, names)
        return projection(store, store.load(check_ref, self.owner))

    def declare_outputs(self, root, check_ref, directories):
        """Replace this check's output declaration; never run or certify a scan."""
        from .development_scope import output_roots
        store = self.store(root)
        store.load(check_ref, self.owner)
        roots = output_roots(store.root, directories)
        with store.transaction() as db:
            row = store._get(db, check_ref)
            if roots != row.get('generated_output_roots', []):
                row = dict(row, generated_output_roots=roots, dirty_seq=row['dirty_seq']+1,
                    updated_at=self.now(), last_event_at=self.now(), state='DIRTY',
                    finish_requested=False, reason_code=None, failure_diagnostic=None,
                    attempt_count=0, busy_attempts=0, next_attempt_at=0, failed_seq=None,
                    launch_failures=0, launch_retry_at=0)
                store._put(db, check_ref, row)
        return projection(store, store.load(check_ref, self.owner))

    @timed('check.finish')
    def finish(self, root, check_ref):
        new_submission = False
        total_budget = product_total_wait_seconds()
        store = self.store(root)
        store.load(check_ref, self.owner)
        from .development_file_watch import stop_window
        with span('check.watch_drain'):
            stop_window(store, check_ref, self.owner)
        with store.transaction() as db:
            row = store._get(db, check_ref)
            selected, invalid = clean_paths(row['observed_paths'], tolerant=True)
            if row['state'] in {'OPEN', 'DIRTY'}:
                from .development_scope import separate_directories
                compiled_paths = []
                selected, directories = separate_directories(store.root, selected, compiled_paths=compiled_paths)
                from .development_scope import filter_gitignored
                selected, ignored, ignore_note = filter_gitignored(store.root, selected)
                row = dict(row, observed_directories=directories, excluded_compiled_paths=compiled_paths,
                           gitignored_paths=ignored, gitignore_filter_note=ignore_note)
            row = dict(row, observed_paths=selected, scope_unknown=row['scope_unknown'] or invalid)
            state = row['state']
            worker = store._get(db, '$worker')
            running = worker and worker.get('lease_until', 0) > self.now()
            if row['dirty_seq'] == 0 or not selected:
                state = 'NO_OBSERVED_CHANGES'
            elif (row['dirty_seq'] > row['scanned_seq'] and
                    row.get('failed_seq') != row['dirty_seq'] and (state != 'RUNNING' or not running)):
                state = 'QUEUED'
            if state in {'QUEUED', 'RUNNING'} and row.get('wait_seq') != row['dirty_seq']:
                new_submission = True
                row.update(wait_seq=row['dirty_seq'], wait_deadline=self.now()+total_budget)
            if row.get('stop_fallback', {}).get('seq') == row['dirty_seq'] and row.get('wait_deadline'):
                row['wait_deadline'] = min(row['wait_deadline'], row['stop_fallback']['deadline'])
            row = store._put(db, check_ref, dict(row, finish_requested=True, state=state, updated_at=self.now()))
        if new_submission:
            from .performance_trace import queue_event
            queue_event('submitted', row)
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
        return await self.wait_saved(root, check_ref, wait_seconds, submitted=submitted)

    async def complete(self, root, check_ref):
        """One submit; the product selects the communication budget."""
        budget = product_wait_seconds()  # Reject bad configuration before dispatch.
        started = self.monotonic()
        submitted = self.finish(root, check_ref)
        submission_ms = round((self.monotonic()-started)*1000, 3)
        result = await self.wait_saved(root, check_ref, budget, submitted=submitted)
        result['closeout_wait']['submission_ms'] = submission_ms
        return result

    @timed('check.wait')
    async def wait_saved(self, root, check_ref, wait_seconds=None, *, submitted=None):
        """Read-only continuation. Never finish, rescan, or wake a worker."""
        if wait_seconds is None:
            wait_seconds = product_wait_seconds()
        if type(wait_seconds) not in (int, float) or not 0 <= wait_seconds <= MAX_PRODUCT_WAIT_SECONDS:
            raise ValueError('DEVELOPMENT_WAIT_INVALID')
        submitted = submitted or projection(self.store(root), self.store(root).load(check_ref, self.owner))
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
            if (row['dirty_seq'] != expected_seq or state['status'] not in {'QUEUED', 'RUNNING'}
                    or state['wait_deadline_exceeded']):
                break
            remaining = deadline - self.monotonic()
            if state['wait_deadline'] is not None:
                remaining = min(remaining, state['wait_deadline'] - self.now())
            if remaining <= 0:
                break
            # Local metadata reads are cheap; do not delay a ready result by 2s.
            # The external continuation hint remains unchanged.
            await self.wait_sleep(min(0.25, remaining))
        # Reuse the normal read boundary and its full scope, gaps, version and
        # finding access, including any edit racing with the last observation.
        read_started = self.monotonic()
        result = self.get(root, check_ref)
        result_read_ms = round((self.monotonic()-read_started)*1000, 3)
        reason = ('VERSION_CHANGED' if result['dirty_seq'] != expected_seq else
                  'TOTAL_WAIT_BUDGET_EXHAUSTED' if result['wait_deadline_exceeded'] else
                  'TIME_BUDGET_EXHAUSTED' if result['status'] in {'QUEUED', 'RUNNING'} else
                  'STATE_AVAILABLE')
        result['closeout_wait'] = dict(contract='bounded-closeout-wait-v1',
            requested_seconds=wait_seconds, elapsed_ms=round((self.monotonic()-started)*1000, 3),
            result_read_ms=result_read_ms,
            polls=polls, requested_dirty_seq=expected_seq, stopped_reason=reason,
            scanner_dispatched_by_wait=False, host_review_completed=False)
        return result

    def deliveries(self, root, *, offset=0, limit=20):
        from .development_delivery import pending, facts
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError('DEVELOPMENT_DELIVERY_PAGE_INVALID')
        rows = pending(self.store(root), self.owner)
        return dict(contract='development-result-delivery-v1', results=[facts(r, summary=True) for r in rows[offset:offset+limit]],
                    total=len(rows), next_offset=offset+limit if offset+limit < len(rows) else None,
                    user_consumption='UNKNOWN', automatic_host_ack=False)

    def saved_result(self, root, check_ref, scanned_seq):
        from .development_delivery import key, facts
        store = self.store(root)
        store.load(check_ref, self.owner)
        row = store.read(key(check_ref, scanned_seq))
        if row is None or row['owner'] != self.owner or row['root_identity'] != root_identity(store.root):
            raise ValueError('DEVELOPMENT_RESULT_UNAVAILABLE')
        result = dict(delivery=facts(row), result=row['result'], reason_code=row['reason_code'],
                      analysis_requirements=analysis_requirements(row))
        if row['scan_id']:
            from .storage import ReadOnlySQLiteStore
            from .mcp_tools.presentation import _agent_result
            no_links(Path(row['scan_path']))
            scan = ReadOnlySQLiteStore(Path(row['scan_path'])).get_scan(row['scan_id'])
            if scan is None or Path(scan['target_profile']['path']).resolve() != store.root:
                raise ValueError('DEVELOPMENT_RESULT_UNAVAILABLE')
            result['static_result'] = _agent_result(scan, summary=True)
            if 'findings_access' in result['static_result']:
                result['static_result']['findings_access']['arguments']['workspace_path'] = str(store.root)
        from .dashboard_service import session_url
        url = session_url(store.root, self.owner)
        if url:
            result['risk_management_url'] = url
        return result

    @timed('check.result_read')
    def get(self, root, check_ref):
        store = self.store(root)
        row = store.load(check_ref, self.owner)
        result = projection(store, row)
        from .business_audit import status as audit_status
        result['business_audit'] = audit_status(row)
        result['risk_import_status'] = row.get('risk_import_status', 'AVAILABLE')
        if row.get('has_unified_risks'):
            result['risk_access'] = dict(tool='get_development_risks', arguments=dict(
                workspace_path=str(store.root), check_ref=check_ref))
        if row.get('has_development_review') or row.get('scan_id'):
            from .development_risks import DevelopmentRisks, review_progress
            risks = DevelopmentRisks(self, store.root, check_ref).load()
            result['review_progress'] = review_progress(row, risks)
            result['host_review_completed'] = result['review_progress']['host_review_completed']
            result['host_review_trust'] = 'HOST_REPORTED_NOT_SCANNER_PROOF'
            result['risk_access'] = dict(tool='get_development_risks', arguments=dict(
                workspace_path=str(store.root), check_ref=check_ref))
        if row['scan_id']:
            from .storage import ReadOnlySQLiteStore
            from .mcp_tools.presentation import _agent_result
            no_links(Path(row['scan_path']))
            unified = row.get('security_result', {})
            scan = unified.get('scan_facts', {}).get(row['scan_id'])
            if scan is not None:
                originals = [o['finding'] for risk in unified['risks'].values()
                             for o in risk['observations'] if o.get('source') == 'SCANNER'
                             and o.get('scan_id') == row['scan_id']]
                scan = dict(scan, findings=originals)
            else:
                scan = ReadOnlySQLiteStore(Path(row['scan_path'])).get_scan(row['scan_id'])
            if scan is None or Path(scan['target_profile']['path']).resolve() != store.root:
                result.update(reason_code='DEVELOPMENT_RESULT_UNAVAILABLE', result_available=False)
                result['gaps'].append('SAVED_RESULT_UNAVAILABLE')
            else:
                result['static_result'] = _agent_result(scan, summary=True)
                if 'findings_access' in result['static_result']:
                    result['static_result']['findings_access']['arguments']['workspace_path'] = str(store.root)
        if (result['result_available'] and result['status'] in {'RESULTS_READY', 'PARTIAL'}
                and row['scanned_seq'] == row['dirty_seq']
                and any(result.get('review_progress', {}).get(part) == 'PENDING'
                        for part in ('scanner_review', 'business_review'))):
            result['next_action'] = result['risk_access']
            result['review_instruction'] = (
                '最终回复前按 review_progress 完成配置要求的复核：读取告警证据并提交判断，'
                '再重新读取风险及处置。无需运行漏洞利用；实际证据不足时保留 INCONCLUSIVE 并说明缺口。')
        result['review_ready'] = False
        if (result['result_available'] and result['status'] in {'RESULTS_READY', 'PARTIAL'}
                and row['scanned_seq'] == row['dirty_seq']):
            from .development_risks import DevelopmentRisks
            from .development_views import risk_summary
            page = DevelopmentRisks(self, store.root, check_ref).get(limit=20, include_history=False)
            if (page['scan_id'] == row['scan_id'] and page['dirty_seq'] == row['dirty_seq']
                    and page.get('candidates_ready')):
                result['review_ready'] = True
                result['development_result'] = risk_summary(page)
                result['development_result']['scan_summary'] = result.get('static_result')
                result['development_result']['storage_contract'] = 'embedded-development-result-v1'
                from .dashboard_service import session_url
                url = session_url(store.root, self.owner)
                if url:
                    result['development_result']['risk_management_url'] = url
                if page.get('next_action') is not None:
                    result['next_action'] = page['next_action']
            else:
                result['reason_code'] = page.get('reason_code', 'DEVELOPMENT_RESULT_VERSION_CHANGED')
                result['next_action'] = page.get('next_action')
                if page.get('candidate_status') == 'PENDING':
                    result.update(status='RUNNING', poll_after_seconds=2)
        return result


def record_hook(hooks, root, owner, paths=(), *, scope_unknown=True, event_id=None,
                scan_path=None, launcher=None, prepare_only=False, watch_eligible=False, turn_id=None):
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
    focused = store.read(key)
    if owner['host'] == 'codex':
        from .hooks import codex_commit_only
        if codex_commit_only(store.root):
            current = store.load(focused['check_ref'], owner) if focused else None
            if not current or current.get('automatic') or current.get('finish_requested'):
                return dict(status='NOT_SCANNED', reason_code='GIT_COMMIT_ONLY',
                            scanner_run=False, coverage='NOT_APPLICABLE')
    covered = False
    if focused and not prepare_only and (event_id or watch_eligible):
        from .development_file_watch import active
        covered = active(store, focused['check_ref'], owner, completed=event_id) and watch_eligible
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
        row = note_activity(row, turn_id)
        if prepare_only:
            store._put(db, row['check_ref'], row)
        elif covered and focused['check_ref'] == row['check_ref'] and not names and not invalid:
            # The live task window records actual notifications. A shell whose
            # syntax is unknown need not invent an edit or a new unknown scope.
            store._put(db, row['check_ref'], row)
        else:
            row, changed = store.append(db, row, names, bool(scope_unknown or invalid), event_id)
        if digest is not None:
            store._put(db, replay_key, dict(kind='replay', events=[*replay['events'],
                dict(id=digest, check_ref=row['check_ref'])][-MAX_EVENTS:]))
    service._prewarm(store.root, row, names)
    return projection(store, store.load(row['check_ref'], owner))

"""Durable selected native-repair intent, separate from impact drafts and risk choices.

This is a product workflow guard, not an atomic bridge to host file writes or
authenticated human consent. Only the native repair entry point records intent.
"""
from __future__ import annotations

import copy
import math
from pathlib import Path
import re
import time

from .repair_impact_models import digest, encoded, path, require, source as clean_source
from .repair_impact_store import RepairImpactStore
from .tasks.ownership import record_owner, valid_owner


CONTRACT = 'native-repair-intent-v1'
PREPARATION_FIELDS = frozenset({'assessment_ref', 'revision', 'source', 'source_binding',
    'proposal_revision', 'proposal_summary', 'security_goal', 'preserve', 'source_hashes'})
TASK_REF = re.compile(r'ts1-[a-f0-9]{32}')


class NativeRepairIntents:
    def __init__(self, hooks, root, owner, now=time.time):
        require(valid_owner(owner), 'NATIVE_REPAIR_OWNER_REQUIRED')
        self.hooks, self.root, self.owner, self.now = hooks, Path(root), copy.deepcopy(owner), now
        self.workspace = digest(str(self.root).casefold())
        self.id = digest(dict(workspace=self.workspace, owner=self.owner))
        self.store = RepairImpactStore(hooks.workspace_directory(self.root) / 'repair-impact')

    def _time(self):
        value = self.now()
        require(type(value) in (int, float) and math.isfinite(value), 'NATIVE_REPAIR_CLOCK_INVALID')
        return value

    def _load(self, db):
        record = self.store.load(db, 'native_intents', self.id)
        if record is not None:
            require(record.get('contract') == CONTRACT and record.get('workspace') == self.workspace
                and record.get('owner') == self.owner
                and record.get('status') in {'WAITING', 'READY', 'BOUND', 'CANCELLED'},
                'NATIVE_REPAIR_INTENT_INVALID')
        return record

    def _save(self, db, record):
        record['updated_at'] = self._time()
        self.store.save(db, 'native_intents', self.id, record)
        return copy.deepcopy(record)

    def get(self):
        # Ordinary development must not create a private DB/key or migrate an
        # existing impact-only DB just to establish that no intent was recorded.
        if not self.store.path.exists():
            return None
        with self.store.connect() as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='native_intents'").fetchone():
                return None
            return copy.deepcopy(self._load(db))

    def _completed_binding(self, record):
        """Completion releases workflow blocking, without resolving the risk.

        Only the exact signed task and preparation count. A missing, expired,
        foreign or incomplete task cannot be treated as a completed repair.
        """
        if not record.get('repair_task_ref'):
            return False
        from .tasks.security_state import TaskSecurityStore
        task = TaskSecurityStore(self.hooks, self.root, now=self.now).get(record['repair_task_ref'])
        return (task is not None and record_owner(task) == self.owner
            and task.get('native_repair') == record['preparation']
            and task['phase'] in {'COMPLETE', 'NO_CHANGES'})

    def request(self, source, assessment_ref=None):
        source = clean_source(source)
        require(source['kind'] == 'HOST_TASK_RISK', 'NATIVE_REPAIR_SOURCE_REQUIRED')
        require(assessment_ref is None or (isinstance(assessment_ref, str)
            and 0 < len(assessment_ref) <= 160), 'NATIVE_REPAIR_ASSESSMENT_INVALID')
        with self.store.connect(write=True) as db:
            old = self._load(db)
            same = old is not None and old['source'] == source and old['assessment_ref'] == assessment_ref
            if old and old.get('repair_task_ref'):
                if old['status'] == 'BOUND':
                    if same:
                        return copy.deepcopy(old)
                    require(self._completed_binding(old), 'NATIVE_REPAIR_ALREADY_BOUND')
                if old['status'] == 'CANCELLED':
                    if same:
                        old['status'] = 'BOUND'
                        return self._save(db, old)
                    require(self._completed_binding(old), 'NATIVE_REPAIR_ALREADY_BOUND')
            if old and old['status'] in {'WAITING', 'READY'}:
                require(old['source'] == source, 'NATIVE_REPAIR_SELECTION_PENDING')
                if same:
                    return copy.deepcopy(old)
            now = self._time()
            record = dict(contract=CONTRACT, workspace=self.workspace, owner=self.owner,
                source=source, assessment_ref=assessment_ref, preparation=None,
                repair_task_ref=None, status='WAITING', created_at=now, updated_at=now)
            return self._save(db, record)

    def ready(self, preparation):
        require(isinstance(preparation, dict) and set(preparation) == PREPARATION_FIELDS,
                'NATIVE_REPAIR_PREPARATION_INVALID')
        require(len(encoded(preparation)) <= 128_000, 'NATIVE_REPAIR_PREPARATION_INVALID')
        require(type(preparation['revision']) is int and preparation['revision'] >= 1
            and isinstance(preparation['source_binding'], dict)
            and isinstance(preparation['proposal_revision'], str)
            and bool(re.fullmatch(r'[a-f0-9]{64}', preparation['proposal_revision']))
            and isinstance(preparation['source_hashes'], dict)
            and 0 < len(preparation['source_hashes']) <= 64,
            'NATIVE_REPAIR_PREPARATION_INVALID')
        for name, sha in preparation['source_hashes'].items():
            require(path(name) == name and isinstance(sha, str)
                and bool(re.fullmatch(r'[a-f0-9]{64}', sha)), 'NATIVE_REPAIR_PREPARATION_INVALID')
        with self.store.connect(write=True) as db:
            record = self._load(db)
            require(record is not None and record['status'] != 'CANCELLED', 'NATIVE_REPAIR_INTENT_REQUIRED')
            require(preparation['source'] == record['source']
                and preparation['assessment_ref'] == record['assessment_ref'],
                'NATIVE_REPAIR_PREPARATION_MISMATCH')
            if record['status'] == 'BOUND':
                require(record['preparation'] == preparation, 'NATIVE_REPAIR_ALREADY_BOUND')
                return copy.deepcopy(record)
            record.update(status='READY', preparation=copy.deepcopy(preparation))
            return self._save(db, record)

    def bind(self, task_ref):
        require(isinstance(task_ref, str) and TASK_REF.fullmatch(task_ref), 'NATIVE_REPAIR_TASK_INVALID')
        with self.store.connect(write=True) as db:
            record = self._load(db)
            require(record is not None and record['status'] in {'READY', 'BOUND'},
                    'NATIVE_REPAIR_PREPARATION_REQUIRED')
            if record['status'] == 'BOUND':
                require(record['repair_task_ref'] == task_ref, 'NATIVE_REPAIR_ALREADY_BOUND')
                return copy.deepcopy(record)
            from .tasks.security_state import TaskSecurityStore
            task = TaskSecurityStore(self.hooks, self.root, now=self.now).get(task_ref)
            require(task is not None and record_owner(task) == self.owner
                and task.get('native_repair') == record['preparation'],
                'NATIVE_REPAIR_TASK_MISMATCH')
            record.update(status='BOUND', repair_task_ref=task_ref)
            return self._save(db, record)

    def cancel(self, user_requested=True):
        require(user_requested is True, 'NATIVE_REPAIR_USER_REQUEST_REQUIRED')
        if self.get() is None:
            return None
        with self.store.connect(write=True) as db:
            record = self._load(db)
            require(record is not None, 'NATIVE_REPAIR_INTENT_REQUIRED')
            record['status'] = 'CANCELLED'
            return self._save(db, record)

    def release_effect(self, source):
        """Capture only the exact selected intent; this template is not consent."""
        source = clean_source(source)
        record = self.get()
        if (record is None or record['source'] != source or record['owner'] != self.owner
                or record['status'] == 'CANCELLED'):
            return None
        return dict(kind='RELEASE_NATIVE_INTENT', payload=dict(owner=copy.deepcopy(self.owner),
            source=copy.deepcopy(source), intent_sha256=digest(record)))

    def apply_release(self, effect):
        """Decision outbox -> exact owner/version cancellation plus signed inbox."""
        require(isinstance(effect, dict) and effect.get('contract') == 'native-intent-release-v1'
            and effect.get('kind') == 'RELEASE_NATIVE_INTENT'
            and isinstance(effect.get('event_id'), str) and 0 < len(effect['event_id']) <= 200,
            'NATIVE_REPAIR_RELEASE_INVALID')
        payload = effect.get('payload')
        require(isinstance(payload, dict) and set(payload) == {'owner','source','intent_sha256'}
            and payload['owner'] == self.owner and clean_source(payload['source']) == payload['source'],
            'NATIVE_REPAIR_RELEASE_OWNER_MISMATCH')
        require(isinstance(payload['intent_sha256'],str) and
                re.fullmatch(r'[a-f0-9]{64}',payload['intent_sha256']) is not None,
                'NATIVE_REPAIR_RELEASE_SNAPSHOT_UNAVAILABLE')
        from .persistence_effects import digest as effect_digest
        require(effect['event_id'] == 'nie1-'+effect_digest({key: value for key, value in effect.items()
            if key != 'event_id'}),
            'NATIVE_REPAIR_RELEASE_INVALID')
        sha = digest(effect)
        with self.store.connect(write=True) as db:
            prior = self.store.load(db, 'native_effect_receipts', effect['event_id'])
            if prior is not None:
                require(prior.get('payload_sha256') == sha, 'NATIVE_REPAIR_RELEASE_CONFLICT')
                return dict(event_id=effect['event_id'], outcome=prior['outcome'], already_applied=True)
            require(db.execute('SELECT count(*) FROM native_effect_receipts').fetchone()[0] < 2000,
                    'NATIVE_REPAIR_RELEASE_CAPACITY')
            record = self._load(db)
            matches = (record is not None and record['source'] == payload['source']
                       and digest(record) == payload['intent_sha256'])
            outcome = 'APPLIED' if matches else 'SUPERSEDED'
            if matches:
                record['status'] = 'CANCELLED'
                self._save(db, record)
            self.store.save(db, 'native_effect_receipts', effect['event_id'],
                dict(payload_sha256=sha, outcome=outcome, owner=self.owner))
            return dict(event_id=effect['event_id'], outcome=outcome, already_applied=False)

    def drain_releases(self, decisions, limit=16):
        """Mutation-only bounded recovery; foreign owners remain pending."""
        applied = superseded = errors = 0
        import sqlite3
        def unavailable():
            # A corrupt/unavailable decision store is not an empty queue. Its
            # recovery diagnostic must not undo explicit cancel or bypass guard.
            return dict(status='PENDING', applied=applied, superseded=superseded,
                foreign=None, pending=None, errors=errors + 1,
                reason_code='NATIVE_RELEASE_QUEUE_UNAVAILABLE', repair_authorized=False)
        try:
            effects = decisions.pending_effects(self.root, limit=limit, owner=self.owner, ready_only=True)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return unavailable()
        for effect in effects:
            try:
                result = self.apply_release(effect)
                decisions.acknowledge_effect(effect['event_id'], outcome=result['outcome'])
                applied += result['outcome'] == 'APPLIED'
                superseded += result['outcome'] == 'SUPERSEDED'
            except (OSError, ValueError, sqlite3.DatabaseError):
                errors += 1  # Preserve this obligation; other owned deliveries can progress.
        try:
            pending = decisions.pending_effect_count(self.root,owner=self.owner)
            foreign = decisions.pending_effect_count(self.root)-pending
        except (OSError, ValueError, sqlite3.DatabaseError):
            return unavailable()
        return dict(status='PENDING' if pending else 'APPLIED', applied=applied,
            superseded=superseded, foreign=foreign, pending=pending, errors=errors, repair_authorized=False)

    def guard(self, preparation=None):
        record = self.get()
        if record is None or record['status'] == 'CANCELLED':
            if preparation is None:
                return None
        elif record['status'] in {'READY', 'BOUND'}:
            if preparation is not None and preparation == record['preparation']:
                return None
            if (record['status'] == 'BOUND' and preparation is None
                    and self._completed_binding(record)):
                return None
        result = dict(status='NATIVE_REPAIR_PREPARATION_REQUIRED',
            reason_code='NATIVE_REPAIR_PREPARATION_REQUIRED', scanner_run=False,
            source_modified=False, repair_authorized=False,
            message='先沿已选原生风险完成修复准备，沿用原修复意图；不要另建任务替代。')
        if record:
            result.update(source=copy.deepcopy(record['source']), assessment_ref=record['assessment_ref'])
            if record.get('repair_task_ref'):
                result['repair_task_ref'] = record['repair_task_ref']
            if record.get('repair_task_ref'):
                from .tasks.security_state import TaskSecurityStore
                from .task_review.protocol import is_v3_record, UnsupportedTaskReviewProtocol
                task = TaskSecurityStore(self.hooks, self.root, now=self.now).get(record['repair_task_ref'])
                if (task is not None and record_owner(task) == self.owner
                        and task.get('native_repair') == record['preparation']
                        and not is_v3_record(task)):
                    result.update(protocol_support=UnsupportedTaskReviewProtocol(
                        task.get('review_protocol')).response(), new_work_requires_explicit_switch=True,
                        message='已绑定的旧开发任务协议已停止执行，原风险、修复意图与基线保留。'
                                '如用户已明确暂停该修复或切换其他工作，沿原引用取消阻塞意图后，'
                                '在后续修改前用新任务键开始 v3；不能为旧改动补建基线。')
                    return result
            arguments = dict(task_ref=record['source']['task_ref'], finding_id=record['source']['finding_id'],
                             impact_ref=record['assessment_ref'], user_requested=True,
                             workspace_path=str(self.root))
            if 'origin_review_revision' in record['source']:
                arguments['origin_review_revision'] = record['source']['origin_review_revision']
            result['next_action'] = dict(tool='prepare_task_risk_fix', arguments=arguments)
        return result

"""Task-bound static checks and bounded host reasoning before the dev summary.

No model, source edits, installs, builds or Stop continuation inside Runtime.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from .hook_state import HookStateStore, identity
from .git import GitError, GitService
from .local_evidence import EvidenceUnavailable, WorkspaceReader, _relative, safe_source, MAX_LINE_CHARS
from .redactor import SecretRedactor
from .task_security_state import CONTRACT, TaskSecurityStore
from .task_review_protocol import PROTOCOL_VERSION, validate_protocol, require_record_protocol, is_v3_record
from .task_snapshot import (SnapshotPolicy, collect_snapshot,
                            MAX_READ_BYTES, MAX_INLINE_TEXT_BYTES as MAX_PREIMAGE_BYTES,
                            MAX_INVENTORY_PATHS, MAX_INVENTORY_NAME_BYTES,
                            MAX_INVENTORY_DIRECTORIES, MAX_INVENTORY_DEPTH)
from .target import DEPENDENCIES, EXTENSIONS, IGNORED
from .workspace import WorkspaceResolver

MAX_FILES = SnapshotPolicy().max_files
MAX_CHANGED = 20
MAX_STATIC_CHANGED = 1000

REVIEW_TTL = 900


class TaskContextError(ValueError):
    """A bounded context request problem, not a workspace readiness failure."""
    def __init__(self, reason_code, message, *, recoverable=True, guidance, details=None):
        super().__init__(message)
        self.reason_code = reason_code
        self.recoverable = recoverable
        self.guidance = guidance
        self.details = details or {}

    def response(self, task_ref, review_session):
        return dict(status='CONTEXT_REQUEST_REJECTED', task_ref=task_ref,
                    review_session=review_session, reason_code=self.reason_code,
                    message=str(self), recoverable=self.recoverable, guidance=self.guidance,
                    details=self.details, scanner_run=False, repair_authorized=False)


def _merge_spans(spans):
    merged = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(high, merged[-1][1])
        else:
            merged.append([low, high])
    return merged


def _unread_context(record):
    """Only Runtime-issued windows satisfy a requested current-version span."""
    missing = []
    for request in record.get('context_requests', {}).values():
        spans = request['spans']
        evidence = [e for e in record['evidence'].values()
                    if all(e[k] == request[k] for k in ('path', 'file_sha256', 'location_version'))]
        covered = _merge_spans([[e['start_line'], e['end_line']] for e in evidence])
        for low, high in spans:
            cursor = low
            for start, end in covered:
                if end < cursor or start > high:
                    continue
                if start > cursor:
                    missing.append(dict(path=request['path'], start_line=cursor, end_line=min(high, start-1)))
                cursor = max(cursor, end+1)
                if cursor > high:
                    break
            if cursor <= high:
                missing.append(dict(path=request['path'], start_line=cursor, end_line=high))
    return missing


def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_value(value):
    return hash_bytes(json.dumps(value, sort_keys=True, ensure_ascii=True).encode())


def method(protocol_version=PROTOCOL_VERSION):
    validate_protocol(protocol_version)
    path = Path(__file__).parent / 'skills/ai-security-review/references/quick-task-review-v3.md'
    content = path.read_text(encoding='utf-8')
    return dict(version='quick-task-review-v3', sha256=hash_bytes(content.encode()), content=content)


def _supported(name):
    path = Path(name)
    return (path.suffix.lower() in set(EXTENSIONS) | {'.mjs', '.cjs', '.mts', '.cts', '.yaml', '.yml', '.json', '.xml', '.properties', '.toml', '.tf'}
            or path.name in set(DEPENDENCIES) | {'Dockerfile', '.env', '.gitignore'} or path.name.startswith('.env.'))


def _environment(name):
    return Path(name).name == '.env' or Path(name).name.startswith('.env.')


def _inventory(root, ignored):
    """Use Git's project boundary and ignore policy, never recursively walk Git output."""
    limitations, dirty = [], []
    if (root / '.git').exists():
        try:
            git = GitService(root)
            if git.top_level() != root.resolve():
                raise GitError('TASK_GIT_ROOT_MISMATCH')
            names = git._paths('ls-files', '--cached', '--others', '--exclude-standard', '-z')
            dirty = git.changed_files('quick')
        except (GitError, OSError, subprocess.TimeoutExpired):
            return [], [], False, [{'reason': 'GIT_INVENTORY_UNAVAILABLE'}]
    else:
        from .task_inventory import non_git_inventory
        names, limitations = non_git_inventory(root, ignored,
            max_entries=MAX_INVENTORY_PATHS, max_directories=MAX_INVENTORY_DIRECTORIES,
            max_depth=MAX_INVENTORY_DEPTH, max_name_bytes=MAX_INVENTORY_NAME_BYTES)
    selected, selected_name_bytes = set(), 0
    for name in names:
        try:
            name = _relative(name)
            if not _supported(name) or set(Path(name).parts) & ignored:
                continue
            if name in selected:
                continue
            cost = len(name.encode('utf-8'))
            if len(selected) >= MAX_INVENTORY_PATHS or selected_name_bytes+cost > MAX_INVENTORY_NAME_BYTES:
                reason = ('SNAPSHOT_INVENTORY_FILE_BUDGET' if len(selected) >= MAX_INVENTORY_PATHS
                          else 'SNAPSHOT_INVENTORY_NAME_BYTE_BUDGET')
                limitations.append(dict(reason=reason, limit=(MAX_INVENTORY_PATHS
                    if reason == 'SNAPSHOT_INVENTORY_FILE_BUDGET' else MAX_INVENTORY_NAME_BYTES),
                    observed_at_least=len(selected)+1, pending_count_unknown=True))
                break
            # Missing tracked files are real deletions, not read failures. lstat
            # does not follow a link; WorkspaceReader validates every actual read.
            (root / name).lstat()
            selected.add(name)
            selected_name_bytes += cost
        except FileNotFoundError:
            continue
        except (OSError, EvidenceUnavailable) as exc:
            limitations.append({'path': name, 'reason': getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')})
    return sorted(selected), dirty, not limitations, limitations


def capture(root, *, known_paths=None, priority_paths=(), include_text=True, preimage_writer=None):
    """Hash the actual workspace (including pre-existing dirty/new files).

    Retain only sanitized text, never raw source/credentials. All budgets are
    reported; unavailable/truncated inventory cannot attest a full task.
    Freshness-only callers may omit text preparation, but must still inventory
    and safely read/hash every current file with the same source guards.
    """
    ignored = IGNORED | {v.strip() for v in os.getenv('SECURITY_RUNTIME_EXCLUDE_DIRS', '').split(',') if v.strip()}
    inventory, dirty, complete, inventory_limits = _inventory(root, ignored)
    policy = SnapshotPolicy(max_files=MAX_FILES, max_read_bytes=MAX_READ_BYTES,
        max_inline_text_bytes=MAX_PREIMAGE_BYTES, max_inventory_paths=MAX_INVENTORY_PATHS,
        max_inventory_name_bytes=MAX_INVENTORY_NAME_BYTES)
    return collect_snapshot(root, inventory=inventory, dirty=dirty,
        inventory_complete=complete, inventory_limits=inventory_limits,
        known_paths=known_paths, priority_paths=priority_paths, include_text=include_text,
        preimage_writer=preimage_writer, policy=policy,
        reader_factory=WorkspaceReader, sanitizer=safe_source)


def task_changes(root, baseline, end):
    """Absent hashes in a partial snapshot never prove an addition or deletion."""
    before, after = baseline['hashes'], end['hashes']
    before_names = set(baseline.get('inventory', before))
    after_names = set(end.get('inventory', after))
    before_complete = baseline.get('inventory_complete', not baseline['limitations'])
    after_complete = end.get('inventory_complete', not end['limitations'])
    changes, unknown = [], []
    for name in sorted(before_names | after_names):
        if name not in before_names:
            if before_complete:
                changes.append(dict(path=name, change='ADDED'))
            else:
                unknown.append(name)
        elif name not in after_names:
            if after_complete and not os.path.lexists(root / name):
                changes.append(dict(path=name, change='DELETED'))
            else:
                unknown.append(name)
        elif name not in before or name not in after:
            unknown.append(name)
        elif before[name] != after[name]:
            changes.append(dict(path=name, change='MODIFIED'))
    return changes, unknown


def _clean(value, limit=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError('Invalid bounded review text')
    # Free-form model text is data, never an instruction or authorization.
    text = SecretRedactor().redact(value)
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)


def finding_view(f):
    """Bounded navigation/explanation; raw scanner evidence stays local."""
    result = {k:f[k] for k in ('id','category','severity','file_path','line_start','line_end') if k in f}
    for key in ('plain_title','title','impact','fix_advice'):
        if key in f:
            result[key] = SecretRedactor().redact(str(f[key]))[:1200]
    result['scanner_sources'] = f.get('scanner_sources', [])[:10]
    return result


def _coverage_gaps(limitations):
    labels = {'SOURCE_LINE_CHAR_BUDGET': '源码单行超出显示预算',
              'SNAPSHOT_INVENTORY_DIRECTORY_BUDGET': '文件盘点达到目录容量上限',
              'SNAPSHOT_INVENTORY_FILE_BUDGET': '文件盘点达到路径数量上限',
              'SNAPSHOT_INVENTORY_ENTRY_BUDGET': '文件盘点达到目录条目处理容量上限，剩余数量未知',
              'SNAPSHOT_INVENTORY_NAME_BYTE_BUDGET': '文件盘点达到路径存储容量上限',
              'SNAPSHOT_READ_FILE_BUDGET': '源码采集达到文件数量上限',
              'SNAPSHOT_READ_BYTE_BUDGET': '源码采集达到读取容量上限',
              'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET': '修改前脱敏正文超出保存容量',
              'TASK_SEMANTIC_PROOF_UNVERIFIED': '脱敏行的修改前定位记录无法核验',
              'TASK_HOOK_CURRENT_SOURCE_UNAVAILABLE': '文件修改检查保留路径的当前源码不可用',
              'TASK_HOOK_FINAL_SCOPE_BUDGET': '文件修改检查保留路径超出最终扫描范围预算',
              'TASK_HOOK_LEDGER_SCOPE_INCOMPLETE': '部分文件修改检查记录或保留路径超出记录预算',
              'TASK_HOOK_RECORDING_FAILED': '部分文件修改检查结果未能保存，相关路径的完整核查仍待确认',
              'TASK_HOOK_FAILED_PATHS_UNKNOWN': '部分文件修改检查记录失败，失败路径未知或不完整',
              'TASK_HOOK_FAILURE_MARKER_UNVERIFIED': '文件修改检查失败记录无法核验，失败路径未知',
              'TASK_STATIC_SCOPE_EXCLUDED': '部分任务改动未进入静态检查范围',
              'TASK_CONTEXT_SCOPE_EXCLUDED': '部分任务改动超出上下文文件预算',
              'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE': '开始版本或脱敏源码超出文本预算',
              'DIFF_BYTE_BUDGET': '部分任务差异超出字节预算',
              'DIFF_LINE_BUDGET': '部分任务差异超出行数预算',
              'INITIAL_PACKET_BUDGET': '初始任务上下文超出返回预算',
              'CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE': '同一工作区的任务时间窗重叠，改动归属未能独立确认'}
    result = []
    for limitation in limitations[:10]:
        message = labels.get(limitation.get('reason'), '部分任务源码或盘点不可用')
        paths = ([limitation['path']] if limitation.get('path') else limitation.get('paths', []))
        if paths:
            message += '：'+ '、'.join(str(p) for p in paths[:5])
            if len(paths)>5:
                message += f' 等 {len(paths)} 个记录路径'
        if limitation.get('count'):
            message += f"（{limitation['count']} 项）"
        result.append(message[:500])
    return result


class TaskSecurityService:
    def __init__(self, runtime, hooks=None, *, now=time.time, owner=None):
        self.runtime = runtime
        self.hooks = hooks or HookStateStore()
        self.now = now
        self.owner = owner

    def _owner(self):
        from .task_ownership import valid_owner
        owner=self.owner() if callable(self.owner) else self.owner
        if owner is not None and not valid_owner(owner): raise ValueError('Invalid task owner')
        return owner

    @staticmethod
    def key(task_key, owner=None):
        return identity(task_key if owner is None else task_key+'\x00'+json.dumps(owner,sort_keys=True))

    def root(self, workspace):
        return WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True).path

    def store(self, root):
        return TaskSecurityStore(self.hooks, root, now=self.now)

    def preimages(self, root):
        from .task_preimages import TaskPreimageStore
        return TaskPreimageStore(self.hooks, root, now=self.now)

    def discard_preimages(self, root, ref):
        try:
            self.preimages(root).discard(ref)
        except (OSError, ValueError):
            pass  # TTL and the private-store hard limits remain in force.

    def before_lines(self, root, record, path):
        """Only the original inline body or its signed immutable reference."""
        inline = record['baseline'].get('texts', {}).get(path)
        if inline is not None:
            return inline
        reference = record['baseline'].get('preimages', {}).get(path)
        if reference is None:
            return None
        return self.preimages(root).read(record['task_ref'], path,
            record['baseline']['hashes'][path], reference)

    def end_lines(self, root, record, path):
        raw, text = WorkspaceReader(root).read(path)
        if hash_bytes(raw) != record['end']['hashes'].get(path):
            raise ValueError('Task source changed; submitted evidence is stale')
        truncated = []
        lines = safe_source(text, source_path=path, truncation_lines=truncated)
        if truncated:
            record['end'].setdefault('text_truncations', {})[path] = dict(line_count=len(truncated), lines=truncated)
        return lines

    def load(self, root, ref, *, read_only=False):
        record = self.store(root).get(ref)
        if not record:
            raise ValueError('Task is unavailable or expired; never infer a baseline after editing')
        from .task_ownership import record_owner, ownership_error
        owner=self._owner()
        if not read_only and owner is not None and record_owner(record)!=owner:
            raise ownership_error(record_owner(record), owner)
        return record

    def begin(self, workspace, task_key, *, _owner=None, _native_preparation=None):
        if not isinstance(task_key, str) or not 1 <= len(task_key) <= 200:
            raise ValueError('Use a short unique task key, not a prompt or source')
        from .task_ownership import valid_owner, record_owner, writer_identity
        owner=self._owner() if _owner is None else _owner
        if owner is not None and not valid_owner(owner):
            raise ValueError('Invalid connector owner')
        root = self.root(workspace)
        def existing():
            store = self.store(root)
            self._recover_persistence(root, owner)
            native = None
            if owner is not None:
                from .native_repair_intent import NativeRepairIntents
                native = NativeRepairIntents(self.hooks, root, owner, now=self.now)
                blocked = native.guard(_native_preparation)
                if blocked is not None:
                    return blocked, native
                intent = native.get()
                if _native_preparation is not None and intent.get('repair_task_ref'):
                    original = self.load(root, intent['repair_task_ref'])
                    require_record_protocol(original)
                    if original.get('native_repair') != _native_preparation:
                        raise ValueError('NATIVE_REPAIR_TASK_MISMATCH')
                    return self._view(original), native
                if _native_preparation is not None:
                    # Recover a task published before a process stopped between
                    # the signed baseline save and the independent intent bind.
                    candidates = [old for old in store.records(active=True)
                        if record_owner(old) == owner and old.get('native_repair') == _native_preparation]
                    if len(candidates) > 1:
                        raise ValueError('NATIVE_REPAIR_TASK_AMBIGUOUS')
                    if candidates:
                        require_record_protocol(candidates[0])
                        native.bind(candidates[0]['task_ref'])
                        return self._view(candidates[0]), native
            elif _native_preparation is not None:
                raise ValueError('NATIVE_REPAIR_OWNER_REQUIRED')
            existing = store.get(task_key=self.key(task_key,owner))
            if existing:
                require_record_protocol(existing)
                if _native_preparation is not None:
                    if existing.get('native_repair') != _native_preparation:
                        raise ValueError('NATIVE_REPAIR_TASK_KEY_CONFLICT')
                    native.bind(existing['task_ref'])
                return self._view(existing), native
            active = store.get(active=True,owner=owner)
            if active and owner is None:
                # Avoid silently joining another editing task. The host may
                # resume the exact ref, or finish it, then begin the next one.
                return dict(status='ACTIVE_TASK_EXISTS', scanner_run=False), native
            return None, native

        with self.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'scanner_run': False}
            self.hooks.key(root)
            response, _ = existing()
            if response is not None:
                return response
            capture_started_at = self.now()
        # Preimages use their independent bounded transaction. Capture source
        # outside the workspace lock, then recheck owner/intent/task membership.
        ref = 'ts1-'+uuid.uuid4().hex
        with self.preimages(root).writer(ref) as writer:
            baseline = capture(root, preimage_writer=writer,
                priority_paths=tuple(_native_preparation['source_hashes']) if _native_preparation else ())
        with self.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                self.discard_preimages(root, ref)
                return {'status': 'BUSY', 'scanner_run': False}
            response, native = existing()
            if response is not None:
                self.discard_preimages(root, ref)
                return response
            if _native_preparation is not None and not all(
                    baseline['hashes'].get(name) == sha
                    for name, sha in _native_preparation['source_hashes'].items()):
                self.discard_preimages(root, ref)
                raise ValueError('NATIVE_REPAIR_BASELINE_MISMATCH')
            record = dict(contract=CONTRACT, task_ref=ref, task_key=self.key(task_key,owner),
                workspace=str(root), generation=0, phase='ACTIVE', created_at=capture_started_at,
                review_protocol=PROTOCOL_VERSION,
                baseline=baseline, static_attempts=0, limitations=[], source='TASK_BASELINE_BEFORE_EDIT',
                # A short-lived command Hook is not the conversation's owner process.
                # Its normal exit can never prove that the editing task ended.
                writer=writer_identity() if _owner is None else None)
            if owner is not None: record['task_owner']=owner
            if _native_preparation is not None:
                import copy
                record['native_repair'] = copy.deepcopy(_native_preparation)
            if _owner is not None:
                record['connector_owner'] = _owner
            record = self.store(root).save(record, new=True)
            if _native_preparation is not None:
                native.bind(record['task_ref'])
            return self._view(record)

    def _recover_persistence(self, root, owner):
        """Existing signed obligations only, under the already held write lock."""
        from .task_projection import reconcile_pending
        reconcile_pending(self, root, limit=8, owner=owner)
        if owner is not None:
            from .native_repair_intent import NativeRepairIntents
            from .task_risk_ledger import disposition_store
            NativeRepairIntents(self.hooks, root, owner, now=self.now).drain_releases(
                disposition_store(self.hooks, root))

    def _fresh(self, root, record):
        if record.get('finished_hook_revision'):
            revision, _, _ = self._hook_inputs(root, record)
            if revision != record['finished_hook_revision']:
                return False
        current = capture(root, known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                          priority_paths=record['end'].get('read_priority', ()), include_text=False)
        if current.get('read_limitations', current['limitations']) != record['end'].get(
                'read_limitations', record['end']['limitations']):
            return False
        return (current['hashes'] == record['end']['hashes']
                and current.get('inventory') == record['end'].get('inventory', sorted(record['end']['hashes']))
                and current['inventory_complete'] == record['end'].get('inventory_complete', not record['end']['limitations']))

    def _hook_inputs(self, root, record):
        """A bounded scope revision, excluding review/read bookkeeping."""
        marker, marker_error = None, None
        try:
            marker = self.store(root).get_hook_failure(record['task_ref'])
        except (OSError, ValueError):
            marker_error = 'TASK_HOOK_FAILURE_MARKER_UNVERIFIED'
        keys = ('hook_checks', 'hook_recheck_files', 'hook_pending_scope_files',
                'hook_checks_omitted', 'hook_recheck_paths_omitted', 'hook_pending_paths_omitted')
        inputs = dict(ledger={key: record.get(key) for key in keys},
                      marker=marker, marker_error=marker_error)
        return digest_value(inputs), marker, marker_error

    def _project_risks(self, root, record, updates=None):
        from .task_projection import enqueue, drain
        from .task_risk_ledger import TaskRiskLedger
        ledger = TaskRiskLedger(self.hooks, root)
        rows = ledger.read_origins(key.split(':', 1)[0] for key in updates) if updates else {}
        expected = {key: ledger.row_version(rows[key]) for key in (updates or {})}
        saved = self.store(root).save(enqueue(record, updates, expected))
        return drain(self, root, saved)

    def finish(self, workspace, ref):
        root = self.root(workspace)
        original = self.load(root, ref)
        require_record_protocol(original)
        # Source IO never holds the cross-process publication lock.
        end = capture(root, known_paths=original['baseline'].get('inventory', original['baseline']['hashes']),
                      priority_paths=original.get('end', {}).get('read_priority', ()), include_text=False)
        # Runtime may consume root ignore/configuration files which are outside
        # the development snapshot's supported-source inventory. Bind their
        # actual bytes/absence separately; never invent an original task hash.
        auxiliary = {'.gitleaks.toml', '.gitleaksignore', '.semgrepignore'}
        for variable in ('GITLEAKS_CONFIG', 'TRIVY_CONFIG'):
            value = os.getenv(variable)
            if value:
                configured = Path(value).expanduser()
                configured = ((root/configured).resolve() if not configured.is_absolute() else configured.resolve())
                if configured.is_relative_to(root):
                    auxiliary.add(_relative(configured.relative_to(root).as_posix()))
        auxiliary_hashes = {}
        for name in sorted(auxiliary):
            if name in end['hashes']:
                auxiliary_hashes[name] = end['hashes'][name]
            elif not os.path.lexists(root/name):
                auxiliary_hashes[name] = None
            else:
                raw, _ = WorkspaceReader(root).read(name)
                auxiliary_hashes[name] = hash_bytes(raw)
        from .scan_attempt import ScanAttemptStore, ScanAttemptExecution, ScanAttemptLost, source_binding
        from .progress import ScanCancelled, current_reporter
        attempts = ScanAttemptStore(self.hooks, root, now=self.now)
        attempts.recover_cleanup(limit=2)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'task_ref': ref, 'scanner_run': False}
            record = self.load(root, ref)
            require_record_protocol(record)
            self._recover_persistence(root, self._owner())
            record = self.load(root, ref)
            from .task_projection import drain
            record = drain(self, root, record)
            if record['baseline'] != original['baseline']:
                raise ValueError('Original task baseline changed; never replace or infer it')
            lane = attempts.read()['lane']
            if (record['phase'] == 'STATIC_RUNNING' and lane and lane['state'] == 'ACTIVE'
                    and lane['scope_key'] == ref and self.now() < lane['expires_at']):
                return {'status': 'BUSY', 'task_ref': ref, 'scanner_run': False}
            hook_revision, marker, marker_error = self._hook_inputs(root, record)
            if (record.get('end') and end['hashes'] == record['end']['hashes']
                    and end['limitations'] == record['end']['limitations']
                    and end['inventory'] == record['end'].get('inventory', sorted(record['end']['hashes']))
                    and record['phase'] != 'STATIC_RUNNING'
                    and record.get('static', {}).get('status') != 'CANCELLED'
                    and record.get('finished_hook_revision') == hook_revision):
                return self._view(record)
            changes, unknown = task_changes(root, record['baseline'], end)
            # Independent tasks may share a checkout, never each other's verdict.
            # Conservatively retain a gap if editing intervals overlap; do not
            # infer exclusive attribution from a whole-workspace snapshot.
            overlaps=[v for v in self.store(root).records() if v['task_ref']!=record['task_ref'] and
                      v.get('closed_at',float('inf'))>record['created_at'] and v['created_at']<=self.now()]
            # Keep historical risk membership before staging a new current view.
            from .task_risk_ledger import TaskRiskLedger
            if record.get('end'):
                TaskRiskLedger(self.hooks, root).register(record)
            from .task_review_revisions import advance_revision
            record = advance_revision(record)
            # Delivery totals and the first review deadline survive refinish.
            record['lifetime_context_bytes'] = max(record.get('lifetime_context_bytes', 0), record.get('context_bytes', 0))
            record['lifetime_context_reads'] = record.get('lifetime_context_reads', 0) + len(record.get('evidence', {}))
            for key in ('packet', 'review_session', 'review_plan', 'review_completion', 'skip_reason'):
                record.pop(key, None)
            record.update(end=end, changes=changes, review=None, evidence={}, related_files=[],
                          context_bytes=record.get('review_ledger', {}).get('total_bytes', 0),
                          context_requests={}, context_gaps=[],
                          finished_hook_revision=hook_revision,
                          unverified_paths=unknown, limitations=record['baseline']['limitations']+end['limitations'])
            if changes and overlaps:
                record['limitations'].append({'reason':'CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE',
                    'count':len(overlaps)})
            # Hook checks may have found a pre-existing risk outside the final
            # net diff, or left an edited/reverted file pending. Re-evaluate
            # those CURRENT sources; historical alerts are never replayed as
            # evidence about this version.
            hook_paths, hook_excluded = set(), []
            marker_paths = (marker or {}).get('scope_files', [])
            if marker_error:
                record['limitations'].append({'reason': marker_error})
            if marker:
                record['limitations'].append({'reason': 'TASK_HOOK_RECORDING_FAILED',
                    'count': marker['failure_count'], 'paths': marker_paths[:100]})
                if not marker_paths or marker.get('scope_paths_omitted'):
                    record['limitations'].append({'reason': 'TASK_HOOK_FAILED_PATHS_UNKNOWN',
                        'count': marker.get('scope_paths_omitted', 0)})
            record['hook_recording_failure'] = dict(present=bool(marker), verified=not marker_error,
                failure_count=(marker or {}).get('failure_count', 0),
                failure_paths_unknown=bool(marker_error or (marker and (not marker_paths or marker.get('scope_paths_omitted')))))
            for value in set(record.get('hook_recheck_files', [])) | set(record.get('hook_pending_scope_files', [])) | set(marker_paths):
                try:
                    name = _relative(value)
                    if not _supported(name) or _environment(name) or name not in end['hashes']:
                        hook_excluded.append(name)
                    else:
                        hook_paths.add(name)
                except (ValueError, EvidenceUnavailable):
                    hook_excluded.append('[REJECTED_HOOK_PATH]')
            record['hook_final_recheck_files'] = sorted(hook_paths)
            if hook_excluded:
                record['limitations'].append({'reason': 'TASK_HOOK_CURRENT_SOURCE_UNAVAILABLE',
                                             'count': len(hook_excluded), 'paths': hook_excluded[:100]})
            omitted = {key: record[key] for key in ('hook_recheck_paths_omitted', 'hook_pending_paths_omitted',
                                                   'hook_checks_omitted') if record.get(key)}
            if omitted:
                record['limitations'].append({'reason': 'TASK_HOOK_LEDGER_SCOPE_INCOMPLETE', 'omitted': omitted})
            if unknown:
                record['limitations'].append({'reason': 'TASK_CHANGE_COMPARISON_UNAVAILABLE', 'count': len(unknown), 'paths': unknown[:100]})
            if not changes and not hook_paths:
                if unknown or record['limitations']:
                    message = ('部分文件修改检查记录失败或无法核验，失败路径未知；不能确认本次任务安全核查已完成。'
                               if record['hook_recording_failure']['failure_paths_unknown'] else
                               '文件盘点、开始版本或文件修改检查的保留范围不完整，无法确认本次检查范围。')
                    record.update(phase='INCOMPLETE', skip_reason=message)
                    record['baseline']['texts'] = {}
                    record['end']['texts'] = {}
                    return self._view(self.store(root).save(record))
                # A later edit still compares with this exact original baseline.
                record.update(phase='NO_CHANGES')
                return self._view(self.store(root).save(record))
            if record['static_attempts'] >= 2:
                record.update(phase='READY', static=dict(status='NOT_EXECUTED', coverage='UNKNOWN', findings=[], reason='TASK_STATIC_ATTEMPT_BUDGET'))
                return self._view(self.store(root).save(record))
            eligible = sorted(set(v['path'] for v in changes if not _environment(v['path'])) | hook_paths)
            scope = eligible[:MAX_STATIC_CHANGED]
            exclusions = [v['path'] for v in changes if _environment(v['path']) or v['path'] not in scope]
            if exclusions:
                record['limitations'].append({'reason': 'TASK_STATIC_SCOPE_EXCLUDED', 'count': len(exclusions), 'paths': exclusions[:MAX_CHANGED]})
            hook_over_budget = sorted(hook_paths-set(scope))
            if hook_over_budget:
                record['limitations'].append({'reason': 'TASK_HOOK_FINAL_SCOPE_BUDGET',
                                             'count': len(hook_over_budget), 'paths': hook_over_budget[:100]})
            lease = attempts.claim('TASK', ref, source_binding(dict(task_ref=ref,
                end_hashes=end['hashes'], auxiliary_hashes=auxiliary_hashes,
                scope=scope, hook_revision=hook_revision)), owner=self._owner())
            if lease is None:
                return {'status': 'BUSY', 'task_ref': ref, 'scanner_run': False}
            record.update(phase='STATIC_RUNNING', static_attempts=record['static_attempts']+1,
                          static_execution=lease.receipt)
            try:
                record = self.store(root).save(record)
            except BaseException:
                attempts.finish(lease, outcome='FAILED')
                raise
        def validate_input(view):
            view.assert_intact()
            entries = {entry.path:entry for entry in view.manifest if entry.role in {'TARGET','CONTEXT'}}
            for name, expected in auxiliary_hashes.items():
                if (name in entries) != (expected is not None):
                    return False
            for name in entries:
                expected = end['hashes'].get(name, auxiliary_hashes.get(name))
                if expected is None or hash_bytes((view.execution_root/name).read_bytes()) != expected:
                    return False
            for name in scope:
                expected = end['hashes'].get(name)
                if expected is None:
                    if name not in view.request.absent_files:
                        return False
                elif hash_bytes((view.execution_root/name).read_bytes()) != expected:
                    return False
            return True
        execution = ScanAttemptExecution(attempts, lease, validator=validate_input, progress=current_reporter())
        started = time.perf_counter()
        try:
            if scope:
                from .dependency_inputs import is_dependency_input
                try:
                    engine = self.runtime() if callable(self.runtime) else self.runtime
                    from .scan_input import scoped_request
                    result = engine.scan(root, mode='quick', request=scoped_request(root, scope,
                        dependency_changes=[p for p in scope if is_dependency_input(p)]), execution=execution)
                    if execution.input_id is None:
                        raise ScanAttemptLost('SCAN_ATTEMPT_INPUT_NOT_BOUND')
                    # Scanner labels/proof originate only from Runtime.
                    record['static'] = dict(scan_id=result.scan_id, status=result.status, coverage=result.coverage,
                        scope_files=scope, actual_files=result.target_profile.files,
                        scanner_runs=[asdict(r) for r in result.scanner_runs],
                        rule_coverage=result.rule_coverage, findings=[asdict(f) for f in result.findings],
                        capability_results=result.capability_results)
                except ScanCancelled:
                    raise
                except Exception:
                    record['static'] = dict(status='FAILED', coverage='UNKNOWN', scope_files=scope, findings=[], reason='TASK_STATIC_CHECK_FAILED')
            else:
                record['static'] = dict(status='NOT_EXECUTED', coverage='UNKNOWN', scope_files=[], findings=[], reason='NO_ELIGIBLE_STATIC_FILES')
            record['static']['duration_ms'] = round((time.perf_counter()-started)*1000)
            fresh = self._fresh(root, record)  # Expensive task inventory outside the lock.
            with self.hooks.lock(root, wait_seconds=2) as acquired:
                if not acquired:
                    return dict(status='BUSY', task_ref=ref, scanner_run=False,
                                reason='SCAN_ATTEMPT_PUBLICATION_PENDING')
                if not attempts.is_current(lease, execution.input_id):
                    raise ScanAttemptLost('SCAN_ATTEMPT_SUPERSEDED')
                current = self.load(root, ref)
                require_record_protocol(current)
                if (current.get('static_execution') != lease.receipt
                        or current['phase'] != 'STATIC_RUNNING'
                        or current['end']['hashes'] != end['hashes']):
                    attempts.finish(lease, input_id=execution.input_id, outcome='STALE')
                    return dict(status='STALE', task_ref=ref, scanner_run=False,
                                reason='SCAN_ATTEMPT_SUPERSEDED')
                # Preserve Hook arrivals and any newer metadata, never save an
                # old whole-record copy after the unlocked worker completes.
                current['static'] = record['static']
                current['phase'] = ('READY' if fresh and self._hook_inputs(root,current)[0]
                                    == current['finished_hook_revision'] else 'STALE')
                if (current['phase'] == 'READY' and not changes and not current['limitations']
                        and not current['static']['findings'] and current['static']['coverage'] in {'FULL', 'SCOPED'}
                        and current['static']['status'] in {'SUCCESS', 'COMPLETED'}):
                    current['phase'] = 'NO_CHANGES'
                    current['baseline']['texts'] = {}
                    current['end']['texts'] = {}
                current['static']['execution_attempt'] = dict(execution.receipt,
                    publication='STALE' if current['phase']=='STALE' else 'COMMITTED')
                try:
                    current = self._project_risks(root, current)
                finally:
                    attempts.finish(lease, input_id=execution.input_id,
                        scan_id=record['static'].get('scan_id'),
                        outcome='STALE' if current['phase']=='STALE' else 'COMPLETED')
                view = self._view(current)
                view['scanner_run'] = any(r.get('status') in {'SUCCESS','FAILED','TIMEOUT'}
                                          for r in current['static'].get('scanner_runs', []))
                return view
        except (ScanCancelled, KeyboardInterrupt):
            with self.hooks.lock(root, wait_seconds=2) as acquired:
                if acquired:
                    current = self.load(root, ref)
                    if current.get('static_execution') == lease.receipt and current['phase'] == 'STATIC_RUNNING':
                        current.update(phase='STALE', static=dict(status='CANCELLED', coverage='UNKNOWN',
                            findings=[], scope_files=scope, reason='SCAN_ATTEMPT_CANCELLED'))
                        self.store(root).save(current)
                    attempts.cancel(lease)
            raise
        except Exception:
            # A source/storage failure must not leave a live lane until timeout.
            # Do not overwrite a replacement worker or publish partial evidence.
            with self.hooks.lock(root, wait_seconds=2) as acquired:
                if acquired and attempts.is_current(lease):
                    current = self.load(root, ref)
                    if current.get('static_execution') == lease.receipt and current['phase'] == 'STATIC_RUNNING':
                        current.update(phase='STALE', static=dict(status='FAILED', coverage='UNKNOWN',
                            findings=[], scope_files=scope, reason='SCAN_ATTEMPT_PUBLICATION_FAILED'))
                        self.store(root).save(current)
                    attempts.finish(lease, input_id=execution.input_id, outcome='FAILED')
            raise

    def prepare(self, workspace, ref, protocol_version=PROTOCOL_VERSION):
        validate_protocol(protocol_version)
        from .task_review import TaskReviewCoordinator
        return TaskReviewCoordinator(self).prepare(workspace, ref, protocol_version=protocol_version)

    def _session(self, root, ref, session, *, full_fresh=True):
        record = self.load(root, ref)
        require_record_protocol(record)
        if record['phase'] != 'REVIEWING' or session != record.get('review_session'):
            from .task_review_plan import ReviewPlanError
            raise ReviewPlanError('REVIEW_PLAN_SESSION_MISMATCH',
                'Review session unavailable; keep the original task and current revision session')
        if self.now() > record['review_deadline']:
            raise ValueError('Review activity lease expired; prepare protocol_version=3 to resume this exact snapshot and ledger')
        if full_fresh and not self._fresh(root, record):
            raise ValueError('Task source or Hook scope changed; submitted evidence is stale')
        if not full_fresh and self._hook_inputs(root, record)[0] != record.get('finished_hook_revision'):
            raise ValueError('Task Hook scope changed; submitted evidence is stale')
        return record

    def read(self, workspace, ref, session, path, start_line=1, end_line=80, source_version='CURRENT'):
        from .task_review import TaskReviewCoordinator
        return TaskReviewCoordinator(self).read(workspace, ref, session, path, start_line, end_line, source_version)

    def _context_gap(self, root, record, reason_code, path):
        gap = dict(reason=reason_code, path=path)
        gaps = record.setdefault('context_gaps', [])
        if gap not in gaps and len(gaps) < record['review_ledger']['limits']['reads']:
            gaps.append(gap)
        self.store(root).save(record)

    def review_plan(self, workspace, ref, session, cursor=0, limit=10):
        from .task_review import TaskReviewCoordinator
        return TaskReviewCoordinator(self).page(workspace, ref, session, cursor, limit)

    def review_method(self, workspace, ref, session):
        from .task_review import TaskReviewCoordinator
        return TaskReviewCoordinator(self).method(workspace, ref, session)

    def submit_batch(self, workspace, ref, session, unit_ids, coverage, limitations):
        from .task_review import TaskReviewCoordinator
        return TaskReviewCoordinator(self).submit_batch(workspace, ref, session, unit_ids, coverage, limitations)

    def submit(self, workspace, ref, session, findings, coverage, limitations, risk_resolutions=None):
        root = self.root(workspace)
        require_record_protocol(self.load(root, ref))
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY'}
            old = self.load(root, ref)
            require_record_protocol(old)
            from .task_projection import drain
            old = drain(self, root, old)
            if old['phase'] == 'COMPLETE' and old.get('review_session') == session:
                return self.get(workspace, ref)  # idempotent retry; no scan/model.
            record = self._session(root, ref, session)
            from .task_review_contract import validate_task_review_body, evidence_error, TaskReviewInputError
            body = validate_task_review_body(findings, coverage, limitations)
            findings, coverage, limitations = body['findings'], body['coverage'], body['limitations']
            clean_limitations = [_clean(v, 500) for v in limitations]
            if coverage == 'PARTIAL' and not clean_limitations:
                raise TaskReviewInputError([dict(field='limitations', code='REQUIRED_FOR_PARTIAL',
                    correction='PARTIAL 必须列出实际未完成范围或缺少的上下文。')])
            fields = {'title','category','severity','primary_evidence','evidence_refs','impact','preconditions','unknowns','counterevidence','fix_advice'}
            optional_fields = {'risk_scope', 'task_evidence', 'current_protections'}
            accepted = []
            scope = record['changes']
            changed = {v['path'] for v in scope}
            for index, candidate in enumerate(findings):
                if not isinstance(candidate, dict) or not fields <= set(candidate) or set(candidate) - fields - optional_fields:
                    raise ValueError('Use the task candidate schema; scanner proof and authority fields are forbidden')
                refs = candidate['evidence_refs']
                primary = candidate['primary_evidence']
                if not isinstance(refs, list) or not 1 <= len(refs) <= 10 or any(not isinstance(e, str) or e not in record['evidence'] for e in refs) or not isinstance(primary, str) or primary not in refs:
                    raise evidence_error(index, 'evidence_refs', 'EVIDENCE_NOT_ISSUED',
                        '只使用原任务当前复核版本实际读取返回的 evidence_id 字符串，且 primary_evidence 必须包含在 evidence_refs 中。')
                location = record['evidence'][primary]
                if location['location_version'] == 'BEFORE_TASK':
                    raise evidence_error(index, 'primary_evidence', 'HISTORICAL_LOCATION',
                        '当前风险的主证据不能使用 BEFORE_TASK；引用实际读取的当前代码证据。')
                risk_scope = candidate.get('risk_scope', 'TASK_CHANGED')
                if risk_scope not in {'TASK_CHANGED', 'RELATED_EXISTING'}:
                    raise ValueError('Invalid task risk scope')
                task_evidence = candidate.get('task_evidence', primary)
                if (not isinstance(task_evidence, str) or task_evidence not in refs
                        or record['evidence'][task_evidence]['path'] not in changed):
                    raise evidence_error(index, 'task_evidence', 'TASK_CHANGED_EVIDENCE_REQUIRED',
                        '引用原任务当前复核版本已读取的改动文件 evidence_id 字符串，并将它包含在 evidence_refs 中。')
                if risk_scope == 'TASK_CHANGED' and location['path'] not in changed:
                    raise evidence_error(index, 'primary_evidence', 'TASK_CHANGED_LOCATION_REQUIRED',
                        'TASK_CHANGED 的主证据须来自任务改动文件；关联现有风险按 RELATED_EXISTING 契约提交。')
                if risk_scope == 'RELATED_EXISTING' and (location['path'] not in record['related_files']
                        or location['path'] in changed or location['location_version'] != 'CURRENT_TASK_END'):
                    raise evidence_error(index, 'primary_evidence', 'CURRENT_RELATED_LOCATION_REQUIRED',
                        'RELATED_EXISTING 的主证据须来自当前已读取、未修改的关联文件。')
                protections = candidate.get('current_protections', candidate['counterevidence'])
                if not isinstance(protections, list) or len(protections) > 10:
                    raise ValueError('Invalid current protections')
                if risk_scope == 'RELATED_EXISTING' and (not candidate.get('preconditions')
                        or not candidate.get('unknowns') or 'current_protections' not in candidate):
                    raise TaskReviewInputError([dict(field=f'findings[{index}].{field}',
                        code='RELATED_EXISTING_FIELD_REQUIRED',
                        correction='RELATED_EXISTING 须说明实际触发条件、未知范围和当前防护；不编造缺少的事实。')
                        for field in ('preconditions', 'unknowns', 'current_protections')
                        if not candidate.get(field) and (field != 'current_protections' or field not in candidate)])
                if candidate['severity'] not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
                    raise ValueError('Invalid candidate severity')
                item = {k: _clean(candidate[k], 1200) for k in ('title','category','impact','fix_advice')}
                for field in ('preconditions','unknowns','counterevidence'):
                    values = candidate[field]
                    if not isinstance(values, list) or len(values) > 10:
                        raise ValueError('Invalid candidate conditions or counterevidence')
                    item[field] = [_clean(v, 500) for v in values]
                item.update(id='tc1-'+digest_value([ref, candidate])[:32], severity=candidate['severity'],
                    risk_scope=risk_scope, task_evidence=task_evidence,
                    current_protections=[_clean(v, 500) for v in protections],
                    evidence_locations=[dict(evidence_ref=e, **{k: record['evidence'][e][k]
                        for k in ('path', 'start_line', 'end_line', 'location_version')}) for e in dict.fromkeys(refs)],
                    file_path=location['path'], line_start=location['start_line'], line_end=location['end_line'],
                    location_version=location['location_version'],
                    evidence_refs=list(dict.fromkeys(refs)), source='HOST_TASK_REVIEW', validation='STRUCTURE_AND_VERSION_VALIDATED',
                    verdict='CANDIDATE_REQUIRES_REVIEW', scanner_sources=[])
                accepted.append(item)
            unread = _unread_context(record)
            if unread:
                coverage = 'PARTIAL'
                # Bound display, but preserve all spans in the signed record.
                clean_limitations.append('已请求的源码范围尚未读完：'+
                    '；'.join(f"{v['path']}:{v['start_line']}-{v['end_line']}" for v in unread[:10])+
                    (f'；另有 {len(unread)-10} 个范围' if len(unread)>10 else '')+'。')
            if record.get('context_gaps'):
                coverage = 'PARTIAL'
                clean_limitations.append('源码上下文受限：'+
                    '；'.join(f"{v['path']} ({v['reason']})" for v in record['context_gaps'][:10])+'。')
            if record['limitations']:
                coverage = 'PARTIAL'
                clean_limitations.extend(_coverage_gaps(record['limitations']))
            from .task_review_plan import finalize_plan
            completion = finalize_plan(record, now=self.now())
            record['review_completion'] = completion
            if completion['coverage'] != 'REVIEWED':
                coverage = 'PARTIAL'
                gaps = completion['gaps']
                from .task_review_results import semantic_gap_notes
                clean_limitations = list(dict.fromkeys(semantic_gap_notes(gaps)+clean_limitations))
                clean_limitations.append(f"逐文件复核完成 {completion['reviewed_unit_count']}/{completion['unit_count']} 项；未完成："+
                    '、'.join(dict.fromkeys(v.get('path', '未知路径') for v in gaps[:10]))+'。')
            from .task_risk_ledger import TaskRiskLedger
            ledger = TaskRiskLedger(self.hooks, root)
            for item in risk_resolutions or []:
                if not isinstance(item, dict) or not isinstance(item.get('original_task_ref'), str):
                    raise ValueError('Invalid original risk reference')
                original_record = self.load(root, item['original_task_ref'])
                if not original_record.get('end'):
                    raise ValueError('Original task was never checked')
                ledger.register(original_record)
            updates = ledger.validate_host(record, risk_resolutions or [], coverage)
            record.update(phase='COMPLETE', review=dict(source='HOST_TASK_REVIEW', coverage=coverage,
                findings=accepted, limitations=clean_limitations, model_invocation='HOST_ONLY_NOT_OBSERVED_BY_RUNTIME',
                validation='STRUCTURE_AND_SOURCE_VERSION_ONLY', method_sha256=record['packet']['quick_skill']['sha256'],
                elapsed_wall_ms=round((self.now()-record.get('review_started_at', record['review_deadline']-REVIEW_TTL))*1000),
                submitted_at=self.now()))
            # Further edits stay in this task. Retain the original sanitized
            # preimages until their original TTL, never recapture after editing.
            record['end']['texts'] = {}
            record.pop('packet', None)
            from .task_review import TaskReviewCoordinator
            result_packet = TaskReviewCoordinator(self).completion_packet(record, reserve_projection_sync=True)
            record = self._project_risks(root, record, updates)
            from .task_projection import status as projection_status
            result_packet['risk_ledger_sync'] = projection_status(record)
            return result_packet

    def get(self, workspace, ref, finding_offset=0, finding_limit=20):
        if type(finding_offset) is not int or type(finding_limit) is not int or finding_offset < 0 or not 1 <= finding_limit <= 30:
            raise ValueError('Invalid result page')
        root = self.root(workspace)
        record = self.load(root, ref,read_only=True)
        from .task_review_results import bounded_history_result, history_freshness, seal_history_result
        current = capture(root, known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                          priority_paths=(record.get('end') or {}).get('read_priority', ()), include_text=False)
        revision = self._hook_inputs(root, record)[0] if record.get('finished_hook_revision') else None
        freshness = history_freshness(record, current, hook_revision=revision)
        from .task_risk_feedback import feedback_for_record
        feedback = feedback_for_record(self.hooks, root, record)
        result = bounded_history_result(record, finding_offset, finding_limit,
                                        now=self.now(), freshness=freshness, feedback=feedback)
        result['risk_ledger_next_action'] = dict(tool='get_task_risk_ledger', task_ref=ref)
        from .task_projection import status as projection_status
        result['risk_ledger_sync'] = projection_status(record)
        return seal_history_result(result)

    def risk_ledger(self, workspace, ref, offset=0, limit=30):
        root = self.root(workspace)
        original = self.load(root, ref,read_only=True)  # Historical reads never transfer ownership.
        from .task_risk_ledger import TaskRiskLedger
        result = TaskRiskLedger(self.hooks, root).view(ref, offset, limit, original)
        from .task_projection import status as projection_status
        result['risk_ledger_sync'] = projection_status(original)
        return result

    def skip(self, workspace, ref, reason):
        """Finish with an explicit coverage gap, never a fabricated host pass.

        State-only CAS permits a host to finish its response even when a scan
        is busy. A concurrent runner cannot overwrite this terminal record.
        """
        root = self.root(workspace)
        record = self.load(root, ref)
        require_record_protocol(record)
        if record['phase'] in {'COMPLETE','NO_CHANGES','INCOMPLETE'}:
            return self._view(record)
        reason = _clean(reason, 500)
        record.update(phase='INCOMPLETE', skip_reason=reason)
        record['baseline']['texts'] = {}
        if record.get('end'):
            record['end']['texts'] = {}
        record.pop('packet', None)
        saved = self.store(root).save(record)
        self.discard_preimages(root, ref)
        return self._view(saved)

    def _current_handling(self, record):
        """Read current handling independently of the immutable task report."""
        root = Path(record['workspace'])
        from .task_risk_feedback import feedback_for_record
        host = feedback_for_record(self.hooks, root, record)
        static = {}
        scan_id = (record.get('static') or {}).get('scan_id')
        if scan_id:
            engine = self.runtime() if callable(self.runtime) else self.runtime
            scan_store = getattr(engine, 'store', None)
            if scan_store is not None and scan_store.get_scan(scan_id):
                from .finding_feedback import FindingFeedbackService
                static = FindingFeedbackService(scan_store, root).presentations(scan_id)
        return host, static

    def _view(self, record):
        phase = record['phase']
        result = dict(status=phase, task_ref=record['task_ref'], scanner_run=False,
            task_scope=('HOST_SESSION' if (record.get('task_owner') or {}).get('host') in {'cursor','codex'} else
                        'MCP_CONNECTION' if record.get('task_owner') else 'LEGACY_UNOWNED'),
            review_protocol=record.get('review_protocol'),
            review_required=is_v3_record(record) and phase in {'READY','REVIEWING'}, changes=record.get('changes', [])[:MAX_CHANGED],
            changed_file_count=len(record.get('changes', [])), change_scope_truncated=len(record.get('changes', []))>MAX_CHANGED,
            unverified_file_count=len(record.get('unverified_paths', [])),
            baseline_file_count=len(record['baseline']['hashes']), limitations=record.get('limitations') or record['baseline']['limitations'],
            static=None, host_review=record.get('review'), repair_authorized=False)
        from .task_projection import status as projection_status
        result['risk_ledger_sync'] = projection_status(record)
        result['snapshot_capture'] = dict(baseline=record['baseline'].get('capture_stats'),
            current=(record.get('end') or {}).get('capture_stats'))
        if record.get('native_repair'):
            import copy
            result['native_repair'] = {key: copy.deepcopy(record['native_repair'][key]) for key in
                ('source', 'assessment_ref', 'proposal_revision', 'source_binding')}
            result['native_repair']['repair_authorized'] = False
        if is_v3_record(record):
            result['review_revision'] = record.get('review_revision', 1)
            result['previous_review_count'] = len(record.get('review_history', []))
        host_feedback, static_feedback = {}, {}
        try:
            host_feedback, static_feedback = self._current_handling(record)
        except (OSError, ValueError):
            # A failed read cannot turn a past user choice into a new repair ask.
            result['handling_unavailable'] = True
        def pending(findings, feedback):
            if result.get('handling_unavailable'):
                return []
            return [f for f in findings if not feedback.get(f['id'], {}).get(
                'reminder_suppressed', feedback.get(f['id'], {}).get('folded', False))]
        current_host = pending((record.get('review') or {}).get('findings', []), host_feedback)
        current_static = pending((record.get('static') or {}).get('findings', []), static_feedback)
        from .risk_decision_guidance import handling_counts, PRIMARY_CHOICES, SECONDARY_CHOICES
        feedback = {'host:'+f['id']:host_feedback.get(f['id'], {})
                    for f in (record.get('review') or {}).get('findings', [])}
        feedback.update({'scanner:'+f['id']:static_feedback.get(f['id'], {})
                         for f in (record.get('static') or {}).get('findings', [])})
        result['risk_handling'] = dict(handling_counts(feedback),
            raw_finding_count=len((record.get('static') or {}).get('findings', [])) +
                              len((record.get('review') or {}).get('findings', [])),
            pending_finding_count=len(current_host)+len(current_static),
            raw_findings_preserved=True, repair_authorized=False)
        result['risk_handling']['counts_available'] = not result.get('handling_unavailable', False)
        if result.get('handling_unavailable'):
            # Unknown persisted choices are not zero pending risks or confirmed exclusions.
            for key in ('pending', 'deferred', 'excluded_by_user', 'excluded_by_agent', 'resolved',
                        'pending_finding_count'):
                result['risk_handling'][key] = None
            result['risk_handling']['unknown_finding_count'] = len(feedback)
        result['risk_choices'] = [dict(finding_id=f['id'], title=f['title'],
            options=list(PRIMARY_CHOICES), secondary_options=list(SECONDARY_CHOICES),
            deferred_keeps_risk=True, repair_authorized=False) for f in current_host]
        result['file_hook_checks'] = dict(check_count=len(record.get('hook_checks', [])),
            omitted_check_count=record.get('hook_checks_omitted', 0),
            current_recheck_files=record.get('hook_final_recheck_files', [])[:100],
            current_recheck_file_count=len(record.get('hook_final_recheck_files', [])),
            findings_source='FINAL_CURRENT_STATIC_CHECK; HISTORICAL_HOOK_ALERTS_NOT_REPLAYED',
            recording_failure=record.get('hook_recording_failure'))
        unread = _unread_context(record)
        budget = record.get('review_ledger') or {}
        limits = budget.get('limits') or {}
        result['context_read_coverage'] = dict(unread_range_count=len(unread), unread_ranges=unread[:100],
            gaps=record.get('context_gaps', []), used_reads=budget.get('reads'),
            max_reads=limits.get('reads'), used_bytes=budget.get('total_bytes'),
            max_bytes=limits.get('total_bytes'))
        if is_v3_record(record) and record.get('review_plan'):
            from .task_review_plan import finalize_plan
            progress = record.get('review_completion') or finalize_plan(record, now=self.now())
            result['review_progress'] = {k:progress[k] for k in ('unit_count','reviewed_unit_count','coverage','status')}
            used = record['review_ledger']
            result['context_read_coverage'].update(used_bytes=used['total_bytes'], max_bytes=used['limits']['total_bytes'],
                used_reads=used['reads'], max_reads=used['limits']['reads'])
        if record.get('static'):
            static = record['static']
            result['static'] = {key: static[key] for key in ('scan_id','status','coverage','scope_files','actual_files','duration_ms','reason','capability_results') if key in static}
            result['static'].update(finding_count=len(static['findings']), findings=[finding_view(f) for f in static['findings'][:20]],
                has_more=len(static['findings'])>20,
                scanner_runs=[{k: r[k] for k in ('scanner','version','status','duration_ms','error_code','coverage_contract') if k in r}
                              for r in static.get('scanner_runs', [])])
        from .reply_adapters import task_facts
        from .reply_plan import plan_reply
        from .reply_render import render_reply
        plan = plan_reply(task_facts(record, host_feedback, static_feedback,
                                    handling_available=not result.get('handling_unavailable')))
        result['reply_plan'] = plan.to_dict()
        result['development_summary'] = render_reply(plan)
        if plan.check.state == 'CAPACITY_REQUIRED':
            result.update(status='CAPACITY_REQUIRED', review_required=False,
                          review_capacity=record['review_capacity'])
        return result

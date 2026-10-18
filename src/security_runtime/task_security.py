"""Task-bound static checks and bounded host reasoning before the dev summary.

No model, source edits, installs, builds or Stop continuation inside Runtime.
"""
from __future__ import annotations

from dataclasses import asdict
import difflib
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
from .task_snapshot import (SnapshotPolicy, collect_snapshot,
                            MAX_READ_BYTES, MAX_INLINE_TEXT_BYTES as MAX_PREIMAGE_BYTES,
                            MAX_INVENTORY_PATHS, MAX_INVENTORY_NAME_BYTES,
                            MAX_INVENTORY_DIRECTORIES, MAX_INVENTORY_DEPTH)
from .target import DEPENDENCIES, EXTENSIONS, IGNORED
from .workspace import WorkspaceResolver

MAX_FILES = SnapshotPolicy().max_files
MAX_CHANGED = 20
MAX_STATIC_CHANGED = 1000
MAX_RELATED = 10



MAX_CONTEXT = 64_000
MAX_DIFF_LINES = 2000
MAX_CONTEXT_READS = 40
MAX_CONTEXT_WINDOW_LINES = 80
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


def method(protocol_version=1):
    if type(protocol_version) is not int or protocol_version not in {1, 2, 3}:
        raise ValueError('Unsupported task review protocol')
    name = 'quick-task-review.md' if protocol_version == 1 else f'quick-task-review-v{protocol_version}.md'
    path = Path(__file__).parent / 'skills/ai-security-review/references' / name
    content = path.read_text(encoding='utf-8')
    return dict(version=f'quick-task-review-v{protocol_version}', sha256=hash_bytes(content.encode()), content=content)


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
        from .task_ownership import valid_owner, record_owner, writer_identity, writer_gone
        owner=self._owner() if _owner is None else _owner
        if owner is not None and not valid_owner(owner):
            raise ValueError('Invalid connector owner')
        root = self.root(workspace)
        # Project preparation publishes its seed under the same short lock.
        # Give that publication time to finish; never begin an unbound fallback
        # task merely because the first edit happened during initialization.
        with self.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'scanner_run': False}
            self.hooks.key(root)
            store = self.store(root)
            native = None
            if owner is not None:
                from .native_repair_intent import NativeRepairIntents
                native = NativeRepairIntents(self.hooks, root, owner, now=self.now)
                blocked = native.guard(_native_preparation)
                if blocked is not None:
                    return blocked
                intent = native.get()
                if _native_preparation is not None and intent.get('repair_task_ref'):
                    original = self.load(root, intent['repair_task_ref'])
                    if original.get('native_repair') != _native_preparation:
                        raise ValueError('NATIVE_REPAIR_TASK_MISMATCH')
                    return self._view(original)
                if _native_preparation is not None:
                    # Recover a task published before a process stopped between
                    # the signed baseline save and the independent intent bind.
                    candidates = [old for old in store.records(active=True)
                        if record_owner(old) == owner and old.get('native_repair') == _native_preparation]
                    if len(candidates) > 1:
                        raise ValueError('NATIVE_REPAIR_TASK_AMBIGUOUS')
                    if candidates:
                        native.bind(candidates[0]['task_ref'])
                        return self._view(candidates[0])
            elif _native_preparation is not None:
                raise ValueError('NATIVE_REPAIR_OWNER_REQUIRED')
            # Expiration alone never establishes a dead owner. Keep all evidence
            # and risks; only a confirmed ended writer plus an expired lease retires.
            for old in store.records(active=True):
                if (old.get('review_protocol') != 3
                        and old.get('lease_until',float('inf'))<self.now() and writer_gone(old.get('writer'))):
                    old.update(phase='INCOMPLETE',skip_reason='原任务运行进程已结束，检查未完成；历史风险与检查记录保留。')
                    old['baseline']['texts']={}
                    if old.get('end'): old['end']['texts']={}
                    old.pop('packet',None)
                    store.save(old)
                    self.discard_preimages(root, old['task_ref'])
            existing = store.get(task_key=self.key(task_key,owner))
            if existing:
                if _native_preparation is not None:
                    if existing.get('native_repair') != _native_preparation:
                        raise ValueError('NATIVE_REPAIR_TASK_KEY_CONFLICT')
                    native.bind(existing['task_ref'])
                return self._view(existing)
            active = store.get(active=True,owner=owner)
            if (active and active.get('review_protocol') != 3 and active['phase'] == 'REVIEWING'
                    and self.now() > active['review_deadline']):
                active.update(phase='INCOMPLETE')
                active['baseline']['texts'] = {}
                active['end']['texts'] = {}
                active.pop('packet', None)
                store.save(active)
                self.discard_preimages(root, active['task_ref'])
                active = None
            if active and owner is None:
                # Avoid silently joining another editing task. The host may
                # resume the exact ref, or finish it, then begin the next one.
                return dict(status='ACTIVE_TASK_EXISTS', scanner_run=False)
            ref = 'ts1-'+uuid.uuid4().hex
            with self.preimages(root).writer(ref) as writer:
                baseline = capture(root, preimage_writer=writer,
                    priority_paths=tuple(_native_preparation['source_hashes']) if _native_preparation else ())
            if _native_preparation is not None and not all(
                    baseline['hashes'].get(name) == sha
                    for name, sha in _native_preparation['source_hashes'].items()):
                self.discard_preimages(root, ref)
                raise ValueError('NATIVE_REPAIR_BASELINE_MISMATCH')
            record = dict(contract=CONTRACT, task_ref=ref, task_key=self.key(task_key,owner),
                workspace=str(root), generation=0, phase='ACTIVE', created_at=self.now(),
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
            record = store.save(record, new=True)
            if _native_preparation is not None:
                native.bind(record['task_ref'])
            return self._view(record)

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

    def finish(self, workspace, ref):
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'task_ref': ref, 'scanner_run': False}
            record = self.load(root, ref)
            end = capture(root, known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                          priority_paths=record.get('end', {}).get('read_priority', ()), include_text=False)
            hook_revision, marker, marker_error = self._hook_inputs(root, record)
            if (record.get('end') and end['hashes'] == record['end']['hashes']
                    and end['limitations'] == record['end']['limitations']
                    and end['inventory'] == record['end'].get('inventory', sorted(record['end']['hashes']))
                    and record['phase'] != 'STATIC_RUNNING'
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
                          context_bytes=(record.get('review_ledger', {}).get('total_bytes', 0)
                                         if record.get('review_protocol') == 3 else 0),
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
            record.update(phase='STATIC_RUNNING', static_attempts=record['static_attempts']+1)
            record = self.store(root).save(record)
            started = time.perf_counter()
            if scope:
                from .dependency_inputs import is_dependency_input
                try:
                    engine = self.runtime() if callable(self.runtime) else self.runtime
                    result = engine.scan(root, mode='quick', _hook_scope=scope,
                        _hook_dependency_changes=[p for p in scope if is_dependency_input(p)])
                    # Scanner labels/proof originate only from Runtime.
                    record['static'] = dict(scan_id=result.scan_id, status=result.status, coverage=result.coverage,
                        scope_files=scope, actual_files=result.target_profile.files,
                        scanner_runs=[asdict(r) for r in result.scanner_runs],
                        rule_coverage=result.rule_coverage, findings=[asdict(f) for f in result.findings],
                        capability_results=result.capability_results)
                except Exception:
                    record['static'] = dict(status='FAILED', coverage='UNKNOWN', scope_files=scope, findings=[], reason='TASK_STATIC_CHECK_FAILED')
            else:
                record['static'] = dict(status='NOT_EXECUTED', coverage='UNKNOWN', scope_files=[], findings=[], reason='NO_ELIGIBLE_STATIC_FILES')
            record['static']['duration_ms'] = round((time.perf_counter()-started)*1000)
            record['phase'] = 'READY' if self._fresh(root, record) else 'STALE'
            if (record['phase'] == 'READY' and not changes and not record['limitations']
                    and not record['static']['findings'] and record['static']['coverage'] in {'FULL', 'SCOPED'}
                    and record['static']['status'] in {'SUCCESS', 'COMPLETED'}):
                record['phase'] = 'NO_CHANGES'
                record['baseline']['texts'] = {}
                record['end']['texts'] = {}
            record = self.store(root).save(record)
            from .task_risk_ledger import TaskRiskLedger
            TaskRiskLedger(self.hooks, root).register(record)
            view = self._view(record)
            view['scanner_run'] = any(r.get('status') in {'SUCCESS','FAILED','TIMEOUT'} for r in record['static'].get('scanner_runs', []))
            return view

    def prepare(self, workspace, ref, protocol_version=1):
        if type(protocol_version) is not int or protocol_version not in {1, 2, 3}:
            raise ValueError('Unsupported task review protocol')
        if protocol_version in {2, 3}:
            from .task_review import TaskReviewCoordinator
            return TaskReviewCoordinator(self).prepare(workspace, ref, protocol_version=protocol_version)
        root = self.root(workspace)
        # Only the never-finished ACTIVE task may perform its first closeout.
        # Release/no lock here: finish owns the normal lock and attempt guard.
        initial = self.load(root, ref)
        if initial.get('review_protocol', 1) != 1:
            raise ValueError('A prepared task keeps its original review protocol and budgets')
        if initial['phase'] == 'STATIC_RUNNING':
            return dict(status='BUSY', task_ref=ref, scanner_run=False, message='任务末检查正在进行，保留原任务；不要重复检查。')
        if initial['phase'] == 'INCOMPLETE':
            return self._view(initial)
        if initial['phase'] == 'ACTIVE':
            finished = self.finish(workspace, ref)
            if finished['status'] not in {'READY', 'NO_CHANGES'}:
                return finished
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'task_ref': ref}
            record = self.load(root, ref)
            if record['phase'] == 'NO_CHANGES':
                return self._view(record)
            if record['phase'] not in {'READY', 'REVIEWING', 'COMPLETE'} or not self._fresh(root, record):
                return {'status': 'STALE', 'task_ref': ref, 'review_required': False, 'message': '代码版本或文件修改检查范围已变化，或基础检查未完成；保留缺口，不循环扫描。'}
            if record['phase'] == 'COMPLETE':
                return self._view(record)
            if record.get('packet') and self.now() <= record.get('review_deadline', 0):
                return dict(record['packet'], review_session=record['review_session'])
            if record.get('packet'):
                return {'status': 'EXPIRED', 'task_ref': ref, 'review_required': False}
            guide = method()
            diffs, remaining = [], MAX_DIFF_LINES
            for change in record['changes'][:MAX_CHANGED]:
                name = change['path']
                if _environment(name):
                    continue
                before_truncation = record['baseline'].get('text_truncations', {}).get(name, {})
                after_truncation = record['end'].get('text_truncations', {}).get(name, {})
                if before_truncation or after_truncation:
                    record['limitations'].append(dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET',
                        before_line_count=before_truncation.get('line_count', 0),
                        after_line_count=after_truncation.get('line_count', 0)))
                from .task_preimages import TaskPreimageUnavailable as PreimageError
                try:
                    old = self.before_lines(root, record, name) if change['change'] != 'ADDED' else []
                    new = self.end_lines(root, record, name) if change['change'] != 'DELETED' else []
                except (OSError, EvidenceUnavailable, PreimageError, UnicodeError):
                    old, new = None, None
                if change['change'] == 'ADDED':
                    old = []
                if change['change'] == 'DELETED':
                    new = []
                if old is None or new is None:
                    diffs.append({'path': name, 'change': change['change'], 'availability': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'})
                    record['limitations'].append({'path': name, 'reason': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'})
                    continue
                if record['end'].get('text_truncations', {}).get(name) and not any(
                        v.get('path') == name and v.get('reason') == 'SOURCE_LINE_CHAR_BUDGET' for v in record['limitations']):
                    record['limitations'].append(dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET'))
                # Long tests are retrieved as issued windows, rather than
                # duplicating their entire added text in both diff and reads.
                if ('tests' in Path(name).parts or Path(name).name.startswith('test_')) and len(old)+len(new) > 80:
                    spans = _merge_spans([[max(1,j1-2), min(len(new),max(j1+1,j2)+3)]
                        for tag,i1,i2,j1,j2 in difflib.SequenceMatcher(None,old,new).get_opcodes()
                        if tag != 'equal' and new])
                    diffs.append(dict(path=name, change=change['change'], availability='ON_DEMAND',
                        before_lines=len(old), after_lines=len(new),
                        changed_current_ranges=spans, trust='NAVIGATION_ONLY_NOT_REVIEW_PROOF',
                        context_read=dict(file_path=name, start_line=1, end_line=max(1,len(new))),
                        before_read=(dict(file_path=name, start_line=1, end_line=len(old), source_version='BEFORE_TASK') if old else None)))
                    continue
                lines = list(difflib.unified_diff(old, new, fromfile='before/'+name, tofile='after/'+name, lineterm=''))
                selected = lines[:remaining]
                item = dict(path=name, change=change['change'], diff='\n'.join(selected), truncated=len(selected)<len(lines))
                if len(json.dumps(diffs+[item], ensure_ascii=False).encode()) > 24_000:
                    record['limitations'].append({'reason': 'DIFF_BYTE_BUDGET'})
                    break
                diffs.append(item)
                remaining -= len(selected)
            if any(d.get('truncated') for d in diffs):
                record['limitations'].append({'reason': 'DIFF_LINE_BUDGET'})
            static = record['static']
            from .task_review import submission_contract
            findings = [dict(id=f['id'], title=f['plain_title'], category=f['category'], severity=f['severity'],
                            file_path=f['file_path'], line_start=f['line_start']) for f in static['findings'][:30]]
            packet = dict(status='REVIEW_REQUIRED', task_ref=ref, review_required=True,
                static=dict(scan_id=static.get('scan_id'), status=static['status'], coverage=static['coverage'],
                    duration_ms=static.get('duration_ms'), scope_files=static.get('scope_files', [])[:MAX_CHANGED],
                    scope_file_count=len(static.get('scope_files', [])), scope_truncated=len(static.get('scope_files', []))>MAX_CHANGED,
                    finding_count=len(static['findings']), findings=findings, capability_results=static.get('capability_results', {})),
                changes=record['changes'], diffs=diffs, related_candidates=[],
                quick_skill=guide, limitations=record['limitations'],
                trust='UNTRUSTED_CODE_AND_SCANNER_DATA', redaction='LITERALS_AND_CREDENTIALS_MASKED; RETAIN_SEMANTIC_UNKNOWNS',
                submission_contract=submission_contract(),
                budget=dict(changed_files=MAX_CHANGED, static_changed_files=MAX_STATIC_CHANGED,
                            related_files=MAX_RELATED, context_reads=MAX_CONTEXT_READS,
                            context_window_lines=MAX_CONTEXT_WINDOW_LINES,
                            total_context_bytes=MAX_CONTEXT, expires_in_seconds=REVIEW_TTL))
            changed_dirs = {str(Path(c['path']).parent) for c in record['changes']}
            candidates = [p for p in record['end']['hashes'] if p not in {c['path'] for c in record['changes']} and not _environment(p)]
            candidates.sort(key=lambda p: (not any(v in p.lower() for v in ('auth','route','service','repository','permission','middleware')), str(Path(p).parent) not in changed_dirs, p))
            packet['related_candidates'] = candidates[:100]
            packet['risk_resolution_contract'] = dict(tool='get_task_risk_ledger',
                submission='risk_resolutions: original_task_ref,finding_id,evidence_refs,outcome,rationale,tests',
                outcomes=['CODE_REVIEWED_RESOLVED','STILL_PRESENT','INCONCLUSIVE'],
                evidence='Re-read every required_source_path; current change evidence required. Host outcomes are not scanner proof.',
                test_report='Host reported only; no Runtime execution attestation.',
                context='Long test diffs are ON_DEMAND; read current windows and signed BEFORE_TASK only when needed. Budgets unchanged.')
            cost = len(json.dumps(packet, ensure_ascii=False).encode())
            if cost > 40_000:
                packet['diffs'] = []
                packet['related_candidates'] = candidates[:30]
                packet['changes'] = record['changes'][:MAX_CHANGED]
                record['limitations'].append({'reason': 'INITIAL_PACKET_BUDGET', 'changed_file_count': len(record['changes'])})
                cost = len(json.dumps(packet, ensure_ascii=False).encode())
            if cost > MAX_CONTEXT:
                raise ValueError('Review packet exceeds context budget')
            if len(record['changes']) > MAX_CHANGED:
                record['limitations'].append(dict(reason='TASK_CONTEXT_SCOPE_EXCLUDED', count=len(record['changes'])-MAX_CHANGED))
            cost += record.get('lifetime_context_bytes', 0)
            if cost > MAX_CONTEXT:
                raise ValueError('Review task lifetime context budget exceeded')
            record.update(phase='REVIEWING', packet=packet, review_session='tr1-'+uuid.uuid4().hex,
                review_deadline=record.get('review_deadline', self.now()+REVIEW_TTL), context_bytes=cost, review_protocol=1)
            record = self.store(root).save(record)
            return dict(packet, review_session=record['review_session'])

    def _session(self, root, ref, session, *, full_fresh=True):
        record = self.load(root, ref)
        if record['phase'] != 'REVIEWING' or session != record.get('review_session'):
            if record.get('review_protocol') == 3:
                from .task_review_plan import ReviewPlanError
                raise ReviewPlanError('REVIEW_PLAN_SESSION_MISMATCH',
                    'Review session unavailable; keep the original task and current revision session')
            raise ValueError('Review session unavailable; keep the original task and session')
        if self.now() > record['review_deadline']:
            if record.get('review_protocol') == 3:
                raise ValueError('Review activity lease expired; prepare protocol_version=3 to resume this exact snapshot and ledger')
            raise ValueError('Review session unavailable or expired; no automatic restart')
        if full_fresh and not self._fresh(root, record):
            raise ValueError('Task source or Hook scope changed; submitted evidence is stale')
        if not full_fresh and self._hook_inputs(root, record)[0] != record.get('finished_hook_revision'):
            raise ValueError('Task Hook scope changed; submitted evidence is stale')
        return record

    def read(self, workspace, ref, session, path, start_line=1, end_line=80, source_version='CURRENT'):
        root = self.root(workspace)
        if self.load(root, ref).get('review_protocol') in {2, 3}:
            from .task_review import TaskReviewCoordinator
            return TaskReviewCoordinator(self).read(workspace, ref, session, path, start_line, end_line, source_version)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY'}
            record = self._session(root, ref, session)
            if source_version not in {'CURRENT', 'BEFORE_TASK'}:
                raise ValueError('Invalid source version')
            try:
                name = _relative(path)
            except (ValueError, EvidenceUnavailable):
                raise TaskContextError('TASK_CONTEXT_PATH_REJECTED', 'Source path rejected',
                    guidance='Use a relative source path from this task packet; do not escape the workspace.') from None
            deleted = any(c['path'] == name and c['change'] == 'DELETED' for c in record['changes'][:MAX_CHANGED])
            if not _supported(name):
                raise TaskContextError('TASK_CONTEXT_FILE_UNSUPPORTED', 'File type is outside task source context',
                    guidance='Use task changes or related_candidates. This source contract excludes documentation; if it is needed for the conclusion, submit PARTIAL and identify the gap.')
            if (name not in record['end']['hashes'] and not deleted) or _environment(name):
                raise TaskContextError('TASK_CONTEXT_PATH_EXCLUDED', 'Path is outside the task inventory or excluded from model context',
                    guidance='Use an allowed task source path. Environment content stays excluded; do not widen the task scope.')
            if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line <= 2_147_483_647:
                raise TaskContextError('TASK_CONTEXT_RANGE_INVALID', 'Invalid source range',
                    guidance='Use integer source lines with 1 <= start_line <= end_line. Keep this task and review session; no new scan is required.',
                    details={'max_window_lines': MAX_CONTEXT_WINDOW_LINES})
            changed = {c['path'] for c in record['changes'][:MAX_CHANGED]}
            if name not in changed and name not in record['related_files'] and len(record['related_files']) >= MAX_RELATED:
                self._context_gap(root, record, 'TASK_CONTEXT_RELATED_FILE_BUDGET', name)
                raise TaskContextError('TASK_CONTEXT_RELATED_FILE_BUDGET', 'Related source file budget exceeded', recoverable=False,
                    guidance='Keep existing evidence and submit PARTIAL with the unread path; do not create a new task or session to reset budgets.')
            if deleted or source_version == 'BEFORE_TASK':
                from .task_preimages import TaskPreimageUnavailable as PreimageError
                try:
                    lines = self.before_lines(root, record, name)
                except (OSError, PreimageError):
                    lines = None
                if lines is None:
                    self._context_gap(root, record, 'TASK_CONTEXT_SOURCE_UNAVAILABLE', name)
                    raise TaskContextError('TASK_CONTEXT_SOURCE_UNAVAILABLE', 'Task-start source preimage unavailable', recoverable=False,
                        guidance='Submit PARTIAL with the unavailable preimage; do not substitute current code or a later baseline.')
                file_hash = record['baseline']['hashes'][name]
                location_version = 'BEFORE_DELETION' if deleted else 'BEFORE_TASK'
            else:
                try:
                    raw, text = WorkspaceReader(root).read(name)
                except (OSError, EvidenceUnavailable, UnicodeError):
                    self._context_gap(root, record, 'TASK_CONTEXT_SOURCE_UNAVAILABLE', name)
                    raise TaskContextError('TASK_CONTEXT_SOURCE_UNAVAILABLE', 'Task source context unavailable', recoverable=False,
                        guidance='Submit PARTIAL with the missing source; link and source-size guards remain in force.') from None
                file_hash = hash_bytes(raw)
                if file_hash != record['end']['hashes'][name]:
                    raise ValueError('Source changed during context read')
                truncated_lines = []
                lines = safe_source(text, source_path=name, truncation_lines=truncated_lines)
                if truncated_lines:
                    record['end'].setdefault('text_truncations', {})[name] = dict(line_count=len(truncated_lines), lines=truncated_lines)
                location_version = 'CURRENT_TASK_END'
            if start_line > len(lines):
                raise TaskContextError('TASK_CONTEXT_RANGE_UNAVAILABLE', 'Source range unavailable',
                    guidance='Use a range within total_lines, keeping this task and review session; no new scan is required.',
                    details={'total_lines': len(lines), 'max_window_lines': MAX_CONTEXT_WINDOW_LINES})
            requested_high = min(end_line, len(lines))
            high = min(requested_high, start_line+MAX_CONTEXT_WINDOW_LINES-1)
            eid = 'te1-'+digest_value([ref, session, name, file_hash, start_line, high, location_version])[:32]
            packet = dict(evidence_id=eid, path=name, file_sha256=file_hash, location_version=location_version, start_line=start_line, end_line=high,
                          total_lines=len(lines), requested_range=dict(start_line=start_line, end_line=end_line),
                          returned_range=dict(start_line=start_line, end_line=high),
                          max_window_lines=MAX_CONTEXT_WINDOW_LINES, has_more=high<requested_high,
                          next_read=(dict(task_ref=ref, review_session=session, file_path=name,
                                          start_line=high+1, end_line=requested_high, source_version=source_version, workspace_path=str(root))
                                     if high<requested_high else None),
                          numbered_lines=[f'{i}: {lines[i-1]}' for i in range(start_line, high+1)], trust='UNTRUSTED_CODE')
            truncation_snapshot = record['baseline'] if deleted or source_version == 'BEFORE_TASK' else record['end']
            truncated = truncation_snapshot.get('text_truncations', {}).get(name)
            packet['line_truncation'] = dict(max_line_chars=MAX_LINE_CHARS,
                file_line_truncation_count=truncated['line_count'] if truncated else 0,
                known_truncated_lines=[i for i in (truncated or {}).get('lines', []) if start_line<=i<=high],
                complete_line_text=not truncated)
            if truncated and not any(v.get('path') == name and v.get('reason') == 'SOURCE_LINE_CHAR_BUDGET'
                                     for v in record['limitations']):
                record['limitations'].append(dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET',
                                                  line_count=truncated['line_count']))
            request_key = digest_value([name, file_hash, location_version])
            requests = record.setdefault('context_requests', {})
            request = requests.setdefault(request_key, dict(path=name, file_sha256=file_hash,
                                                            location_version=location_version, spans=[]))
            request['spans'] = _merge_spans([*request['spans'], [start_line, requested_high]])
            if eid not in record['evidence']:
                if len(record['evidence']) + record.get('lifetime_context_reads', 0) >= MAX_CONTEXT_READS:
                    self._context_gap(root, record, 'TASK_CONTEXT_READ_BUDGET', name)
                    raise TaskContextError('TASK_CONTEXT_READ_BUDGET', 'Task context read budget exceeded', recoverable=False,
                        guidance='Submit PARTIAL with unread ranges. Pagination does not reset the read, byte or session budgets.')
                cost = len(json.dumps(packet, ensure_ascii=False).encode())
                if record['context_bytes'] + cost > MAX_CONTEXT:
                    self._context_gap(root, record, 'TASK_CONTEXT_BYTE_BUDGET', name)
                    raise TaskContextError('TASK_CONTEXT_BYTE_BUDGET', 'Task model context byte budget exceeded', recoverable=False,
                        guidance='Submit PARTIAL with unread ranges; do not restart a task, rescan or widen the context budget.')
                record['evidence'][eid] = {k: packet[k] for k in ('path','file_sha256','location_version','start_line','end_line')}
                record['context_bytes'] += cost
                if name not in changed and name not in record['related_files']:
                    record['related_files'].append(name)
            self.store(root).save(record)
            return packet

    def _context_gap(self, root, record, reason_code, path):
        gap = dict(reason=reason_code, path=path)
        gaps = record.setdefault('context_gaps', [])
        if gap not in gaps and len(gaps) < MAX_CONTEXT_READS:
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
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY'}
            old = self.load(root, ref)
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
            scope = (record['changes'] if record.get('review_protocol') == 3 else
                     record['changes'][:(100 if record.get('review_protocol') == 2 else MAX_CHANGED)])
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
            # Reading related evidence is mandatory for a fully reported multi-
            # file review; runtime cannot prove the host actually reasoned.
            if record.get('review_protocol', 1) == 1 and len(record['changes']) > 1 and not record['related_files']:
                coverage = 'PARTIAL'
                clean_limitations.append('未读取未改动的关联文件；跨文件控制和调用上下文未充分核查。')
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
            if record.get('review_protocol') in {2, 3}:
                from .task_review_plan import finalize_plan
                completion = finalize_plan(record, now=self.now())
                record['review_completion'] = completion
                if completion['coverage'] != 'REVIEWED':
                    coverage = 'PARTIAL'
                    gaps = completion['gaps']
                    if record.get('review_protocol') == 3:
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
            result_packet = None
            if record.get('review_protocol') in {2, 3}:
                from .task_review import TaskReviewCoordinator
                result_packet = TaskReviewCoordinator(self).completion_packet(record)
            record = self.store(root).save(record)
            ledger.register(record)
            ledger.record_host(updates)
            return result_packet if result_packet is not None else self._view(record)

    def get(self, workspace, ref, finding_offset=0, finding_limit=20):
        if type(finding_offset) is not int or type(finding_limit) is not int or finding_offset < 0 or not 1 <= finding_limit <= 30:
            raise ValueError('Invalid result page')
        root = self.root(workspace)
        record = self.load(root, ref,read_only=True)
        if record.get('review_protocol') in {2, 3}:
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
            return seal_history_result(result)
        current = self._fresh(root, record) if record.get('end') else None
        result = self._view(record)
        if record.get('static'):
            result['static']['findings'] = [finding_view(f) for f in record['static']['findings'][finding_offset:finding_offset+finding_limit]]
            result['static']['finding_offset'] = finding_offset
            result['static']['has_more'] = finding_offset+finding_limit < len(record['static']['findings'])
        result['current_version'] = current
        result['risk_ledger'] = self.risk_ledger(workspace, ref)
        if current is False:
            result.update(status='STALE', review_required=False, development_summary='任务核查对应的代码版本或检查范围已变化，旧记录不能用于当前任务范围。')
            result['risk_choices'] = []
            from .reply_plan import CheckFact, ReplyFacts, plan_reply
            result['reply_plan'] = plan_reply(ReplyFacts('HISTORY', CheckFact('STALE'), current=False)).to_dict()
        return result

    def risk_ledger(self, workspace, ref, offset=0, limit=30):
        root = self.root(workspace)
        original = self.load(root, ref,read_only=True)  # Historical reads never transfer ownership.
        from .task_risk_ledger import TaskRiskLedger
        return TaskRiskLedger(self.hooks, root).view(ref, offset, limit, original)

    def skip(self, workspace, ref, reason):
        """Finish with an explicit coverage gap, never a fabricated host pass.

        State-only CAS permits a host to finish its response even when a scan
        is busy. A concurrent runner cannot overwrite this terminal record.
        """
        root = self.root(workspace)
        record = self.load(root, ref)
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
            review_required=phase in {'READY','REVIEWING'}, changes=record.get('changes', [])[:MAX_CHANGED],
            changed_file_count=len(record.get('changes', [])), change_scope_truncated=len(record.get('changes', []))>MAX_CHANGED,
            unverified_file_count=len(record.get('unverified_paths', [])),
            baseline_file_count=len(record['baseline']['hashes']), limitations=record.get('limitations') or record['baseline']['limitations'],
            static=None, host_review=record.get('review'), repair_authorized=False)
        result['snapshot_capture'] = dict(baseline=record['baseline'].get('capture_stats'),
            current=(record.get('end') or {}).get('capture_stats'))
        if record.get('native_repair'):
            import copy
            result['native_repair'] = {key: copy.deepcopy(record['native_repair'][key]) for key in
                ('source', 'assessment_ref', 'proposal_revision', 'source_binding')}
            result['native_repair']['repair_authorized'] = False
        if record.get('review_protocol') == 3:
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
        result['context_read_coverage'] = dict(unread_range_count=len(unread), unread_ranges=unread[:100],
            gaps=record.get('context_gaps', []), used_reads=len(record.get('evidence', {})),
            max_reads=MAX_CONTEXT_READS, used_bytes=record.get('context_bytes', 0), max_bytes=MAX_CONTEXT,
            max_window_lines=MAX_CONTEXT_WINDOW_LINES)
        if record.get('review_protocol') in {2, 3} and record.get('review_plan'):
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

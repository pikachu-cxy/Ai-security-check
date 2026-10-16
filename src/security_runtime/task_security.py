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
from .target import DEPENDENCIES, EXTENSIONS, IGNORED
from .workspace import WorkspaceResolver

MAX_FILES = 1000
MAX_READ_BYTES = 20_000_000
MAX_PREIMAGE_BYTES = 512_000
MAX_CHANGED = 20
MAX_STATIC_CHANGED = 1000
MAX_INVENTORY_PATHS = 20_000
MAX_INVENTORY_NAME_BYTES = 256_000
MAX_RELATED = 10

RISK_CHOICE_PROMPT = ('请选择具体风险后回复：**修复** ／ **暂不处理**。\n\n'
                      '暂不处理仅表示本次不修复，风险记录保留；未授权的风险不会自动修改。')


def _risk_heading(total, related=0):
    label = '关联风险' if related == total else '安全风险'
    detail = f'（其中 {related} 项关联风险）' if 0 < related < total else ''
    return f'**有 {total} 项{label}需要你决定{detail}。**'
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


def method():
    path = Path(__file__).parent / 'skills/ai-security-review/references/quick-task-review.md'
    content = path.read_text(encoding='utf-8')
    return dict(version='quick-task-review-v1', sha256=hash_bytes(content.encode()), content=content)


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
        names = []
        started, visited = time.monotonic(), 0
        def onerror(error):
            limitations.append({'reason': 'INVENTORY_DIRECTORY_UNAVAILABLE'})
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            visited += 1
            depth = len(Path(directory).relative_to(root).parts)
            dirs[:] = sorted(d for d in dirs if d not in ignored
                             and d != '.test-tmp' and not d.startswith('.test-tmp-'))
            for d in list(dirs):
                path = Path(directory) / d
                if path.is_symlink() or path.is_junction() or depth >= 12:
                    limitations.append({'path': path.relative_to(root).as_posix(), 'reason': 'LINK_OR_DEPTH_EXCLUDED'})
                    dirs.remove(d)
            if visited > 2000 or time.monotonic() - started > 5:
                limitations.append({'reason': 'INVENTORY_TIME_OR_DIRECTORY_BUDGET'})
                break
            names.extend((Path(directory) / filename).relative_to(root).as_posix() for filename in files)
            if len(names) > MAX_INVENTORY_PATHS:
                limitations.append({'reason': 'INVENTORY_PATH_BUDGET'})
                break
    selected = set()
    for name in names:
        try:
            name = _relative(name)
            if not _supported(name) or set(Path(name).parts) & ignored:
                continue
            # Missing tracked files are real deletions, not read failures. lstat
            # does not follow a link; WorkspaceReader validates every actual read.
            (root / name).lstat()
            selected.add(name)
        except FileNotFoundError:
            continue
        except (OSError, EvidenceUnavailable) as exc:
            limitations.append({'path': name, 'reason': getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')})
    return sorted(selected), dirty, not limitations, limitations[:100]


def capture(root, *, known_paths=None, priority_paths=(), include_text=True):
    """Hash the actual workspace (including pre-existing dirty/new files).

    Retain only sanitized text, never raw source/credentials. All budgets are
    reported; unavailable/truncated inventory cannot attest a full task.
    Freshness-only callers may omit text preparation, but must still inventory
    and safely read/hash every current file with the same source guards.
    """
    reader = WorkspaceReader(root)
    hashes, texts, limitations, text_truncations = {}, {}, [], {}
    total, text_total = 0, 0
    ignored = IGNORED | {v.strip() for v in os.getenv('SECURITY_RUNTIME_EXCLUDE_DIRS', '').split(',') if v.strip()}
    inventory, dirty, complete, inventory_limits = _inventory(root, ignored)
    limitations.extend(inventory_limits)
    known = set(known_paths) if known_paths is not None else None
    added = [p for p in inventory if known is not None and p not in known]
    priority = list(dict.fromkeys([*priority_paths, *added, *sorted(dirty)]))
    inventory_set = set(inventory)
    priority = [p for p in priority if p in inventory_set]
    ordered = list(dict.fromkeys([*priority, *inventory]))
    name_bytes = sum(len(p.encode('utf-8')) for p in ordered)
    if len(ordered) > MAX_INVENTORY_PATHS or name_bytes > MAX_INVENTORY_NAME_BYTES:
        complete = False
        limitations.append({'reason': 'INVENTORY_PATH_BUDGET'})
        selected, cost = [], 0
        for name in ordered[:MAX_INVENTORY_PATHS]:
            cost += len(name.encode('utf-8'))
            if cost > MAX_INVENTORY_NAME_BYTES:
                break
            selected.append(name)
        inventory, ordered = sorted(selected), selected
    started = time.monotonic()
    for name in ordered:
        if len(hashes) >= MAX_FILES or total >= MAX_READ_BYTES or time.monotonic() - started > 5:
            limitations.append({'reason': 'INVENTORY_READ_BUDGET'})
            break
        try:
            raw, text = reader.read(name, maximum=min(1_000_000, MAX_READ_BYTES-total))
            hashes[name] = hash_bytes(raw)
            total += len(raw)
            if not include_text or _environment(name):
                continue
            truncated_lines = [i for i, line in enumerate(text.splitlines(), 1) if len(line)>MAX_LINE_CHARS]
            if truncated_lines:
                text_truncations[name] = {'line_count': len(truncated_lines), 'lines': truncated_lines[:20]}
            lines = safe_source(text)
            cost = len(json.dumps(lines, ensure_ascii=True).encode())
            if cost + text_total <= MAX_PREIMAGE_BYTES:
                texts[name] = lines
                text_total += cost
        except (OSError, EvidenceUnavailable, UnicodeError) as exc:
            limitations.append({'path': name, 'reason': getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')})
    return dict(hashes=hashes, texts=texts, text_truncations=text_truncations,
                limitations=limitations[:100], inventory=inventory,
                inventory_complete=complete,
                read_priority=ordered[:MAX_FILES])


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
              'INITIAL_PACKET_BUDGET': '初始任务上下文超出返回预算'}
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
    def __init__(self, runtime, hooks=None, *, now=time.time):
        self.runtime = runtime
        self.hooks = hooks or HookStateStore()
        self.now = now

    def root(self, workspace):
        return WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True).path

    def store(self, root):
        return TaskSecurityStore(self.hooks, root, now=self.now)

    def load(self, root, ref):
        record = self.store(root).get(ref)
        if not record:
            raise ValueError('Task is unavailable or expired; never infer a baseline after editing')
        return record

    def begin(self, workspace, task_key, *, _owner=None):
        if not isinstance(task_key, str) or not 1 <= len(task_key) <= 200:
            raise ValueError('Use a short unique task key, not a prompt or source')
        if _owner is not None and (not isinstance(_owner, dict)
                or set(_owner) != {'host', 'session'} or _owner['host'] != 'cursor'
                or not isinstance(_owner['session'], str) or len(_owner['session']) != 64
                or any(c not in '0123456789abcdef' for c in _owner['session'])):
            raise ValueError('Invalid connector owner')
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'scanner_run': False}
            self.hooks.key(root)
            store = self.store(root)
            existing = store.get(task_key=identity(task_key))
            if existing:
                return self._view(existing)
            active = store.get(active=True)
            if active and active['phase'] == 'REVIEWING' and self.now() > active['review_deadline']:
                active.update(phase='INCOMPLETE')
                active['baseline']['texts'] = {}
                active['end']['texts'] = {}
                active.pop('packet', None)
                store.save(active)
                active = None
            if active:
                # Avoid silently joining another editing task. The host may
                # resume the exact ref, or finish it, then begin the next one.
                return dict(status='ACTIVE_TASK_EXISTS', task_ref=active['task_ref'], scanner_run=False)
            baseline = capture(root)
            record = dict(contract=CONTRACT, task_ref='ts1-'+uuid.uuid4().hex, task_key=identity(task_key),
                workspace=str(root), generation=0, phase='ACTIVE', created_at=self.now(),
                baseline=baseline, static_attempts=0, limitations=[], source='TASK_BASELINE_BEFORE_EDIT')
            if _owner is not None:
                record['connector_owner'] = _owner
            record = store.save(record, new=True)
            return self._view(record)

    def _fresh(self, root, record):
        if record.get('finished_hook_revision'):
            revision, _, _ = self._hook_inputs(root, record)
            if revision != record['finished_hook_revision']:
                return False
        current = capture(root, known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                          priority_paths=record['end'].get('read_priority', ()), include_text=False)
        if current['limitations'] != record['end']['limitations']:
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
                          priority_paths=record.get('end', {}).get('read_priority', ()))
            hook_revision, marker, marker_error = self._hook_inputs(root, record)
            if (record.get('end') and end['hashes'] == record['end']['hashes']
                    and end['limitations'] == record['end']['limitations']
                    and end['inventory'] == record['end'].get('inventory', sorted(record['end']['hashes']))
                    and record['phase'] != 'STATIC_RUNNING'
                    and record.get('finished_hook_revision') == hook_revision):
                return self._view(record)
            before = record['baseline']['hashes']
            changes, unknown = task_changes(root, record['baseline'], end)
            for key in ('packet', 'review_session', 'review_deadline', 'skip_reason'):
                record.pop(key, None)
            record.update(end=end, changes=changes, review=None, evidence={}, related_files=[], context_bytes=0,
                          context_requests={}, context_gaps=[],
                          finished_hook_revision=hook_revision,
                          unverified_paths=unknown, limitations=record['baseline']['limitations']+end['limitations'])
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
                record.update(phase='NO_CHANGES', baseline=dict(hashes=before, texts={}, limitations=record['baseline']['limitations']))
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
            if len(changes) > MAX_CHANGED:
                record['limitations'].append({'reason': 'TASK_CONTEXT_SCOPE_EXCLUDED', 'count': len(changes)-MAX_CHANGED,
                                             'paths': [v['path'] for v in changes[MAX_CHANGED:MAX_CHANGED*2]]})
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

    def prepare(self, workspace, ref):
        root = self.root(workspace)
        # Only the never-finished ACTIVE task may perform its first closeout.
        # Release/no lock here: finish owns the normal lock and attempt guard.
        initial = self.load(root, ref)
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
                old = record['baseline']['texts'].get(name)
                new = record['end']['texts'].get(name)
                if change['change'] == 'ADDED':
                    old = []
                if change['change'] == 'DELETED':
                    new = []
                if old is None or new is None:
                    diffs.append({'path': name, 'change': change['change'], 'availability': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'})
                    record['limitations'].append({'path': name, 'reason': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'})
                    continue
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
                submission_contract=dict(findings='list[max10]: title,category,severity,primary_evidence,evidence_refs,impact,preconditions,unknowns,counterevidence,fix_advice',
                                         optional_candidate_fields='risk_scope: TASK_CHANGED or RELATED_EXISTING; task_evidence: issued changed-file evidence; current_protections: list[str]',
                                         related_existing_risk='Primary evidence may locate a read unchanged related file only with task_evidence in evidence_refs, conditions, unknowns and explicit current_protections. Register surviving conditional risks as findings, never only as limitations or later advice.',
                                         coverage='REVIEWED or PARTIAL', limitations='list[str], including unreviewed paths and missing context',
                                         evidence='Runtime-issued ids only; primary location must be a changed file',
                                         validation='STRUCTURE_AND_SOURCE_VERSION_ONLY; HOST_CANDIDATES_NOT_SCANNER_PROOF'),
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
            record.update(phase='REVIEWING', packet=packet, review_session='tr1-'+uuid.uuid4().hex,
                review_deadline=self.now()+REVIEW_TTL, context_bytes=cost)
            record = self.store(root).save(record)
            return dict(packet, review_session=record['review_session'])

    def _session(self, root, ref, session):
        record = self.load(root, ref)
        if record['phase'] != 'REVIEWING' or session != record.get('review_session') or self.now() > record['review_deadline']:
            raise ValueError('Review session unavailable or expired; no automatic restart')
        if not self._fresh(root, record):
            raise ValueError('Task source or Hook scope changed; submitted evidence is stale')
        return record

    def read(self, workspace, ref, session, path, start_line=1, end_line=80, source_version='CURRENT'):
        root = self.root(workspace)
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
                lines = record['baseline']['texts'].get(name)
                if lines is None:
                    self._context_gap(root, record, 'TASK_CONTEXT_SOURCE_UNAVAILABLE', name)
                    raise TaskContextError('TASK_CONTEXT_SOURCE_UNAVAILABLE', 'Deleted source preimage unavailable', recoverable=False,
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
                lines = safe_source(text)
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
                if len(record['evidence']) >= MAX_CONTEXT_READS:
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

    def submit(self, workspace, ref, session, findings, coverage, limitations, risk_resolutions=None):
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY'}
            old = self.load(root, ref)
            if old['phase'] == 'COMPLETE' and old.get('review_session') == session:
                return self.get(workspace, ref)  # idempotent retry; no scan/model.
            record = self._session(root, ref, session)
            if not isinstance(findings, list) or len(findings) > 10 or coverage not in {'REVIEWED','PARTIAL'}:
                raise ValueError('Invalid bounded host review')
            if not isinstance(limitations, list) or len(limitations) > 30:
                raise ValueError('Invalid review limitations')
            clean_limitations = [_clean(v, 500) for v in limitations]
            if coverage == 'PARTIAL' and not clean_limitations:
                raise ValueError('Partial review must identify a limitation')
            fields = {'title','category','severity','primary_evidence','evidence_refs','impact','preconditions','unknowns','counterevidence','fix_advice'}
            optional_fields = {'risk_scope', 'task_evidence', 'current_protections'}
            accepted = []
            changed = {v['path'] for v in record['changes'][:MAX_CHANGED]}
            for candidate in findings:
                if not isinstance(candidate, dict) or not fields <= set(candidate) or set(candidate) - fields - optional_fields:
                    raise ValueError('Use the task candidate schema; scanner proof and authority fields are forbidden')
                refs = candidate['evidence_refs']
                primary = candidate['primary_evidence']
                if not isinstance(refs, list) or not 1 <= len(refs) <= 10 or any(not isinstance(e, str) or e not in record['evidence'] for e in refs) or not isinstance(primary, str) or primary not in refs:
                    raise ValueError('Every candidate needs Runtime-issued evidence')
                location = record['evidence'][primary]
                if location['location_version'] == 'BEFORE_TASK':
                    raise ValueError('Historical evidence cannot locate a current risk')
                risk_scope = candidate.get('risk_scope', 'TASK_CHANGED')
                if risk_scope not in {'TASK_CHANGED', 'RELATED_EXISTING'}:
                    raise ValueError('Invalid task risk scope')
                task_evidence = candidate.get('task_evidence', primary)
                if (not isinstance(task_evidence, str) or task_evidence not in refs
                        or record['evidence'][task_evidence]['path'] not in changed):
                    raise ValueError('Every risk needs issued task-changed evidence in evidence_refs')
                if risk_scope == 'TASK_CHANGED' and location['path'] not in changed:
                    raise ValueError('Primary evidence must locate a task-changed file')
                if risk_scope == 'RELATED_EXISTING' and (location['path'] not in record['related_files']
                        or location['path'] in changed or location['location_version'] != 'CURRENT_TASK_END'):
                    raise ValueError('Existing risk must locate current read related evidence')
                protections = candidate.get('current_protections', candidate['counterevidence'])
                if not isinstance(protections, list) or len(protections) > 10:
                    raise ValueError('Invalid current protections')
                if risk_scope == 'RELATED_EXISTING' and (not candidate.get('preconditions')
                        or not candidate.get('unknowns') or 'current_protections' not in candidate):
                    raise ValueError('Conditional existing risk requires conditions, unknowns and current protections')
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
            if len(record['changes']) > 1 and not record['related_files']:
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
                elapsed_wall_ms=round((self.now()-(record['review_deadline']-REVIEW_TTL))*1000),
                submitted_at=self.now()))
            # Preimages are no longer needed. Local retention is bounded by TTL.
            record['baseline']['texts'] = {}
            record['end']['texts'] = {}
            record.pop('packet', None)
            record = self.store(root).save(record)
            ledger.register(record)
            ledger.record_host(updates)
            return self._view(record)

    def get(self, workspace, ref, finding_offset=0, finding_limit=20):
        if type(finding_offset) is not int or type(finding_limit) is not int or finding_offset < 0 or not 1 <= finding_limit <= 30:
            raise ValueError('Invalid result page')
        root = self.root(workspace)
        record = self.load(root, ref)
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
        return result

    def risk_ledger(self, workspace, ref, offset=0, limit=30):
        root = self.root(workspace)
        original = self.load(root, ref)  # Same signed workspace/ref admission; never infer a root.
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
        return self._view(self.store(root).save(record))

    def _view(self, record):
        phase = record['phase']
        result = dict(status=phase, task_ref=record['task_ref'], scanner_run=False,
            review_required=phase in {'READY','REVIEWING'}, changes=record.get('changes', [])[:MAX_CHANGED],
            changed_file_count=len(record.get('changes', [])), change_scope_truncated=len(record.get('changes', []))>MAX_CHANGED,
            unverified_file_count=len(record.get('unverified_paths', [])),
            baseline_file_count=len(record['baseline']['hashes']), limitations=record.get('limitations') or record['baseline']['limitations'],
            static=None, host_review=record.get('review'), repair_authorized=False)
        result['risk_choices'] = [dict(finding_id=f['id'], title=f['title'],
            options=['修复', '暂不处理'], deferred_keeps_risk=True, repair_authorized=False)
            for f in (record.get('review') or {}).get('findings', [])]
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
        if record.get('static'):
            static = record['static']
            result['static'] = {key: static[key] for key in ('scan_id','status','coverage','scope_files','actual_files','duration_ms','reason','capability_results') if key in static}
            result['static'].update(finding_count=len(static['findings']), findings=[finding_view(f) for f in static['findings'][:20]],
                has_more=len(static['findings'])>20,
                scanner_runs=[{k: r[k] for k in ('scanner','version','status','duration_ms','error_code','coverage_contract') if k in r}
                              for r in static.get('scanner_runs', [])])
        if phase == 'NO_CHANGES':
            result['development_summary'] = '' if not result['limitations'] else '本次没有观察到可检查的文件改动；部分文件未能建立比较记录。'
        elif phase == 'INCOMPLETE':
            result['development_summary'] = '本次任务安全核查未完成：'+record.get('skip_reason', '上下文核查会话已过期。')+' 已有检查记录保留，不认定风险已消除。'
            pending = record.get('static', {}).get('findings', [])
            for f in pending[:3]:
                result['development_summary'] += f"\n- 已有静态提示：{f['file_path']}:{f['line_start']}，{f.get('plain_title') or f['title']}。可能影响：{f['impact']} 建议：{f['fix_advice']} 实际运行条件尚未确认。"
            if len(pending)>3:
                result['development_summary'] += f'\n另有 {len(pending)-3} 项静态提示保留在本次核查记录中。'
            if pending:
                result['development_summary'] = (_risk_heading(len(pending))+'\n\n'
                    +result['development_summary']+'\n\n'+RISK_CHOICE_PROMPT)
        elif phase == 'COMPLETE':
            static = record['static']
            review = record['review']
            total = len(static['findings']) + len(review['findings'])
            complete_static = (static['status'] in {'SUCCESS', 'COMPLETED'}
                               and static['coverage'] in {'FULL', 'SCOPED'})
            prefix = f"安全核查：本任务有 {len(record['changes'])} 个改动文件，提交静态检查 {len(static.get('scope_files', []))} 个文件"
            if record.get('hook_final_recheck_files'):
                prefix += f"（包含文件修改检查保留的 {len(record['hook_final_recheck_files'])} 个当前文件）"
            if total:
                prefix += f'，保留 {total} 项待核实风险。'
            elif not complete_static:
                prefix += '，静态检查未完成或覆盖有限，当前风险尚待核实。'
            elif review['coverage'] == 'PARTIAL' or record['limitations']:
                prefix += '，上下文核查覆盖有限，当前风险尚待核实。'
            else:
                prefix += '，本次未发现安全线索。'
            lines = [prefix]
            if total:
                related = sum(f.get('risk_scope') == 'RELATED_EXISTING' for f in review['findings'])
                lines = [_risk_heading(total, related), '', prefix, '']
            # Aggregate final findings once with a bounded default summary;
            # full records stay accessible and candidates retain uncertainty.
            combined = [(f, '静态检查提示') for f in static['findings']] + [(f, '上下文核查线索') for f in review['findings']]
            order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
            combined.sort(key=lambda v: order.get(v[0]['severity'], 4))
            for f, source in combined[:3]:
                title = f.get('plain_title') or f['title']
                text = f"- {source}：{f['file_path']}:{f['line_start']}，{title}。可能影响：{f['impact']} 建议：{f['fix_advice']}"
                if f.get('location_version') == 'BEFORE_DELETION':
                    text += ' 位置对应删除前的代码。'
                if source == '上下文核查线索':
                    text += ' 风险范围：'+('关联代码中的现有条件性风险，不等于新增入口仍有漏洞。' if f.get('risk_scope') == 'RELATED_EXISTING' else '本次改动相关路径。')
                    locations = f.get('evidence_locations', [])
                    if locations:
                        text += ' 代码依据：'+' → '.join(f"{v['path']}:{v['start_line']}-{v['end_line']}" for v in locations)
                    text += ' 条件：'+('；'.join(f['preconditions']) or '实际可达性未确认')
                    text += ' 未确认：'+('；'.join(f['unknowns']) or '尚未运行验证')
                    text += ' 当前防护：'+('；'.join(f.get('current_protections', f['counterevidence'])) or '未观察到相关防护；不代表不存在')
                    text += ' 反证：'+('；'.join(f['counterevidence']) or '未观察到足以排除风险的反证')
                else:
                    text += ' 实际运行条件尚未确认。'
                lines.append(text)
            if total > 3:
                lines.append(f'另有 {total-3} 项已保留在本次核查记录中。')
            if not complete_static and record.get('hook_final_recheck_files'):
                names = record['hook_final_recheck_files']
                lines.append('文件修改检查保留范围的当前风险尚待核实：'+ '、'.join(names[:5])+
                             (f' 等 {len(names)} 个文件' if len(names)>5 else '')+
                             '；本次最终检查不足以证明先前提示已消除。')
            if not complete_static or review['coverage'] == 'PARTIAL' or record['limitations']:
                lines.append('覆盖有限：'+('；'.join(review['limitations'][:5]) or '静态能力或任务上下文有未完成范围。'))
            lines.append('仅覆盖本任务的局部静态检查和代码上下文核查，未验证运行行为；风险尚未修复。' if total else '仅覆盖本任务的局部静态检查和代码上下文核查，未验证运行行为。')
            if total:
                lines.extend(['', RISK_CHOICE_PROMPT])
            result['development_summary'] = '\n'.join(lines)
        else:
            result['development_summary'] = ''
        return result

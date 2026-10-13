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
import time
import uuid

from .hook_state import HookStateStore, identity
from .local_evidence import EvidenceUnavailable, WorkspaceReader, _relative, safe_source
from .redactor import SecretRedactor
from .task_security_state import CONTRACT, TaskSecurityStore
from .target import DEPENDENCIES, EXTENSIONS, IGNORED
from .workspace import WorkspaceResolver

MAX_FILES = 1000
MAX_READ_BYTES = 20_000_000
MAX_PREIMAGE_BYTES = 512_000
MAX_CHANGED = 20
MAX_RELATED = 10
MAX_CONTEXT = 64_000
MAX_DIFF_LINES = 2000
MAX_CONTEXT_READS = 40
REVIEW_TTL = 900


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
            or path.name in set(DEPENDENCIES) | {'Dockerfile', '.env'} or path.name.startswith('.env.'))


def _environment(name):
    return Path(name).name == '.env' or Path(name).name.startswith('.env.')


def capture(root):
    """Hash the actual workspace (including pre-existing dirty/new files).

    Retain only sanitized text, never raw source/credentials. All budgets are
    reported; unavailable/truncated inventory cannot attest a full task.
    """
    reader = WorkspaceReader(root)
    hashes, texts, limitations = {}, {}, []
    total, text_total, visited = 0, 0, 0
    ignored = IGNORED | {v.strip() for v in os.getenv('SECURITY_RUNTIME_EXCLUDE_DIRS', '').split(',') if v.strip()}
    started = time.monotonic()
    for directory, dirs, files in os.walk(root, followlinks=False):
        visited += 1
        depth = len(Path(directory).relative_to(root).parts)
        dirs[:] = sorted(d for d in dirs if d not in ignored)
        for d in list(dirs):
            path = Path(directory) / d
            if path.is_symlink() or path.is_junction() or depth >= 12:
                limitations.append({'path': path.relative_to(root).as_posix(), 'reason': 'LINK_OR_DEPTH_EXCLUDED'})
                dirs.remove(d)
        if visited > 2000 or time.monotonic() - started > 5:
            limitations.append({'reason': 'INVENTORY_TIME_OR_DIRECTORY_BUDGET'})
            break
        for filename in sorted(files):
            name = (Path(directory)/filename).relative_to(root).as_posix()
            if not _supported(name):
                continue
            if len(hashes) >= MAX_FILES or total >= MAX_READ_BYTES:
                limitations.append({'reason': 'INVENTORY_FILE_OR_BYTE_BUDGET'})
                return dict(hashes=hashes, texts=texts, limitations=limitations[:100])
            try:
                raw, text = reader.read(name, maximum=min(1_000_000, MAX_READ_BYTES-total))
                hashes[name] = hash_bytes(raw)
                total += len(raw)
                if _environment(name):
                    continue
                lines = safe_source(text)
                cost = len(json.dumps(lines, ensure_ascii=True).encode())
                if cost + text_total <= MAX_PREIMAGE_BYTES:
                    texts[name] = lines
                    text_total += cost
            except (OSError, EvidenceUnavailable, UnicodeError) as exc:
                limitations.append({'path': name, 'reason': getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')})
    return dict(hashes=hashes, texts=texts, limitations=limitations[:100])


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

    def begin(self, workspace, task_key):
        if not isinstance(task_key, str) or not 1 <= len(task_key) <= 200:
            raise ValueError('Use a short unique task key, not a prompt or source')
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
            record = store.save(record, new=True)
            return self._view(record)

    def _fresh(self, root, record):
        current = capture(root)
        if current['limitations'] != record['end']['limitations']:
            return False
        return current['hashes'] == record['end']['hashes']

    def finish(self, workspace, ref):
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'task_ref': ref, 'scanner_run': False}
            record = self.load(root, ref)
            if record['phase'] == 'NO_CHANGES':
                return self.get(workspace, ref)
            end = capture(root)
            if record.get('end') and end['hashes'] == record['end']['hashes'] and end['limitations'] == record['end']['limitations'] and record['phase'] != 'STATIC_RUNNING':
                return self._view(record)
            before = record['baseline']['hashes']
            changes = [dict(path=p, change='DELETED' if p not in end['hashes'] else 'ADDED' if p not in before else 'MODIFIED')
                       for p in sorted(set(before) | set(end['hashes'])) if before.get(p) != end['hashes'].get(p)]
            record.update(end=end, changes=changes, review=None, evidence={}, related_files=[], context_bytes=0,
                          limitations=record['baseline']['limitations']+end['limitations'])
            if not changes:
                record.update(phase='NO_CHANGES', baseline=dict(hashes=before, texts={}, limitations=record['baseline']['limitations']))
                return self._view(self.store(root).save(record))
            if record['static_attempts'] >= 2:
                record.update(phase='READY', static=dict(status='NOT_EXECUTED', coverage='UNKNOWN', findings=[], reason='TASK_STATIC_ATTEMPT_BUDGET'))
                return self._view(self.store(root).save(record))
            scope = [v['path'] for v in changes[:MAX_CHANGED] if not _environment(v['path'])]
            exclusions = [v['path'] for v in changes if _environment(v['path']) or v not in changes[:MAX_CHANGED]]
            if exclusions:
                record['limitations'].append({'reason': 'TASK_STATIC_SCOPE_EXCLUDED', 'paths': exclusions})
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
            record = self.store(root).save(record)
            view = self._view(record)
            view['scanner_run'] = any(r.get('status') in {'SUCCESS','FAILED','TIMEOUT'} for r in record['static'].get('scanner_runs', []))
            return view

    def prepare(self, workspace, ref):
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY', 'task_ref': ref}
            record = self.load(root, ref)
            if record['phase'] == 'NO_CHANGES':
                return self._view(record)
            if record['phase'] not in {'READY', 'REVIEWING', 'COMPLETE'} or not self._fresh(root, record):
                return {'status': 'STALE', 'task_ref': ref, 'review_required': False, 'message': '代码版本已变化或基础检查未完成；保留缺口，不循环扫描。'}
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
                    duration_ms=static.get('duration_ms'), scope_files=static.get('scope_files', []),
                    finding_count=len(static['findings']), findings=findings, capability_results=static.get('capability_results', {})),
                changes=record['changes'], diffs=diffs, related_candidates=[],
                quick_skill=guide, limitations=record['limitations'],
                trust='UNTRUSTED_CODE_AND_SCANNER_DATA', redaction='LITERALS_AND_CREDENTIALS_MASKED; RETAIN_SEMANTIC_UNKNOWNS',
                submission_contract=dict(findings='list[max10]: title,category,severity,primary_evidence,evidence_refs,impact,preconditions,unknowns,counterevidence,fix_advice',
                                         coverage='REVIEWED or PARTIAL', limitations='list[str], including unreviewed paths and missing context',
                                         evidence='Runtime-issued ids only; primary location must be a changed file',
                                         validation='STRUCTURE_AND_SOURCE_VERSION_ONLY; HOST_CANDIDATES_NOT_SCANNER_PROOF'),
                budget=dict(changed_files=MAX_CHANGED, related_files=MAX_RELATED, context_reads=MAX_CONTEXT_READS,
                            total_context_bytes=MAX_CONTEXT, expires_in_seconds=REVIEW_TTL))
            changed_dirs = {str(Path(c['path']).parent) for c in record['changes']}
            candidates = [p for p in record['end']['hashes'] if p not in {c['path'] for c in record['changes']} and not _environment(p)]
            candidates.sort(key=lambda p: (not any(v in p.lower() for v in ('auth','route','service','repository','permission','middleware')), str(Path(p).parent) not in changed_dirs, p))
            packet['related_candidates'] = candidates[:100]
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
            raise ValueError('Task source changed; submitted evidence is stale')
        return record

    def read(self, workspace, ref, session, path, start_line=1, end_line=80):
        root = self.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return {'status': 'BUSY'}
            record = self._session(root, ref, session)
            name = _relative(path)
            deleted = any(c['path'] == name and c['change'] == 'DELETED' for c in record['changes'][:MAX_CHANGED])
            if (name not in record['end']['hashes'] and not deleted) or _environment(name):
                raise ValueError('Path is outside the task inventory or excluded from model context')
            if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line or end_line-start_line >= 80:
                raise ValueError('Request 1 to 80 source lines')
            changed = {c['path'] for c in record['changes'][:MAX_CHANGED]}
            if name not in changed and name not in record['related_files'] and len(record['related_files']) >= MAX_RELATED:
                raise ValueError('Related source file budget exceeded')
            if deleted:
                lines = record['baseline']['texts'].get(name)
                if lines is None:
                    raise ValueError('Deleted source preimage unavailable')
                file_hash = record['baseline']['hashes'][name]
                location_version = 'BEFORE_DELETION'
            else:
                raw, text = WorkspaceReader(root).read(name)
                if hash_bytes(raw) != record['end']['hashes'][name]:
                    raise ValueError('Source changed during context read')
                lines = safe_source(text)
                file_hash = hash_bytes(raw)
                location_version = 'CURRENT_TASK_END'
            if start_line > len(lines):
                raise ValueError('Source range unavailable')
            high = min(end_line, len(lines))
            eid = 'te1-'+digest_value([ref, session, name, file_hash, start_line, high, location_version])[:32]
            packet = dict(evidence_id=eid, path=name, file_sha256=file_hash, location_version=location_version, start_line=start_line, end_line=high,
                          numbered_lines=[f'{i}: {lines[i-1]}' for i in range(start_line, high+1)], trust='UNTRUSTED_CODE')
            if eid not in record['evidence']:
                if len(record['evidence']) >= MAX_CONTEXT_READS:
                    raise ValueError('Task context read budget exceeded')
                cost = len(json.dumps(packet, ensure_ascii=False).encode())
                if record['context_bytes'] + cost > MAX_CONTEXT:
                    raise ValueError('Task model context byte budget exceeded')
                record['evidence'][eid] = {k: packet[k] for k in ('path','file_sha256','location_version','start_line','end_line')}
                record['context_bytes'] += cost
                if name not in changed and name not in record['related_files']:
                    record['related_files'].append(name)
                self.store(root).save(record)
            return packet

    def submit(self, workspace, ref, session, findings, coverage, limitations):
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
            accepted = []
            changed = {v['path'] for v in record['changes'][:MAX_CHANGED]}
            for candidate in findings:
                if not isinstance(candidate, dict) or set(candidate) != fields:
                    raise ValueError('Use the task candidate schema; scanner proof and authority fields are forbidden')
                refs = candidate['evidence_refs']
                primary = candidate['primary_evidence']
                if not isinstance(refs, list) or not 1 <= len(refs) <= 10 or any(not isinstance(e, str) or e not in record['evidence'] for e in refs) or not isinstance(primary, str) or primary not in refs:
                    raise ValueError('Every candidate needs Runtime-issued evidence')
                location = record['evidence'][primary]
                if location['path'] not in changed:
                    raise ValueError('Primary evidence must locate a task-changed file')
                if candidate['severity'] not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
                    raise ValueError('Invalid candidate severity')
                item = {k: _clean(candidate[k], 1200) for k in ('title','category','impact','fix_advice')}
                for field in ('preconditions','unknowns','counterevidence'):
                    values = candidate[field]
                    if not isinstance(values, list) or len(values) > 10:
                        raise ValueError('Invalid candidate conditions or counterevidence')
                    item[field] = [_clean(v, 500) for v in values]
                item.update(id='tc1-'+digest_value([ref, candidate])[:32], severity=candidate['severity'],
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
            if record['limitations']:
                coverage = 'PARTIAL'
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
        if current is False:
            result.update(status='STALE', review_required=False, development_summary='任务核查对应的代码已变化，旧结论不能用于当前版本。')
        return result

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
            baseline_file_count=len(record['baseline']['hashes']), limitations=record.get('limitations') or record['baseline']['limitations'],
            static=None, host_review=record.get('review'), repair_authorized=False)
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
            for f in record.get('static', {}).get('findings', [])[:3]:
                result['development_summary'] += f"\n- 已有静态提示：{f['file_path']}:{f['line_start']}，{f.get('plain_title') or f['title']}。可能影响：{f['impact']} 建议：{f['fix_advice']} 实际运行条件尚未确认。"
        elif phase == 'COMPLETE':
            static = record['static']
            review = record['review']
            total = len(static['findings']) + len(review['findings'])
            prefix = f"安全核查：本任务有 {len(record['changes'])} 个改动文件，提交静态检查 {len(static.get('scope_files', []))} 个文件"
            if total:
                prefix += f'，保留 {total} 项待核实风险。'
            else:
                prefix += '，本次未发现安全线索。'
            lines = [prefix]
            # Full results stay accessible; summary is bounded and carries the
            # condition/unknowns rather than presenting host claims as facts.
            combined = [(f, '静态检查提示') for f in static['findings']] + [(f, '上下文核查线索') for f in review['findings']]
            order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
            combined.sort(key=lambda v: order.get(v[0]['severity'], 4))
            for f, source in combined[:3]:
                title = f.get('plain_title') or f['title']
                text = f"- {source}：{f['file_path']}:{f['line_start']}，{title}。可能影响：{f['impact']} 建议：{f['fix_advice']}"
                if f.get('location_version') == 'BEFORE_DELETION':
                    text += ' 位置对应删除前的代码。'
                if source == '上下文核查线索':
                    text += ' 条件：'+('；'.join(f['preconditions']) or '实际可达性未确认')
                    text += ' 未确认：'+('；'.join(f['unknowns']) or '尚未运行验证')
                lines.append(text)
            if total > 3:
                lines.append(f'另有 {total-3} 项已保留在本次核查记录中。')
            if static['coverage'] not in {'FULL','SCOPED'} or review['coverage'] == 'PARTIAL' or record['limitations']:
                lines.append('覆盖有限：'+('；'.join(review['limitations'][:5]) or '静态能力或任务上下文有未完成范围。'))
            lines.append('仅覆盖本任务的局部静态检查和代码上下文核查，未验证运行行为；风险尚未修复。' if total else '仅覆盖本任务的局部静态检查和代码上下文核查，未验证运行行为。')
            result['development_summary'] = '\n'.join(lines)
        else:
            result['development_summary'] = ''
        return result

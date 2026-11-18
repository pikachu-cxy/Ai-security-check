"""Planner handoff and task leases for bounded, read-only business audits."""
import hashlib
import hmac
import secrets
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import audit_assets, incremental_audit as stream
from .development_risks import BusinessReview, Observation, require, safe
from .development_views import EvidenceWindow, read_contexts
from .review_delivery import json_bytes, response_budget
from .scan_request import relative_path
from .user_config import batch_config

MAX_TASKS = 4
MAX_WINDOWS = 48
DEADLINE_SECONDS = 600


class AuditTask(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    direction: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=400)
    priority: int = Field(ge=1, le=5)
    asset_ids: list[str] = Field(min_length=1, max_length=12)
    depends_on: list[str] = Field(default_factory=list, max_length=4)
    paths: list[str] = Field(default_factory=list, max_length=8)
    evidence_windows: list[EvidenceWindow] = Field(default_factory=list, max_length=8)
    resolves: list[str] = Field(default_factory=list, max_length=8)


class FactSuggestion(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    from_id: str | None = Field(default=None, max_length=50)
    to_id: str | None = Field(default=None, max_length=50)
    from_line: int | None = Field(default=None, ge=1)
    to_line: int | None = Field(default=None, ge=1)
    kind: Literal['DECLARES', 'CONTAINS', 'LOCAL_DECLARATION_CANDIDATE']
    evidence_ref: str = Field(max_length=80)


class TaskResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    conclusion: str = Field(min_length=1, max_length=600)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    gaps: list[str] = Field(default_factory=list, max_length=8)
    hypotheses: list[str] = Field(default_factory=list, max_length=8)
    resolves: list[str] = Field(default_factory=list, max_length=8)
    suggestions: list[FactSuggestion] = Field(default_factory=list, max_length=12)


def current(check):
    job = check.get('deep_audit')
    if job and job['dirty_seq'] == check['dirty_seq']:
        return job
    return None


def authenticate(check, token, agent_ref):
    job = current(check)
    grant = (job or {}).get('workers', {}).get(agent_ref)
    require(grant and isinstance(token, str) and
            hmac.compare_digest(grant['token_hash'], hashlib.sha256(token.encode()).hexdigest()),
            'AUDIT_CAPABILITY_INVALID')
    return job


def status(job):
    return dict(audit_round=job['round_id'], dirty_seq=job['dirty_seq'],
                stage=job['stage'], wave=job['wave'], worker_limit=job['worker_limit'],
                worker_count=len(job['workers']), stop_reason=job.get('stop_reason'),
                windows_left=MAX_WINDOWS - job['windows_used'],
                tasks=[{k: t[k] for k in ('id', 'direction', 'state', 'wave')} for t in job['tasks']])


def _planner_view(job):
    tasks = [t for t in job['tasks'] if t['wave'] == job['wave']]
    ready = bool(tasks) and all(t['state'] == 'VERIFIED' for t in tasks)
    if not ready:
        return status(job)
    return dict(status(job), new_facts=job.get('new_facts', []),
                conclusions=[dict(task_id=t['id'], conclusion=t['result']['conclusion'],
                                  gaps=t['result']['gaps']) for t in tasks],
                unresolved=_unresolved(job),
                planner_instruction='可结束并说明理由，或只为影响结论的未解决缺口提交第二轮任务。')


def _unresolved(job):
    resolved = {gap for t in job['tasks'] if t['state'] == 'VERIFIED'
                for gap in t['result']['resolves']}
    return [dict(id=f"{t['id']}:{i}", task_id=t['id'], reason=gap)
            for t in job['tasks'] if t['state'] == 'VERIFIED'
            for i, gap in enumerate(t['result']['gaps']) if f"{t['id']}:{i}" not in resolved]


def prepare(risks, related_paths, host_parallel):
    check = risks.current_check()
    policy = batch_config(check)
    require(policy['agent']['audit_business_logic'] and
            policy['development']['business_audit_mode'] == 'deep', 'DEEP_AUDIT_DISABLED')
    existing = current(check)
    if existing:
        return _initial_view(existing) if existing['wave'] == 0 else _planner_view(existing)
    if check['owner'].get('host') != 'codex' or not host_parallel:
        return fallback(risks, check, related_paths, 'HOST_PARALLEL_UNAVAILABLE')
    paths = list(check['observed_paths'])
    require(paths, 'BUSINESS_AUDIT_NO_OBSERVED_PATHS')
    related = sorted({relative_path(path) for path in related_paths} - set(paths))
    windows, nodes, edges, gaps = audit_assets.plan(risks.root, paths, related)
    context = read_contexts(risks, [EvidenceWindow(**w, related=w['file_path'] in related)
                                    for w in windows])
    graph = audit_assets.project(nodes, edges, gaps, context['evidence'])
    graph['gaps'].extend(dict(file_path=e['file_path'], reason=e['reason_code']) for e in context['errors'])
    audit_assets.bound(graph, response_budget(check) - 6000)
    if not graph['nodes']:
        return fallback(risks, check, related, 'NO_SUPPORTED_ASSETS')
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        require(row['dirty_seq'] == check['dirty_seq'] == context['dirty_seq'], 'AUDIT_ROUND_CHANGED')
        require(not current(row), 'DEEP_AUDIT_ALREADY_PREPARED')
        require(not (row.get('audit_delegate') or {}).get('agent_ref') or
                row['audit_delegate'].get('revoked'), 'DEEP_AUDIT_STANDARD_EXECUTOR_ACTIVE')
        stream.record_changes(row, paths if not row.get('audit_stream') else [])
        round_id = stream.progress(row)['round_id']
        job = dict(dirty_seq=row['dirty_seq'], round_id=round_id, wave=0, stage='PLANNING',
                   asset_graph=graph, paths=paths, related=related, tasks=[], workers={},
                   worker_limit=policy['development']['business_audit_workers'],
                   windows_used=len(windows), deadline=time.time() + DEADLINE_SECONDS)
        row['deep_audit'] = job
        risks.checks._put(db, risks.ref, row)
    return _initial_view(job)


def fallback(risks, check, related_paths, reason):
    from .audit_stream_service import manage

    result = manage(risks, 'prepare', related_paths=related_paths)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        require(row['dirty_seq'] == check['dirty_seq'], 'AUDIT_ROUND_CHANGED')
        row['audit_mode_fallback'] = dict(dirty_seq=row['dirty_seq'], reason=reason)
        risks.checks._put(db, risks.ref, row)
    return dict(result, deep_fallback=reason, execution_mode='standard')


def _initial_view(job):
    return dict(status(job), asset_graph=job['asset_graph'], changed_paths=job['paths'][:50],
                execution_mode='deep',
                planner_instruction='按业务问题规划最多 4 个只读任务，填目标 asset_ids、方向、问题、优先级、'
                f"建议证据范围及依赖。Planner 只规划。提交 deep_plan 后，先并发启动 {job['worker_limit']} 个真实只读子 Agent，"
                '用 deep_started 分别登记实际 ID，再分别交付各自 child_call。'
                '子 Agent 直接提交并领取后续任务，父会话通过 deep_status 获取结构化结论。'
                '若无法派发，使用 deep_finish 结束并记录宿主限制。')


def manage(risks, action, *, tasks=(), agent_ref=None, reason=None, related_paths=(), host_parallel=False,
           task_id=None):
    if action == 'prepare':
        return prepare(risks, related_paths, host_parallel)
    if action == 'status':
        job = current(risks.current_check())
        return _planner_view(job) if job else dict(stage='AUDIT_ROUND_CHANGED')
    if action == 'finish':
        return finish(risks, reason)
    token = None
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        job = current(row)
        require(job, 'AUDIT_ROUND_CHANGED')
        require(job['stage'] not in {'COMPLETE', 'PARTIAL'}, 'DEEP_AUDIT_CLOSED')
        require(time.time() < job['deadline'], 'DEEP_AUDIT_BUDGET_EXHAUSTED')
        if action == 'plan':
            if job['wave']:
                ledger = risks.load(db)
                for task in job['tasks']:
                    if task['state'] == 'VERIFIED':
                        receipt = row['audit_stream']['receipts'][task['request_id']]
                        for ref in _proof_refs(receipt['payload']):
                            risks.evidence(ledger, [ref])
            _plan(job, tasks)
        elif action == 'authorize_paths':
            task = next((t for t in job['tasks'] if t['id'] == task_id), None)
            require(task and task['state'] in {'QUEUED', 'RUNNING'}, 'DEEP_AUDIT_TASK_CHANGED')
            requested = {relative_path(path) for path in related_paths}
            related = set(job['related']) | (requested - set(job['paths']))
            paths = set(task['paths']) | requested
            require(0 < len(requested) <= 8 and len(related) <= 50 and len(paths) <= 8,
                    'AUDIT_RELATED_LIMIT')
            job['related'] = sorted(related)
            task['paths'] = sorted(paths)
        else:
            require(action == 'started' and job['stage'] == 'WORKING', 'DEEP_AUDIT_ACTION_INVALID')
            require(isinstance(agent_ref, str) and 1 <= len(agent_ref) <= 200
                    and agent_ref not in job['workers'] and
                    len(job['workers']) < job['worker_limit'], 'DEEP_AUDIT_WORKER_LIMIT')
            token = 'deep1-' + secrets.token_hex(32)
            job['workers'][agent_ref] = dict(token_hash=hashlib.sha256(token.encode()).hexdigest())
        risks.checks._put(db, risks.ref, row)
    result = status(job)
    if token:
        result['child_call'] = dict(tool='development_review', operation='process_development_audit',
            arguments=dict(workspace_path=str(risks.root), check_ref=risks.ref, agent_ref=agent_ref,
                           audit_token=token, action='claim'))
    return result


def _plan(job, values):
    wave = job['wave'] + 1
    require(1 <= len(values) <= MAX_TASKS and wave <= 2, 'DEEP_AUDIT_PLAN_LIMIT')
    require(all(t['state'] == 'VERIFIED' for t in job['tasks']), 'DEEP_AUDIT_TASKS_PENDING')
    assets = {node['id']: node for node in job['asset_graph']['nodes']}
    unresolved = {gap['id'] for gap in _unresolved(job)}
    allowed = set(job['paths']) | set(job['related'])
    verified = {t['id'] for t in job['tasks']}
    signatures = set()
    additions = []
    for index, value in enumerate(values, 1):
        task = AuditTask.model_validate(value).model_dump()
        identifier = f'w{wave}-t{index}'
        require(set(task['asset_ids']) <= assets.keys(), 'DEEP_AUDIT_ASSET_UNKNOWN')
        paths = {assets[a]['file_path'] for a in task['asset_ids']} | {relative_path(p) for p in task['paths']}
        task['paths'] = sorted(paths)
        require(len(paths) <= 8 and paths <= allowed, 'DEEP_AUDIT_PATH_FORBIDDEN')
        require(set(task['depends_on']) <= verified, 'DEEP_AUDIT_DEPENDENCY_INVALID')
        require(all(w['file_path'] in paths and w['start_line'] <= w['end_line'] < w['start_line'] + 80
                    for w in task['evidence_windows']), 'AUDIT_WINDOWS_INVALID')
        require((wave == 1 and not task['resolves']) or
                (task['resolves'] and set(task['resolves']) <= unresolved), 'DEEP_AUDIT_FOLLOWUP_INVALID')
        direction = safe(task['direction']).strip()
        question = safe(task['question']).strip()
        signature = (direction.casefold(), question.casefold(), tuple(sorted(set(task['asset_ids']))))
        require(direction and question and signature not in signatures, 'DEEP_AUDIT_TASK_DUPLICATE')
        signatures.add(signature)
        additions.append(dict(task, id=identifier, direction=direction, question=question,
                              state='QUEUED', wave=wave))
        verified.add(identifier)
    job.update(wave=wave, stage='WORKING', new_facts=[])
    job['tasks'].extend(additions)


def _claim(row, job, agent_ref, token):
    now = time.time()
    batches = row['audit_stream']['batches']
    for task in job['tasks']:
        if task['state'] == 'RUNNING' and batches[task['batch_id']]['lease_until'] <= now:
            stream.cancel(row, task['batch_id'])
            task['state'] = 'QUEUED'
    for task in job['tasks']:
        if task['state'] == 'RUNNING' and batches[task['batch_id']]['agent_ref'] == agent_ref:
            return task
    done = {t['id'] for t in job['tasks'] if t['state'] == 'VERIFIED'}
    for task in sorted(job['tasks'], key=lambda t: -t['priority']):
        if task['state'] != 'QUEUED' or not set(task['depends_on']) <= done:
            continue
        require(len(batches) < stream.MAX_BATCHES, 'BUSINESS_AUDIT_CAPACITY_REQUIRED')
        identifier = 'ab-' + secrets.token_hex(12)
        batches[identifier] = dict(batch_id=identifier, round_id=job['round_id'], task_id=task['id'],
            status='RUNNING', agent_ref=agent_ref, token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_at=now, lease_until=min(now + stream.LEASE_SECONDS, job['deadline']))
        task.update(state='RUNNING', batch_id=identifier)
        return task
    return None


def _task(row, job, batch_id, token, agent_ref, *, retry=False):
    batch = stream.authenticate(row, batch_id, token, agent_ref)
    task = next((t for t in job['tasks'] if t.get('batch_id') == batch_id), None)
    require(task and batch['round_id'] == job['round_id'], 'DEEP_AUDIT_TASK_CHANGED')
    if retry and task['state'] == 'VERIFIED':
        return task, batch
    require(job['stage'] == 'WORKING' and task['state'] == 'RUNNING' and
            batch['lease_until'] > time.time(), 'DEEP_AUDIT_LEASE_EXPIRED')
    return task, batch


def process(risks, action, *, audit_token, agent_ref, batch_id=None, request_id=None,
            windows=(), observations=(), business_reviews=(), task_result=None):
    if action == 'read':
        return _read(risks, audit_token, agent_ref, batch_id, windows)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        job = authenticate(row, audit_token, agent_ref)
        if action == 'claim':
            require(job['stage'] == 'WORKING' and time.time() < job['deadline'], 'DEEP_AUDIT_CLOSED')
            task = _claim(row, job, agent_ref, audit_token)
            output = dict(task=None, scanner_run=False)
            if task:
                output['task'] = {k: v for k, v in task.items() if k != 'result'}
                output['assets'] = [n for n in job['asset_graph']['nodes'] if n['id'] in task['asset_ids']]
                output['instructions'] = ('先按需要 read 后直接 submit，使用已读取的 evidence_refs、'
                    'business_reviews、observations 和 task_result。提交后可用 claim 领下一项。'
                    '没有任务时向父会话报告空闲，等待续接。')
        elif action == 'recover':
            task, batch = _task(row, job, batch_id, audit_token, agent_ref, retry=True)
            receipt = row['audit_stream']['receipts'].get(request_id)
            require(receipt and receipt['batch_id'] == batch_id, 'BUSINESS_AUDIT_RECEIPT_UNKNOWN')
            return _receipt(receipt, task, True)
        elif action == 'heartbeat':
            _, batch = _task(row, job, batch_id, audit_token, agent_ref)
            batch['lease_until'] = min(time.time() + stream.LEASE_SECONDS, job['deadline'])
            output = dict(lease_until=batch['lease_until'], scanner_run=False)
        else:
            require(action == 'submit', 'AUDIT_ACTION_INVALID')
            task, batch = _task(row, job, batch_id, audit_token, agent_ref, retry=True)
            output = _submit(risks, risks.load(db), row, job, task, batch, audit_token, request_id,
                             observations, business_reviews, task_result)
        risks.checks._put(db, risks.ref, row)
    return output


def _read(risks, token, agent_ref, batch_id, windows):
    require(windows and len(windows) <= 20, 'AUDIT_WINDOWS_INVALID')
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        job = authenticate(row, token, agent_ref)
        task, _ = _task(row, job, batch_id, token, agent_ref)
        extra = {relative_path(w['file_path']) for w in windows} - set(task['paths'])
        if extra:
            return dict(error='AUDIT_RELATED_AUTHORIZATION_REQUIRED', task_id=task['id'],
                        requested_related_paths=sorted(extra), parent_action='deep_authorize_paths',
                        scanner_run=False)
        require(job['windows_used'] + len(windows) <= MAX_WINDOWS, 'DEEP_AUDIT_BUDGET_EXHAUSTED')
        job['windows_used'] += len(windows)
        risks.checks._put(db, risks.ref, row)
    result = read_contexts(risks, [EvidenceWindow(**dict(w, related=True)) for w in windows])
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        job = authenticate(row, token, agent_ref)
        _, batch = _task(row, job, batch_id, token, agent_ref)
        require(result['dirty_seq'] == job['dirty_seq'], 'AUDIT_ROUND_CHANGED')
        batch['issued_evidence'] = sorted(set(batch.get('issued_evidence', [])) |
                                          {e['evidence_ref'] for e in result['evidence']})
        risks.checks._put(db, risks.ref, row)
    return result


def _receipt(receipt, task, repeated=False):
    return dict(received=True, repeated=repeated, task_id=task['id'],
                status=receipt['status'], request_id=receipt['request_id'], scanner_run=False)


def _submit(risks, ledger, row, job, task, batch, token, request_id, observations, reviews, result):
    from .audit_stream_service import _scrub

    values = [Observation.model_validate(v).model_dump() for v in observations]
    coverage = [BusinessReview.model_validate(v).model_dump() for v in reviews]
    require(result is not None and len(values) <= 16 and len(coverage) <= 8, 'DEEP_AUDIT_RESULT_INVALID')
    require(all(item['coverage'] and (item['coverage'] == 'PARTIAL') == bool(item['uncovered'])
                for item in coverage), 'BUSINESS_COVERAGE_DETAIL_REQUIRED')
    conclusion = TaskResult.model_validate(result).model_dump()
    gaps = [gap for item in coverage for gap in item['uncovered']]
    conclusion['gaps'] = list(dict.fromkeys([*conclusion['gaps'], *gaps]))[:8]
    payload = _scrub(dict(observations=values, business_reviews=coverage, task_result=conclusion))
    require(json_bytes(payload) <= 32768, 'DEEP_AUDIT_RESULT_LIMIT')
    if task['state'] == 'VERIFIED':
        return _receipt(stream.receive(row, batch['batch_id'], token, request_id, payload), task, True)
    require(set(conclusion['resolves']) <= set(task['resolves']), 'DEEP_AUDIT_FOLLOWUP_INVALID')
    require(all(not v.get('same_issue_as') and not v.get('scan_id') and not v.get('duplicate_of') for v in values),
            'AUDIT_SCANNER_AUTHORITY_FORBIDDEN')
    issued = set(batch.get('issued_evidence', []))
    supported = set(task['paths']) & set(job['paths'])
    require(all(v['file_path'] in supported for v in [*values, *coverage]), 'AUDIT_PATH_NOT_CLAIMED')
    checked_paths = {item['file_path'] for item in coverage}
    proof_paths = set()
    for item in [*values, *coverage, conclusion]:
        refs = item['evidence_refs']
        require(set(refs) <= issued, 'AUDIT_EVIDENCE_NOT_ISSUED')
        evidence = risks.evidence(ledger, refs)
        proof_paths.update(e['file_path'] for e in evidence)
        require(all(e['dirty_seq'] == job['dirty_seq'] for e in evidence), 'AUDIT_ROUND_CHANGED')
        if 'file_path' in item:
            path = item['file_path']
            require(path in checked_paths and any(e['file_path'] == path and
                    ('line_start' not in item or
                     e['line_start'] <= item['line_start'] <= item['line_end'] <= e['line_end'])
                    for e in evidence), 'DEVELOPMENT_RISK_LOCATION_UNREAD')
    receipt = stream.receive(row, batch['batch_id'], token, request_id, payload)
    receipt['status'] = 'VERIFIED'
    batch['status'] = 'COMPLETE'
    task.update(state='VERIFIED', request_id=request_id, result=payload['task_result'],
                proof_paths=sorted(proof_paths))
    _verify_suggestions(risks, ledger, job, issued, conclusion['suggestions'])
    return _receipt(receipt, task)


def _verify_suggestions(risks, ledger, job, issued, suggestions):
    graph = job['asset_graph']
    for suggestion in suggestions:
        ref = suggestion['evidence_ref']
        require(ref in issued, 'AUDIT_EVIDENCE_NOT_ISSUED')
        evidence = risks.evidence(ledger, [ref], include_source=True)[0]
        path = evidence['file_path']
        if not path.endswith('.java'):
            continue
        import javalang
        try:
            nodes, edges, _ = audit_assets._parse(path, evidence.pop('_source'), evidence['sha256'], set(), True)
        except (ValueError, KeyError, IndexError, RecursionError,
                javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
            continue
        projected = audit_assets.project(nodes, edges, [], [dict(evidence, evidence_ref=ref)])
        existing = {n['id'] for n in graph['nodes']}
        matched = []
        nodes = {n['id']: n for n in projected['nodes']}
        for edge in projected['edges']:
            if edge['kind'] != suggestion['kind']:
                continue
            pair = [nodes[edge[key]] for key in ('from_id', 'to_id')]
            if all((suggestion[prefix+'_id'] is not None or suggestion[prefix+'_line'] is not None)
                   and suggestion[prefix+'_id'] in {None, node['id']}
                   and suggestion[prefix+'_line'] in {None, node['line_start']}
                   for prefix, node in zip(('from', 'to'), pair)):
                matched.append((edge, pair))
        if len(matched) != 1:
            continue
        edge, pair = matched[0]
        new = [node for node in pair if node['id'] not in existing]
        if (edge in graph['edges'] or len(graph['edges']) >= 112
                or len(graph['nodes']) + len(new) > 80):
            continue
        graph['nodes'].extend(new)
        graph['edges'].append(edge)
        job['new_facts'].extend([*new, edge])


def _proof_refs(payload):
    conclusion = payload['task_result']
    items = [*payload['business_reviews'], *payload['observations'], conclusion]
    return {ref for item in items for ref in item['evidence_refs']} | {
        s['evidence_ref'] for s in conclusion['suggestions']}


def finish(risks, reason):
    check = risks.current_check()
    job = current(check)
    require(job, 'AUDIT_ROUND_CHANGED')
    if job['stage'] in {'COMPLETE', 'PARTIAL'}:
        return status(job)
    require(isinstance(reason, str) and 0 < len(reason.strip()) <= 500, 'DEEP_AUDIT_REASON_REQUIRED')
    values, reviews, proof, gaps = {}, {}, set(), []
    ledger = risks.load()
    for task in job['tasks']:
        if task['state'] != 'VERIFIED':
            gaps.append(f"{task['id']} {task['direction']} 未完成")
            continue
        payload = check['audit_stream']['receipts'][task['request_id']]['payload']
        refs = _proof_refs(payload)
        try:
            for ref in refs:
                risks.evidence(ledger, [ref])
        except (OSError, ValueError):
            gaps.append(f"{task['id']} {task['direction']} 的证据已失效")
            continue
        proof.update(refs)
        for item in payload['business_reviews']:
            name = item['file_path']
            previous = reviews.get(name)
            if previous:
                item = dict(item, evidence_refs=list(dict.fromkeys([
                    *item['evidence_refs'], *previous['evidence_refs']]))[:20])
                if previous['coverage'] != 'COMPLETE' and not task['result']['resolves']:
                    item.update(coverage='PARTIAL', uncovered=previous.get('uncovered') or ['先前任务有覆盖缺口'])
            reviews[name] = item
        for item in payload['observations']:
            key = item['file_path'], item['category'], item['issue_key']
            previous = values.get(key)
            if previous and previous['decision'] != item['decision']:
                gaps.append(f"{task['id']} 存在需要人工复核的发现分歧")
                item = dict(item, decision='INCONCLUSIVE')
            values[key] = item
    gaps.extend(g['reason'] for g in _unresolved(job))
    omitted = set(job['paths']) - reviews.keys()
    gaps.extend(f'{name} 缺少当前版本的审计回执' for name in sorted(omitted)[:30])
    gaps.extend(f'{name} 审计覆盖不足' for name, item in reviews.items() if item['coverage'] != 'COMPLETE')
    if not job['tasks']:
        gaps.append('未提交计划或宿主中断')
    if time.time() >= job['deadline'] or job['windows_used'] >= MAX_WINDOWS:
        gaps.append('本次审计共享预算已用完')
    if len(values) > 50 or len(reviews) > 50:
        gaps.append('审计结果超出单次报告保存容量')
    reviews = dict(list(reviews.items())[:50])
    commit = dict(deep=True, batch_id='deep-' + secrets.token_hex(12), round_id=job['round_id'],
                  snapshot=stream._digest(job), evidence_refs=sorted(proof), valid_paths=sorted(reviews),
                  stop_reason=safe(reason), gaps=list(dict.fromkeys(gaps))[:40])
    risks._submit([v for v in list(values.values())[:50] if v['file_path'] in reviews],
        job['dirty_seq'], business_reviews=list(reviews.values()), return_risks=False,
        scan_id=None, audit_id=None, stream_commit=commit)
    return status(current(risks.current_check()))


def validate_finish(risks, row, check, commit):
    job = current(check)
    require(job and job['round_id'] == commit['round_id'] and stream._digest(job) == commit['snapshot'],
            'DEEP_AUDIT_FINALIZATION_CHANGED')
    for ref in commit['evidence_refs']:
        risks.evidence(row, [ref])


def seal_finish(check, commit, business_reviews):
    job = current(check)
    require(job and stream._digest(job) == commit['snapshot'], 'DEEP_AUDIT_FINALIZATION_CHANGED')
    progress = stream.progress(check)
    require(job['round_id'] == progress['round_id'], 'AUDIT_ROUND_CHANGED')
    state = check['audit_stream']
    current_round = state['rounds'][-1]
    versions = {name: current_round['required'][name] for name in commit['valid_paths']
                if name in current_round['required']}
    identifier = commit['batch_id']
    require(len(state['batches']) < stream.MAX_BATCHES and len(state['receipts']) < stream.MAX_RECEIPTS,
            'BUSINESS_AUDIT_CAPACITY_REQUIRED')
    state['batches'][identifier] = dict(batch_id=identifier, status='RECEIVED',
        round_id=job['round_id'], request_id=identifier, versions=versions, aggregate=True)
    state['receipts'][identifier] = dict(request_id=identifier, batch_id=identifier, status='RECEIVED',
        payload=dict(business_reviews=business_reviews), applied_paths=[])
    dependencies = {p: sorted({e for t in job['tasks'] if t['state'] == 'VERIFIED'
                                for e in t.get('proof_paths', [])}) for p in versions}
    stream.complete(check, identifier, identifier, list(versions), dependencies=dependencies)
    for task in job['tasks']:
        if task['state'] == 'RUNNING':
            stream.cancel(check, task['batch_id'])
    job.update(stage='PARTIAL' if commit['gaps'] else 'COMPLETE',
               stop_reason=commit['stop_reason'], gaps=commit['gaps'],
               reviewed_paths=commit['valid_paths'], published_evidence=commit['evidence_refs'],
               publication_id=identifier)


def revalidate(risks, check, row):
    job = current(check)
    if not job or job['stage'] not in {'COMPLETE', 'PARTIAL'} or job.get('evidence_stale'):
        return
    try:
        for ref in job['published_evidence']:
            risks.evidence(row, [ref])
    except (OSError, ValueError):
        stream_data = check['audit_stream']
        publication_id = job['publication_id']
        for round_data in stream_data['rounds']:
            for path, accepted in list(round_data['accepted'].items()):
                if accepted['request_id'] == publication_id:
                    round_data['accepted'].pop(path)
                    round_data['pending'][path] = accepted['seq']
        for path, accepted in list(stream_data['accepted_current'].items()):
            if accepted['request_id'] == publication_id:
                stream_data['accepted_current'].pop(path)
        job.update(stage='PARTIAL', evidence_stale=True, reviewed_paths=[],
                   gaps=[*job['gaps'], '本轮共享证据版本已变化，须按当前代码重新核验'])

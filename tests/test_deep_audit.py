from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import shutil
import sqlite3
from threading import Barrier
from time import monotonic

import pytest

from security_runtime import deep_audit
from security_runtime.audit_stream_service import process, valid_reviews
from security_runtime.development_risks import DevelopmentRisks
from security_runtime.audit_graph_view import dashboard_view, graphs, evidence_view, report_lines
from test_audit_assets import spring_source
from test_development_risks import sample


@pytest.fixture
def prepared(sample):
    root, service, _, _ = sample
    path = 'Refund.java'
    (root / path).write_text(spring_source(True), encoding='utf-8')
    ref = service.begin(root, 'refund')['check_ref']
    service.record(root, ref, [path])
    risks = DevelopmentRisks(service, root, ref)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['effective_config']['values']['development']['business_audit_mode'] = 'deep'
        risks.checks._put(db, ref, row)
    first = deep_audit.manage(risks, 'prepare', host_parallel=True)
    assert first['stage'] == 'PLANNING'
    entry = next(n for n in first['asset_graph']['nodes'] if n['kind'] == 'ENTRY')
    task = dict(direction='归属', question='调用前是否核对归属？', asset_ids=[entry['id']], priority=5)
    deep_audit.manage(risks, 'plan', tasks=[task, dict(task, direction='状态', question='状态检查在哪里？')])
    workers = []
    for name in ['actual-first', 'actual-second']:
        arguments = deep_audit.manage(risks, 'started', agent_ref=name)['child_call']['arguments']
        workers.append({key: arguments[key] for key in ['audit_token', 'agent_ref']})
    return root, service, ref, risks, path, task, workers


def test_unavailable_host_uses_standard_handoff(sample):
    _, _, ref, risks = sample
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['effective_config']['values']['development']['business_audit_mode'] = 'deep'
        risks.checks._put(db, ref, row)
    reply = deep_audit.manage(risks, 'prepare', host_parallel=False)
    assert reply['execution_mode'] == 'standard'
    assert reply['registration']['action'] == 'stream_started'
    assert '单 Worker' in report_lines(risks.current_check())[0]


def read(risks, path, worker, batch):
    result = process(risks, 'read', **worker, batch_id=batch, windows=[
        dict(file_path=path, start_line=104, end_line=110)])
    assert result['evidence'], result['errors']
    return result['evidence'][0]['evidence_ref']


def payload(path, ref, **extra):
    return dict(task_result=dict(conclusion='检查现有规则', evidence_refs=[ref], **extra),
                business_reviews=[dict(file_path=path, rationale='按代码窗口检查', evidence_refs=[ref],
                                       coverage='COMPLETE')])


def test_concurrent_claim_reads_and_idempotent_receipts(prepared):
    _, _, _, risks, path, base, workers = prepared
    ready = Barrier(2, timeout=20)

    def work(worker):
        start = monotonic()
        task = process(risks, 'claim', **worker)['task']
        batch = task['batch_id']
        assert process(risks, 'claim', **worker)['task']['batch_id'] == batch
        ready.wait()
        ref = read(risks, path, worker, batch)
        fields = dict(batch_id=batch, request_id='receipt-' + task['id'], **worker)
        data = payload(path, ref, gaps=['核对状态边界'] if task['id'] == 'w1-t2' else [])
        receipt = process(risks, 'submit', **fields, **data)
        assert process(risks, 'submit', **fields, **data)['repeated']
        assert process(risks, 'recover', **fields)['task_id'] == task['id']
        return start, monotonic(), task, receipt, ref

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(work, workers))
    assert max(first[0], second[0]) < min(first[1], second[1])
    assert first[2]['id'] != second[2]['id']
    assert first[4] == second[4]
    assert {first[3]['status'], second[3]['status']} == {'VERIFIED'}
    gap = deep_audit.manage(risks, 'status')['unresolved'][0]
    deep_audit.manage(risks, 'plan', tasks=[dict(base, resolves=[gap['id']], depends_on=[gap['task_id']])])
    followup = process(risks, 'claim', **workers[0])['task']
    assert process(risks, 'claim', **workers[1])['task'] is None
    batch = followup['batch_id']
    ref = read(risks, path, workers[0], batch)
    process(risks, 'submit', **workers[0], batch_id=batch, request_id='second-wave',
            **payload(path, ref, resolves=[gap['id']]))
    result = deep_audit.manage(risks, 'finish', reason='计划内任务及补证已完成')
    assert result['stage'] == 'COMPLETE'
    assert path in valid_reviews(risks.current_check())


def test_timeout_reclaims_and_changed_source_rejects_late_task(prepared):
    root, service, ref, risks, path, _, workers = prepared
    first = process(risks, 'claim', **workers[0])['task']
    old = first['batch_id']
    ref_proof = read(risks, path, workers[0], old)
    with pytest.raises(ValueError, match='TOKEN_INVALID'):
        read(risks, path, workers[1], old)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['audit_stream']['batches'][old]['lease_until'] = 0
        risks.checks._put(db, ref, row)
    reissued = process(risks, 'claim', **workers[1])['task']
    assert reissued['id'] == first['id'] and reissued['batch_id'] != old
    with pytest.raises(ValueError, match='CANCELLED'):
        process(risks, 'submit', **workers[0], batch_id=old, request_id='late-lease',
                **payload(path, ref_proof))
    (root / path).write_text(spring_source(False), encoding='utf-8')
    service.record(root, ref, [path])
    with pytest.raises(ValueError, match='CAPABILITY_INVALID'):
        process(risks, 'submit', **workers[1], batch_id=reissued['batch_id'], request_id='late-version',
                **payload(path, ref_proof))
    assert risks.current_check()['deep_audit']['stage'] == 'SUPERSEDED'
    assert not valid_reviews(risks.current_check())


def test_unfinished_and_exhausted_are_partial(prepared):
    _, _, ref, risks, _, _, _ = prepared
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['deep_audit']['windows_used'] = deep_audit.MAX_WINDOWS
        risks.checks._put(db, ref, row)
    assert deep_audit.manage(risks, 'finish', reason='共享取证预算耗尽')['stage'] == 'PARTIAL'
    assert '本次审计共享预算已用完' in risks.current_check()['deep_audit']['gaps']


def test_related_guard_is_task_authorized_and_rechecked_at_finish(prepared):
    root, _, _, risks, path, _, workers = prepared
    guard = root / 'Guard.java'
    guard.write_text('class Guard { boolean allowed() { return true; } }\n', encoding='utf-8')
    windows = [dict(file_path='Guard.java', start_line=1, end_line=1)]
    shared = []
    for index, worker in enumerate(workers):
        task = process(risks, 'claim', **worker)['task']
        batch = task['batch_id']
        assert process(risks, 'read', **worker, batch_id=batch, windows=windows)[
            'parent_action'] == 'deep_authorize_paths'
        deep_audit.manage(risks, 'authorize_paths', related_paths=['Guard.java'], task_id=task['id'])
        proof = process(risks, 'read', **worker, batch_id=batch, windows=windows)['evidence'][0]['evidence_ref']
        shared.append(proof)
        local = read(risks, path, worker, batch)
        data = payload(path, local)
        data['task_result']['evidence_refs'].append(proof)
        assert process(risks, 'submit', **worker, batch_id=batch, request_id=f'guard-proof-{index}',
                       **data)['status'] == 'VERIFIED'
    assert shared[0] == shared[1]
    guard.write_text('class Guard { boolean allowed() { return false; } }\n', encoding='utf-8')
    result = deep_audit.manage(risks, 'finish', reason='准备交付')
    assert result['stage'] == 'PARTIAL'
    assert sum('证据已失效' in gap for gap in risks.current_check()['deep_audit']['gaps']) == 2
    assert not valid_reviews(risks.current_check())


def test_final_risk_uses_original_ledger_and_graph_versions(prepared):
    root, _, _, risks, path, _, workers = prepared
    with_source = root / path
    evidence_refs = []
    for index, worker in enumerate(workers):
        task = process(risks, 'claim', **worker)['task']
        batch = task['batch_id']
        ref = read(risks, path, worker, batch)
        evidence_refs.append(ref)
        data = payload(path, ref)
        if index == 0:
            data['observations'] = [dict(issue_key='refund-status', file_path=path,
                category='business-logic', title='退款状态未核验', severity='HIGH', decision='CONFIRMED',
                line_start=106, line_end=106, description='写入前没有状态校验',
                impact='可从不符合条件的状态转移', fix_advice='在写入前核验原状态',
                rationale='局部代码仅包含归属检查和写入', evidence_refs=[ref])]
        process(risks, 'submit', **worker, batch_id=batch, request_id=f'report-{index}', **data)
    deep_audit.manage(risks, 'finish', reason='已核验计划内的归属与状态边界')
    check = risks.current_check()
    page = graphs(check)
    assert len(page['audit_graph']['tasks']) == 2
    asset_ids = {item['id'] for item in page['asset_graph']['nodes']}
    assert all(set(t['asset_ids']) <= asset_ids for t in page['audit_graph']['tasks'])
    ledger = risks.load()
    assert len(ledger['risks']) == 1 and len(ledger['reviews']) == 1
    assert '本轮计划范围已完成' in report_lines(check)[0]
    proof = ledger['evidence'][evidence_refs[0]]
    assert evidence_view(root, proof)['current']['matches_record']
    with_source.write_text(spring_source(False), encoding='utf-8')
    assert 'current' not in evidence_view(root, proof)
    deep_audit.revalidate(risks, check, ledger)
    assert '部分完成' in report_lines(check)[0]
    assert not valid_reviews(check)


def test_dashboard_reads_only_signed_current_batch_and_owned_evidence(prepared, tmp_path, monkeypatch):
    from security_runtime import risk_dashboard
    from security_runtime.hook_state import native_io_path
    from security_runtime.project_identity import describe

    root, _, ref, risks, _, _, _ = prepared
    wid = describe(root)['workspace_id']
    state = tmp_path / 'dashboard-state'
    parent = native_io_path(state / 'global-workspaces' / wid / 'hooks' / wid)
    parent.mkdir(parents=True)
    with closing(sqlite3.connect(risks.checks.path)) as source, closing(
            sqlite3.connect(parent / 'development-checks.db')) as target:
        source.backup(target)
    shutil.copyfile(risks.checks.path.parent / 'snapshot.key', parent / 'snapshot.key')
    monkeypatch.setattr(risk_dashboard, 'STATE', state)
    query = dict(editor='codex', workspace=wid, check=ref, seq=str(risks.current_check()['dirty_seq']))
    current = dashboard_view(query)
    node = current['asset_graph']['nodes'][0]
    view = dashboard_view(dict(query, evidence=node['evidence_ref'], asset=node['id']))
    assert view['current']['matches_record'] and view['line_start'] == node['line_start']
    with pytest.raises(ValueError, match='VERSION_CHANGED'):
        dashboard_view(dict(query, seq='999'))
    with pytest.raises(ValueError, match='EVIDENCE_UNAVAILABLE'):
        dashboard_view(dict(query, evidence='unbound'))


def test_stop_reads_one_combined_partial_report(prepared):
    from security_runtime.development_views import closeout_page

    _, _, ref, risks, path, _, workers = prepared
    task = process(risks, 'claim', **workers[0])['task']
    ref_proof = read(risks, path, workers[0], task['batch_id'])
    process(risks, 'submit', **workers[0], batch_id=task['batch_id'], request_id='before-stop',
            **payload(path, ref_proof))
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        seq = row['dirty_seq']
        row.update(scan_id='scan-current', scanned_seq=seq, state='RESULTS_READY',
                   stop_closeout_notice=dict(seq=seq, scan_id='scan-current', mode='REPORT'))
        row['effective_config']['values']['agent']['review_scanner_findings'] = False
        risks.checks._put(db, ref, row)
        result = risks.load(db)
        result['imported_scan_id'] = 'scan-current'
        risks.store._put(db, ref, result)
    page = closeout_page(risks, 0, None)
    assert page['closeout_mode'] == 'REPORT'
    assert '深度业务审计部分完成' in page['report_text']
    assert '停止原因为' in page['report_text'] and path in page['report_text']
    assert '状态 未完成' in page['report_text']
    check = risks.current_check()
    assert check['stop_noticed_audit_revision'] == check['audit_result_revision']

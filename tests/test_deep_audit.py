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
from test_audit_assets import commit_file, git_repo, python_source
from test_development_risks import sample

CHANGED = 102


def setup(sample, tasks):
    root, service, _, _ = sample
    path = 'refund.py'
    git_repo(root)
    commit_file(root, path, python_source())
    (root / path).write_text(python_source('clarify'), encoding='utf-8')
    ref = service.begin(root, 'refund')['check_ref']
    service.record(root, ref, [path])
    risks = DevelopmentRisks(service, root, ref)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['effective_config']['values']['development']['business_audit_mode'] = 'deep'
        risks.checks._put(db, ref, row)
    first = deep_audit.manage(risks, 'prepare', host_parallel=True)
    assert first['stage'] == 'PLANNING'
    region = next(node for node in first['asset_graph']['nodes'] if node['kind'] == 'SOURCE_REGION')
    base = dict(asset_ids=[region['id']], priority=5,
                acceptance='指出检查所在位置，并说明当前证据能否确认它在写入前生效')
    deep_audit.manage(risks, 'plan', tasks=tasks(base))
    workers = []
    for name in ['actual-first', 'actual-second']:
        arguments = deep_audit.manage(risks, 'started', agent_ref=name)['child_call']['arguments']
        workers.append({key: arguments[key] for key in ['audit_token', 'agent_ref']})
    return root, service, ref, risks, path, base, workers


@pytest.fixture
def prepared(sample):
    return setup(sample, lambda base: [
        dict(base, direction='归属', question='调用前是否核对归属？'),
        dict(base, direction='状态', question='状态检查在哪里？')])


@pytest.fixture
def chained(sample):
    return setup(sample, lambda base: [
        dict(base, direction='归属', question='调用前是否核对归属？'),
        dict(base, direction='状态', question='状态检查在哪里？', depends_on=['w1-t1'])])


def read(risks, path, worker, batch):
    result = process(risks, 'read', **worker, batch_id=batch, windows=[
        dict(file_path=path, start_line=98, end_line=CHANGED)])
    assert result['evidence'], result['errors']
    return result['evidence'][0]['evidence_ref']


def payload(path, ref, **extra):
    return dict(task_result=dict(conclusion='检查现有规则', evidence_refs=[ref], **extra),
                business_reviews=[dict(file_path=path, rationale='按代码窗口检查', evidence_refs=[ref],
                                       coverage='COMPLETE')])


def submit(risks, worker, path, request_id, build=None, **extra):
    task = process(risks, 'claim', **worker)['task']
    batch = task['batch_id']
    ref = read(risks, path, worker, batch)
    data = payload(path, ref, **extra)
    if build:
        data.update(build(ref))
    result = process(risks, 'submit', **worker, batch_id=batch, request_id=request_id, **data)
    return task, ref, result


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


def test_cross_language_graph_returns_source_and_two_workers_claim(prepared):
    _, _, _, risks, _, _, workers = prepared
    job = deep_audit.current(risks.current_check())
    kinds = [node['kind'] for node in job['asset_graph']['nodes']]
    assert kinds[0] == 'FILE' and 'SOURCE_REGION' in kinds
    region = next(node for node in job['asset_graph']['nodes'] if node['kind'] == 'SOURCE_REGION')
    assert region['locator'] == 'GIT_HEAD_DIFF'
    assert region['line_start'] <= CHANGED <= region['line_end']
    assert job['first_package'] and 'save_refund' in job['first_package'][0]['content']
    assert job['first_package'][0]['evidence_ref'] == region['evidence_ref']
    assert region['file_path'] == 'refund.py'
    claimed = [process(risks, 'claim', **worker)['task'] for worker in workers]
    assert len({task['id'] for task in claimed}) == 2
    assert all(task['acceptance'] and task['planner_decision'] == 'PENDING' for task in claimed)


def test_worker_can_take_evidence_beyond_line_80_without_git_diff(sample):
    root, service, _, _ = sample
    path = 'new_module.py'
    (root / path).write_text('# context\n' * 100 + 'value = 1\n', encoding='utf-8')
    ref = service.begin(root, 'worker-chosen-evidence')['check_ref']
    service.record(root, ref, [path])
    risks = DevelopmentRisks(service, root, ref)
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['effective_config']['values']['development']['business_audit_mode'] = 'deep'
        risks.checks._put(db, ref, row)

    prepared = deep_audit.manage(risks, 'prepare', host_parallel=True)
    assert prepared['first_package'] == []
    file, = prepared['asset_graph']['nodes']
    assert file['kind'] == 'FILE' and file['line_count'] == 101
    window = dict(file_path=path, start_line=1, end_line=101)
    deep_audit.manage(risks, 'plan', tasks=[dict(asset_ids=[file['id']], priority=1,
        direction='赋值检查', question='核实赋值是否符合预期', acceptance='读取实际赋值行',
        evidence_windows=[window])])
    child = deep_audit.manage(risks, 'started', agent_ref='file-worker')['child_call']['arguments']
    worker = {key: child[key] for key in ('audit_token', 'agent_ref')}
    task = process(risks, 'claim', **worker)['task']
    result = process(risks, 'read', **worker, batch_id=task['batch_id'], windows=[window])
    proof, = result['evidence']
    assert (proof['line_start'], proof['line_end']) == (1, 101)
    assert proof['content'].splitlines()[-1] == 'value = 1'
    assert process(risks, 'submit', **worker, batch_id=task['batch_id'],
        request_id='worker-chosen-file-proof', **payload(path, proof['evidence_ref']))['status'] == 'VERIFIED'


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
    deep_audit.manage(risks, 'plan', tasks=[dict(base, direction='补证', question='状态边界在哪里？',
                                                 resolves=[gap['id']])])
    followup = process(risks, 'claim', **workers[0])['task']
    assert process(risks, 'claim', **workers[1])['task'] is None
    batch = followup['batch_id']
    ref = read(risks, path, workers[0], batch)
    process(risks, 'submit', **workers[0], batch_id=batch, request_id='second-wave',
            **payload(path, ref, resolves=[gap['id']]))
    for worker, request in ((workers[0], first), (workers[1], second)):
        deep_audit.manage(risks, 'decide_task', task_id=request[2]['id'],
                          receipt_id='receipt-' + request[2]['id'], decision='ACCEPTED',
                          reason='结论与证据一致')
    deep_audit.manage(risks, 'decide_task', task_id=followup['id'], receipt_id='second-wave',
                      decision='ACCEPTED', reason='补证已覆盖原缺口')
    result = deep_audit.manage(risks, 'finish', reason='计划内任务及补证已接受')
    assert result['stage'] == 'COMPLETE'
    assert path in valid_reviews(risks.current_check())


def test_board_is_visible_while_the_round_is_running(prepared):
    _, _, _, risks, path, _, workers = prepared
    a, b = workers
    task = process(risks, 'claim', **a)['task']
    batch = task['batch_id']
    ref = read(risks, path, a, batch)
    entry = dict(summary='归属检查在写入前调用', evidence_refs=[ref])
    first = process(risks, 'board', **a, batch_id=batch, request_id='board-0001',
                    board_entries=[entry])
    assert first['seq'] == 1 and first['repeated'] is False
    assert first['entries'][0]['task_id'] == task['id'] and first['entries'][0]['worker'] == a['agent_ref']
    again = process(risks, 'board', **a, batch_id=batch, request_id='board-0001',
                    board_entries=[entry])
    assert again['repeated'] is True and again['seq'] == 1 and len(again['entries']) == 1
    peer = process(risks, 'board', **b, after_seq=0)
    assert [item['seq'] for item in peer['entries']] == [1]
    assert process(risks, 'board', **b, after_seq=1)['entries'] == []
    planner = deep_audit.manage(risks, 'status')
    assert planner['stage'] == 'WORKING'
    assert planner['board']['entries'][0]['summary'] == '归属检查在写入前调用'
    other = process(risks, 'claim', **b)['task']
    with pytest.raises(ValueError, match='EVIDENCE_NOT_ISSUED'):
        process(risks, 'submit', **b, batch_id=other['batch_id'], request_id='peer-0001',
                **payload(path, ref))


def test_board_rejects_late_writes(prepared):
    root, service, ref, risks, path, _, workers = prepared
    a = workers[0]
    task = process(risks, 'claim', **a)['task']
    batch = task['batch_id']
    proof = read(risks, path, a, batch)
    entry = dict(summary='观察', evidence_refs=[proof])
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['audit_stream']['batches'][batch]['lease_until'] = 0
        risks.checks._put(db, ref, row)
    with pytest.raises(ValueError, match='LEASE_EXPIRED'):
        process(risks, 'board', **a, batch_id=batch, request_id='board-0003', board_entries=[entry])
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row['deep_audit']['stage'] = 'PARTIAL'
        risks.checks._put(db, ref, row)
    with pytest.raises(ValueError, match='CLOSED'):
        process(risks, 'board', **a, batch_id=batch, request_id='board-0004', board_entries=[entry])


def test_board_rejects_an_old_version(sample):
    root, service, ref, risks, path, _, workers = setup(sample, lambda base: [
        dict(base, direction='归属', question='调用前是否核对归属？')])
    a = workers[0]
    task = process(risks, 'claim', **a)['task']
    batch = task['batch_id']
    proof = read(risks, path, a, batch)
    (root / path).write_text(python_source('later'), encoding='utf-8')
    service.record(root, ref, [path])
    with pytest.raises(ValueError, match='CAPABILITY_INVALID'):
        process(risks, 'board', **a, batch_id=batch, request_id='board-0005',
                board_entries=[dict(summary='迟到写入', evidence_refs=[proof])])


def test_dependency_unlocks_only_after_planner_accepts(chained):
    _, _, _, risks, path, _, workers = chained
    a, b = workers
    task = process(risks, 'claim', **a)['task']
    assert task['id'] == 'w1-t1'
    assert process(risks, 'claim', **b)['task'] is None
    batch = task['batch_id']
    ref = read(risks, path, a, batch)
    assert process(risks, 'submit', **a, batch_id=batch, request_id='accept-0001',
                   **payload(path, ref))['status'] == 'VERIFIED'
    assert process(risks, 'claim', **b)['task'] is None
    view = deep_audit.manage(risks, 'status')
    assert view['tasks'][0]['planner_decision'] == 'PENDING'
    assert view['conclusions'][0]['task_id'] == 'w1-t1'
    with pytest.raises(ValueError, match='DECISION_INVALID'):
        deep_audit.manage(risks, 'decide_task', task_id='w1-t1', receipt_id='accept-0001',
                          decision='DONE', reason='试错')
    with pytest.raises(ValueError, match='RECEIPT_UNKNOWN'):
        deep_audit.manage(risks, 'decide_task', task_id='w1-t1', receipt_id='stale-receipt',
                          decision='ACCEPTED', reason='过期回执')
    deep_audit.manage(risks, 'decide_task', task_id='w1-t1', receipt_id='accept-0001',
                      decision='ACCEPTED', reason='结论与证据一致')
    assert process(risks, 'claim', **b)['task']['id'] == 'w1-t2'


def test_followup_task_is_claimable_before_the_original_is_accepted(sample):
    _, _, _, risks, path, base, workers = setup(sample, lambda base: [
        dict(base, direction='归属', question='调用前是否核对归属？')])
    a, b = workers
    task, _, _ = submit(risks, a, path, 'needs-0001', gaps=['缺少状态边界证据'])
    deep_audit.manage(risks, 'decide_task', task_id=task['id'], receipt_id='needs-0001',
                      decision='NEEDS_EVIDENCE', reason='状态边界未取证')
    gap = deep_audit.manage(risks, 'status')['unresolved'][0]
    with pytest.raises(ValueError, match='FOLLOWUP_DEPENDENCY_INVALID'):
        deep_audit.manage(risks, 'plan', tasks=[dict(
            base, direction='补证', question='状态边界在哪里？', resolves=[gap['id']],
            depends_on=[task['id']])])
    deep_audit.manage(risks, 'plan', tasks=[dict(
        base, direction='补证', question='状态边界在哪里？', resolves=[gap['id']])])
    assert process(risks, 'claim', **b)['task']['id'] == 'w2-t1'


def test_timeout_reclaims_and_changed_source_rejects_late_task(prepared):
    root, service, ref, risks, path, _, workers = prepared
    first = process(risks, 'claim', **workers[0])['task']
    old = first['batch_id']
    proof = read(risks, path, workers[0], old)
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
                **payload(path, proof))
    (root / path).write_text(python_source('later'), encoding='utf-8')
    service.record(root, ref, [path])
    with pytest.raises(ValueError, match='CAPABILITY_INVALID'):
        process(risks, 'submit', **workers[1], batch_id=reissued['batch_id'], request_id='late-version',
                **payload(path, proof))
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


def test_finish_stays_partial_until_every_task_is_accepted(prepared):
    _, _, _, risks, path, _, workers = prepared
    for index, worker in enumerate(workers):
        submit(risks, worker, path, f'open-{index:04d}')
    result = deep_audit.manage(risks, 'finish', reason='尚未判定')
    assert result['stage'] == 'PARTIAL'
    gaps = risks.current_check()['deep_audit']['gaps']
    assert sum('未被 Planner 接受' in gap for gap in gaps) == 2
    assert not valid_reviews(risks.current_check())


def test_related_guard_is_task_authorized_and_rechecked_at_finish(prepared):
    root, _, _, risks, path, _, workers = prepared
    guard = root / 'guard.py'
    guard.write_text('def allowed():\n    return True\n', encoding='utf-8')
    windows = [dict(file_path='guard.py', start_line=1, end_line=2)]
    shared = []
    for index, worker in enumerate(workers):
        task = process(risks, 'claim', **worker)['task']
        batch = task['batch_id']
        assert process(risks, 'read', **worker, batch_id=batch, windows=windows)[
            'parent_action'] == 'deep_authorize_paths'
        deep_audit.manage(risks, 'authorize_paths', related_paths=['guard.py'], task_id=task['id'])
        proof = process(risks, 'read', **worker, batch_id=batch, windows=windows)['evidence'][0]['evidence_ref']
        shared.append(proof)
        local = read(risks, path, worker, batch)
        data = payload(path, local)
        data['task_result']['evidence_refs'].append(proof)
        request_id = f'guard-proof-{index}'
        assert process(risks, 'submit', **worker, batch_id=batch, request_id=request_id,
                       **data)['status'] == 'VERIFIED'
        deep_audit.manage(risks, 'decide_task', task_id=task['id'], receipt_id=request_id,
                          decision='ACCEPTED', reason='已核对关联防护')
    assert shared[0] == shared[1]
    guard.write_text('def allowed():\n    return False\n', encoding='utf-8')
    result = deep_audit.manage(risks, 'finish', reason='准备交付')
    assert result['stage'] == 'PARTIAL'
    assert sum('证据已失效' in gap for gap in risks.current_check()['deep_audit']['gaps']) == 2
    assert not valid_reviews(risks.current_check())


def test_accepted_tasks_publish_one_combined_report(prepared):
    root, _, _, risks, path, _, workers = prepared
    proofs = []
    for index, worker in enumerate(workers):
        build = None
        if index == 0:
            def build(ref):
                return dict(observations=[dict(
                    issue_key='refund-status', file_path=path, category='business-logic',
                    title='退款状态未核验', severity='HIGH', decision='CONFIRMED',
                    line_start=CHANGED, line_end=CHANGED, description='写入前没有状态校验',
                    impact='可从不符合条件的状态转移', fix_advice='在写入前核验原状态',
                    rationale='局部代码仅包含归属检查和写入', evidence_refs=[ref])])
        task, ref, _ = submit(risks, worker, path, f'report-{index}', build=build)
        proofs.append(ref)
        deep_audit.manage(risks, 'decide_task', task_id=task['id'], receipt_id=f'report-{index}',
                          decision='ACCEPTED', reason='结论与证据一致')
    result = deep_audit.manage(risks, 'finish', reason='已核验计划内的归属与状态边界')
    assert result['stage'] == 'COMPLETE'
    check = risks.current_check()
    page = graphs(check)
    assert len(page['audit_graph']['tasks']) == 2
    assert all(task['planner_decision'] == 'ACCEPTED' for task in page['audit_graph']['tasks'])
    asset_ids = {item['id'] for item in page['asset_graph']['nodes']}
    assert all(set(task['asset_ids']) <= asset_ids for task in page['audit_graph']['tasks'])
    ledger = risks.load()
    assert len(ledger['risks']) == 1 and len(ledger['reviews']) == 1
    assert report_lines(check) == ['深度业务审计本轮计划范围已完成。']
    assert page['audit_graph']['reviewed_paths'] == [path]
    assert page['audit_graph']['stop_reason'] == '已核验计划内的归属与状态边界'
    assert page['asset_graph']['gaps']
    assert len([b for b in check['audit_stream']['batches'].values() if b.get('aggregate')]) == 1
    assert deep_audit.manage(risks, 'finish', reason='重复结束')['stage'] == 'COMPLETE'
    assert len(risks.load()['reviews']) == 1
    proof = ledger['evidence'][proofs[0]]
    assert evidence_view(root, proof)['current']['matches_record']
    (root / path).write_text(python_source('later'), encoding='utf-8')
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
    node = next(item for item in current['asset_graph']['nodes'] if item['kind'] == 'SOURCE_REGION')
    view = dashboard_view(dict(query, evidence=node['evidence_ref'], asset=node['id']))
    assert view['current']['matches_record'] and view['line_start'] == node['line_start']
    with pytest.raises(ValueError, match='VERSION_CHANGED'):
        dashboard_view(dict(query, seq='999'))
    with pytest.raises(ValueError, match='EVIDENCE_UNAVAILABLE'):
        dashboard_view(dict(query, evidence='unbound'))


def test_stop_reads_one_combined_partial_report(prepared):
    from security_runtime.development_views import closeout_page

    _, _, ref, risks, path, _, workers = prepared
    submit(risks, workers[0], path, 'before-stop')
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

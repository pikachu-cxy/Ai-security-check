"""Real filesystem task boundaries; model submissions/scanner ledger are fixtures."""
from dataclasses import asdict
import json
import sqlite3
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.tasks.security import TaskSecurityService, TaskContextError, MAX_CHANGED
from task_review_helpers import evidence_id, read_plan, read_window, review_all
from security_runtime.mcp_server import create_server
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.codex_mcp_hook import codex_hook_output, handle_codex_hook
from test_mutation_reconciliation import start, edit
from test_hook_runtime import repo


class LedgerRuntime:
    def __init__(self):
        self.calls = []
        self.mutate = None
        self.findings = []

    def scan(self, root, mode, **kwargs):
        scope = kwargs['request'].requested_files
        self.calls.append(tuple(scope))
        def result():
            if self.mutate:
                self.mutate(root)
            return ScanResult('fixture-scan', mode, TargetProfile(str(root), files=scope), 'SUCCESS', self.findings,
                              [ScannerRun('fixture-only', '0', 'SUCCESS', 0)], '', '', 0,
                              coverage='SCOPED', capability_results={'code':'SUCCESS'})
        execution = kwargs.get('execution')
        if execution is None:
            return result()
        # This detector ledger is simulated; its fixed-input lifecycle is real.
        from security_runtime.scan_input import capture_scan_input
        with capture_scan_input(kwargs['request'], private_parent=execution.private_parent,
                on_created=execution.input_created, on_removed=execution.input_removed) as view:
            execution.input_ready(view)
            out = result()
            execution.after_scan(view, out)
            return out


@pytest.fixture
def service(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root/'routes.py').write_text('def get_order(order_id):\n    return load_order(order_id)\n')
    (root/'service.py').write_text('def load_order(order_id):\n    return repository.get(order_id)\n')
    (root/'auth.py').write_text('def owns(user, order):\n    return user.id == order.owner_id\n')
    runtime = LedgerRuntime()
    return TaskSecurityService(runtime, HookStateStore(tmp_path/'state')), root, runtime


def begin(sample, key='development-1'):
    service, root, _ = sample
    return service.begin(root, key)['task_ref']


def prepared(sample):
    service, root, _ = sample
    ref = begin(sample)
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    (root/'service.py').write_text('def load_order(order_id):\n    return repository.get_unchecked(order_id)\n')
    service.finish(root, ref)
    packet = service.prepare(root, ref)
    return ref, packet['review_session'], packet


def candidate(primary, related):
    return dict(title='订单读取缺少所有者检查', category='authorization', severity='MEDIUM',
                primary_evidence=primary, evidence_refs=[primary, related],
                impact='如果入口允许其他用户传入订单编号，可能读取别人的订单。',
                preconditions=['接口可达且没有外层所有者校验'], unknowns=['外层路由及部署权限未确认'],
                counterevidence=['auth.py 定义校验函数，但当前读取路径未显示调用'],
                fix_advice='在读取前绑定当前用户并核对订单归属。')


def test_no_change_is_silent_and_does_not_scan(service):
    s, root, runtime = service
    ref = begin(service)
    (root/'notes.md').write_text('Documentation only.')
    result = s.finish(root, ref)
    assert result['status'] == 'NO_CHANGES' and result['development_summary'] == ''
    assert runtime.calls == [] and not result['review_required']
    assert s.prepare(root, ref)['status'] == 'NO_CHANGES'


def test_scope_uses_starting_workspace_not_git_head_or_last_hook(service):
    s, root, runtime = service
    (root/'old.ts').write_text('export const value = 5;\n')
    (root/'routes.py').write_text('pre-existing dirty user content\n')
    ref = begin(service)
    (root/'service.py').write_text('first task edit\n')
    # A later Hook may see only this file; task boundary still includes early edit.
    (root/'routes.py').write_text('last task edit\n')
    (root/'new.java').write_text('class New {}\n')
    (root/'old.ts').unlink()
    result = s.finish(root, ref)
    assert {c['path'] for c in result['changes']} == {'service.py','routes.py','new.java','old.ts'}
    assert runtime.calls == [('new.java','old.ts','routes.py','service.py')]
    assert s.finish(root, ref)['status'] == 'READY' and len(runtime.calls) == 1
    assert s.begin(root, 'development-2')['status'] == 'ACTIVE_TASK_EXISTS'


def test_static_zero_findings_still_requires_context_review(service):
    s, root, runtime = service
    ref, session, packet = prepared(service)
    assert packet['review_required'] and packet['static']['finding_count'] == 0
    assert packet['quick_skill']['version'] == 'quick-task-review-v3'
    sink = s.read(root, ref, session, 'routes.py', 2, 2)
    control = s.read(root, ref, session, 'auth.py', 1, 2)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [candidate(evidence_id(sink), evidence_id(control))], 'REVIEWED', [])
    result = s.get(root, ref)
    finding = result['findings'][0]['detail']
    assert finding['source'] == 'HOST_TASK_REVIEW' and finding['scanner_sources'] == []
    assert finding['validation'] == 'STRUCTURE_AND_VERSION_VALIDATED'
    assert finding['unknowns'] == ['外层路由及部署权限未确认']
    assert result['history_read_only'] and not result['repair_authorized']
    assert len(runtime.calls) == 1
    before = s.store(root).path.read_bytes()
    repeated = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert repeated == s.get(root, ref, completion_revision=repeated['completion_revision'])
    assert s.store(root).path.read_bytes() == before and len(runtime.calls) == 1


def test_counterevidence_empty_review_remains_scoped_and_host_reported(service):
    s, root, _ = service
    ref, session, packet = prepared(service)
    s.read(root, ref, session, 'auth.py', 1, 2)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', ['部署可达性及隐藏字面量未确认'])
    result = s.get(root, ref)
    assert result['host_review']['finding_count'] == 0
    assert s.load(root, ref)['review']['model_invocation'] == 'HOST_ONLY_NOT_OBSERVED_BY_RUNTIME'
    assert '未验证运行行为' not in result['development_summary']
    assert '部署可达性及隐藏字面量未确认' in s.load(root, ref)['review']['limitations']
    assert s.get(root, ref)['current_version'] is True


def test_unread_required_plan_context_keeps_review_active(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
    assert result['review_required'] and not result['result_saved']
    assert s.load(root, ref)['phase'] == 'REVIEWING'


def test_source_changed_or_unissued_evidence_cannot_be_submitted(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    with pytest.raises(ValueError, match='issued evidence'):
        s.submit(root, ref, session, [candidate('invented', 'fake')], 'REVIEWED', [])
    evidence = s.read(root, ref, session, 'routes.py', 2, 2)
    value = candidate(evidence['evidence_id'], evidence['evidence_id'])
    value['scanner_sources'] = ['invented-proof']
    with pytest.raises(ValueError, match='forbidden'):
        s.submit(root, ref, session, [value], 'REVIEWED', [])
    (root/'auth.py').write_text('changed outside the issued window\n')
    with pytest.raises(ValueError, match='stale'):
        s.submit(root, ref, session, [], 'PARTIAL', ['Changed version'])


def test_path_and_environment_context_excluded_and_source_sanitized(service):
    s, root, _ = service
    (root/'.env').write_text('API_KEY=private_test_value_here\n')
    ref, session, packet = prepared(service)
    for path in ('../outside.py','.env','C:/outside.py','routes.py:stream'):
        with pytest.raises((ValueError, OSError)):
            s.read(root, ref, session, path)
    assert 'private_test_value_here' not in json.dumps(packet)
    assert 'private_test_value_here' not in s.store(root).path.read_bytes().decode(errors='ignore')


def test_static_during_source_mutation_and_attempt_budget(service):
    s, root, runtime = service
    ref = begin(service)
    (root/'routes.py').write_text('task change\n')
    runtime.mutate = lambda r: (r/'auth.py').write_text(str(len(runtime.calls)))
    assert s.finish(root, ref)['status'] == 'STALE'
    assert s.prepare(root, ref)['status'] == 'STALE'
    assert s.finish(root, ref)['status'] == 'STALE'
    (root/'routes.py').write_text('third revision\n')
    limited = s.finish(root, ref)
    assert limited['static']['reason'] == 'TASK_STATIC_ATTEMPT_BUDGET'
    assert len(runtime.calls) == 2


def test_changed_and_context_budgets_are_enforced(service):
    s, root, runtime = service
    ref = begin(service)
    for i in range(MAX_CHANGED+1):
        (root/f'file{i:02}.ts').write_text('export const value = 5;\n')
    result = s.finish(root, ref)
    assert result['changed_file_count'] == MAX_CHANGED+1 and len(runtime.calls[0]) == MAX_CHANGED+1
    packet = s.prepare(root, ref)
    units, _ = read_plan(s, root, ref, packet)
    assert len(units) == MAX_CHANGED+1
    assert not any(v['reason']=='TASK_CONTEXT_SCOPE_EXCLUDED' for v in packet['limitations'])
    record = s.load(root, ref)
    budget = record['review_ledger']
    budget['source_bytes'] = budget['category_limits']['source']
    budget['total_bytes'] = sum(budget[name+'_bytes'] for name in ('source','navigation','control'))
    s.store(root).save(record)
    with pytest.raises(TaskContextError) as rejected:
        s.read(root, ref, packet['review_session'], 'file00.ts')
    assert rejected.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET'
    assert len(runtime.calls) == 1


def test_tampered_task_state_and_cross_workspace_ref_fail(service, tmp_path):
    s, root, _ = service
    ref = begin(service)
    other = tmp_path/'other'
    other.mkdir()
    subprocess.run(['git', 'init', '-q', str(other)], check=True)
    with pytest.raises(ValueError, match='unavailable'):
        s.finish(other, ref)
    with sqlite3.connect(s.store(root).path) as db:
        db.execute("UPDATE security_tasks SET data=replace(data,'ACTIVE','COMPLETE')")
    with pytest.raises(ValueError, match='cannot be verified'):
        s.finish(root, ref)


def test_deleted_control_has_bound_preimage_and_skip_keeps_next_task_usable(service):
    s, root, runtime = service
    ref = begin(service)
    (root/'auth.py').unlink()
    s.finish(root, ref)
    packet = s.prepare(root, ref)
    evidence = s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    assert s.load(root, ref)['evidence'][evidence_id(evidence)]['location_version'] == 'BEFORE_DELETION'
    assert 'owner_id' in '\n'.join(evidence['lines'])
    skipped = s.skip(root, ref, '缺少外层路由上下文')
    assert skipped['status'] == 'INCOMPLETE' and '未完成' in skipped['development_summary']
    assert len(runtime.calls) == 1
    assert s.begin(root, 'next-development')['status'] == 'ACTIVE'


def test_real_file_hook_preserved_but_readonly_and_reused_wire_empty(repo, tmp_path):
    core, runtime = start(repo, tmp_path)
    assert codex_hook_output(edit(core, repo)) == {}
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    changed = edit(core, repo)
    assert changed['scanner_run'] and runtime.calls == [('A.java',)]
    assert codex_hook_output(edit(core, repo)) == {}
    read = handle_codex_hook('PostToolUse', str(repo), 's', 'Bash', {'command':'git status'},
                            binding=WorkspaceBinding('fixture',str(repo),str(repo),'codex','PROJECT',''), coordinator=core)
    assert codex_hook_output(read) == {}


def test_mcp_task_contract_and_quiet_stop(service, monkeypatch):
    s, root, runtime = service
    # Embedding the fixture engine proves no native scanner is called by Stop.
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.storage import SQLiteStore
    engine = SecurityRuntime(store=SQLiteStore(root.parent/'runtime.db'))
    core = HookCoordinator(engine, store=s.hooks)
    binding = WorkspaceBinding('fixture',str(root),str(root),'codex','PROJECT','')
    server = create_server(engine, hook_coordinator=core, workspace_binding=binding)
    def call(name, **kwargs):
        return server._tool_manager.get_tool(name).fn(**kwargs)
    monkeypatch.setattr(engine, 'scan', runtime.scan)
    ref = call('begin_security_task', task_key='mcp-development')['task_ref']
    (root/'routes.py').write_text('actual changed source\n')
    assert call('finish_security_task', task_ref=ref)['review_required']
    packet = call('prepare_task_security_review', task_ref=ref)
    context = call('read_task_review_context', task_ref=ref, review_session=packet['review_session'], file_path='auth.py')
    assert context['evidence_id']
    call('submit_task_security_review', task_ref=ref, review_session=packet['review_session'], findings=[], coverage='REVIEWED', limitations=[])
    assert call('get_task_security_review', task_ref=ref)['current_version']
    # Establish bound lifecycle claims once; repeated Stops must stay quiet.
    call('handle_readiness_event', event='SessionStart', workspace_path=str(root), session_id='mcp-session')
    monkeypatch.setattr(engine, 'scan', lambda *a, **k: pytest.fail('Stop must not scan'))
    for i in range(5):
        response = call('handle_stop_event', event='Stop', workspace_path=str(root), session_id='mcp-session', turn_id=f'turn-{i}', stop_hook_active=False)
        assert json.loads(response.content[0].text) == {}


def test_active_development_keeps_real_hook_scan_but_defers_choice_to_summary(repo, tmp_path):
    from test_hook_runtime import row
    core, runtime = start(repo, tmp_path)
    s = TaskSecurityService(runtime, core.store)
    task_ref = s.begin(repo, 'active-development')['task_ref']
    runtime.findings = [row(repo, 1)]
    (repo/'A.java').write_bytes(b'class A { int timeout = 2500; }\n')
    result = edit(core, repo)
    assert result['scanner_run'] and runtime.calls == [('A.java',)]
    assert result['security_task_ref'] == task_ref
    assert result['continue'] is True and 'stopReason' not in result and 'systemMessage' not in result
    assert '没有授予修复权限' in result['hookSpecificOutput']['additionalContext']


def large_review(sample, line_count):
    s, root, _ = sample
    ref = begin(sample)
    (root/'large.py').write_text(''.join(f'value_{i} = {i}\n' for i in range(1, line_count+1)))
    s.finish(root, ref)
    packet = s.prepare(root, ref)
    return ref, packet['review_session'], packet


@pytest.mark.parametrize('line_count', [106, 300, 500])
def test_large_requested_context_is_paged_in_same_session_without_rescans(service, line_count):
    s, root, runtime = service
    ref, session, packet = large_review(service, line_count)
    assert runtime.calls == [('large.py',)]
    pending, seen, issued = [[1, line_count]], [], []
    while pending:
        low, high = pending.pop(0)
        page = s.read(root, ref, session, 'large.py', low, high)
        item = s.load(root, ref)['evidence'][evidence_id(page)]
        assert item['path'] == 'large.py' and item['location_version'] == 'CURRENT_TASK_END'
        assert 1 <= len(page['lines']) <= 600
        assert len(json.dumps(page, ensure_ascii=False).encode()) <= s.load(root, ref)['review_ledger']['limits']['response_bytes']
        seen.extend(range(page['start_line'], page['start_line']+len(page['lines'])))
        issued.append(evidence_id(page))
        if page.get('next_range'):
            pending.append(page['next_range'])
        pending.extend(page.get('unread_ranges', []))
    assert seen == list(range(1, line_count+1)) and len(set(issued)) == len(issued)
    assert s.get(root, ref)['context_read_coverage']['unread_ranges']['total_count'] == 0
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', [])
    assert s.get(root, ref)['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_unread_requested_continuation_cannot_claim_reviewed(service):
    s, root, runtime = service
    ref, session, _ = large_review(service, 1500)
    first = s.read(root, ref, session, 'large.py', 1, 1500)
    assert first['next_range'][0] == len(first['lines'])+1
    receipt = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert receipt['status'] == 'REVIEW_CONTINUE_REQUIRED' and not receipt['result_saved']
    result = s.get(root, ref)
    assert result['context_read_coverage']['unread_ranges']['items'] == [
        dict(path='large.py', start_line=first['next_range'][0], end_line=1500)]
    assert s.load(root, ref)['phase'] == 'REVIEWING'
    assert len(runtime.calls) == 1


def test_repeated_or_overlapping_pages_do_not_hide_unread_ranges_or_spend_again(service):
    s, root, _ = service
    ref, session, _ = large_review(service, 300)
    first = s.read(root, ref, session, 'large.py', 1, 80)
    initial = s.load(root, ref)['review_ledger'].copy()
    duplicate = s.read(root, ref, session, 'large.py', 1, 80)
    current = s.load(root, ref)['review_ledger']
    assert duplicate['status'] == 'ALREADY_DELIVERED' and duplicate['source_lines_delivered'] == 0
    assert duplicate['evidence_refs'] == [evidence_id(first)]
    assert current['source_bytes'] == initial['source_bytes'] and current['reads'] == initial['reads']
    assert current['navigation_bytes'] > initial['navigation_bytes']
    overlap = s.read(root, ref, session, 'large.py', 40, 120)
    assert overlap['start_line'] == 81 and len(overlap['lines']) == 40
    s.read(root, ref, session, 'large.py', 200, 300)
    s.read(root, ref, session, 'large.py', 1, 300)
    assert s.get(root, ref)['context_read_coverage']['unread_ranges']['total_count'] == 0
    assert s.load(root, ref)['review_ledger']['reads'] == 4


def test_invalid_ranges_and_unsupported_files_do_not_break_context_session(service):
    s, root, runtime = service
    ref, session, packet = large_review(service, 106)
    (root/'README.md').write_text('Untrusted task notes.')
    for low, high in [(0, 80), (81, 80), (True, 80), (1, '110')]:
        with pytest.raises(TaskContextError) as error:
            s.read(root, ref, session, 'large.py', low, high)
        assert error.value.reason_code == 'TASK_CONTEXT_RANGE_INVALID' and error.value.recoverable
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'README.md')
    assert error.value.reason_code == 'TASK_CONTEXT_FILE_UNSUPPORTED'
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'large.py', 107, 110)
    assert error.value.reason_code == 'TASK_CONTEXT_RANGE_UNAVAILABLE'
    assert error.value.details['total_lines'] == 106
    first = s.read(root, ref, session, 'large.py', 1, 110)
    assert first['start_line'] == 1 and len(first['lines']) == 106 and not first.get('next_range')
    last = s.read(root, ref, session, 'large.py', 81, 110)
    assert last['status'] == 'ALREADY_DELIVERED' and evidence_id(last) == evidence_id(first)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', [])
    assert s.get(root, ref)['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_context_byte_budget_retains_pending_ranges_and_forces_partial(service):
    s, root, runtime = service
    ref, session, _ = large_review(service, 300)
    s.read(root, ref, session, 'large.py', 1, 80)
    record = s.load(root, ref)
    ledger = record['review_ledger']
    ledger['source_bytes'] = ledger['category_limits']['source']
    ledger['total_bytes'] = sum(ledger[name+'_bytes'] for name in ('source','navigation','control'))
    s.store(root).save(record)
    before = s.load(root, ref)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'large.py', 81, 300)
    assert error.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET' and not error.value.recoverable
    refused = s.load(root, ref)
    assert refused['evidence'] == before['evidence'] and refused['review_ledger'] == before['review_ledger']
    receipt = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE'
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['unread_ranges']['items'] == [dict(path='large.py', start_line=81, end_line=300)]
    assert len(runtime.calls) == 1


def test_deleted_large_preimage_pages_keep_before_deletion_identity(service):
    s, root, runtime = service
    (root/'old.py').write_text(''.join(f'value_{i} = {i}\n' for i in range(1, 301)))
    ref = begin(service)
    (root/'old.py').unlink()
    packet = s.prepare(root, ref)
    delivered, units = review_all(s, root, ref, packet)
    record = s.load(root, ref)
    assert len(units) == 1 and delivered
    assert {record['evidence'][evidence_id(page)]['location_version'] for page in delivered} == {'BEFORE_DELETION'}
    assert all(record['evidence'][evidence_id(page)]['path'] == 'old.py' for page in delivered)
    s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert s.get(root, ref)['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_task_summary_has_one_selected_risk_choice_and_bounded_risk_list(service):
    s, root, _ = service
    ref, session, packet = prepared(service)
    sink = s.read(root, ref, session, 'routes.py', 2, 2)
    control = s.read(root, ref, session, 'auth.py', 1, 2)
    review_all(s, root, ref, packet)
    findings = [dict(candidate(evidence_id(sink), evidence_id(control)), title=f'风险 {i}') for i in range(4)]
    receipt = s.submit(root, ref, session, findings, 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE' and receipt['result_details_required']
    first = s.get(root, ref)
    assert first['finding_page']['total_count'] == 4 and first['finding_page']['returned_count'] == 3
    assert first['finding_page']['next_offset'] == 3 and first['host_review']['finding_count'] == 4
    assert [item['detail']['title'] for item in first['findings']] == [f'风险 {i}' for i in range(3)]
    assert all(item['details_complete'] and item['detail']['preconditions'] and item['detail']['counterevidence']
               for item in first['findings'])
    last = s.get(root, ref, finding_offset=3)
    assert last['findings'][0]['detail']['title'] == '风险 3' and not last['finding_page']['has_more']
    assert not first['repair_authorized'] and not last['repair_authorized']
    assert len(s.load(root, ref)['review']['findings']) == 4


def test_retained_hook_scope_is_rechecked_at_current_version_outside_net_task_diff(service):
    from test_hook_runtime import row
    s, root, runtime = service
    ref = begin(service)
    record = s.load(root, ref)
    record.update(hook_recheck_files=['auth.py'], hook_pending_scope_files=['service.py'])
    s.store(root).save(record)
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    runtime.findings = [row(root, file='auth.py')]
    result = s.finish(root, ref)
    assert runtime.calls == [('auth.py', 'routes.py', 'service.py')]
    assert result['changes'] == [dict(path='routes.py', change='MODIFIED')]
    assert result['file_hook_checks']['current_recheck_files'] == ['auth.py', 'service.py']
    packet = s.prepare(root, ref)
    s.read(root, ref, packet['review_session'], 'routes.py', 1, 2)
    s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    complete = s.get(root, ref)
    assert complete['findings'][0]['detail']['file_path'] == 'auth.py'
    assert complete['findings'][0]['detail']['line_start'] == 1
    assert complete['history_read_only'] and not complete['repair_authorized']
    assert complete['static']['finding_count'] == 1 and complete['repair_authorized'] is False


def test_reverted_task_clears_transient_hook_risk_only_after_final_current_check(service):
    s, root, runtime = service
    ref = begin(service)
    original = (root/'routes.py').read_text()
    (root/'routes.py').write_text('temporary unchecked read\n')
    record = s.load(root, ref)
    record.update(hook_recheck_files=['routes.py'], hook_pending_scope_files=[])
    s.store(root).save(record)
    (root/'routes.py').write_text(original)
    result = s.finish(root, ref)
    assert runtime.calls == [('routes.py',)]
    assert result['status'] == 'NO_CHANGES' and result['development_summary'] == ''
    assert result['static']['finding_count'] == 0 and not result['review_required']


def test_hook_omitted_or_excluded_current_scope_is_a_coverage_gap(service):
    s, root, runtime = service
    ref = begin(service)
    record = s.load(root, ref)
    record.update(hook_recheck_files=['README.md', '.env', 'missing.py'], hook_checks_omitted=1)
    s.store(root).save(record)
    result = s.finish(root, ref)
    assert result['status'] == 'INCOMPLETE' and not result['review_required']
    reasons = {v['reason'] for v in result['limitations']}
    assert reasons >= {'TASK_HOOK_CURRENT_SOURCE_UNAVAILABLE', 'TASK_HOOK_LEDGER_SCOPE_INCOMPLETE'}
    assert runtime.calls == []


def test_long_sanitized_lines_support_full_context_review(service):
    s, root, _ = service
    ref = begin(service)
    (root/'long.py').write_text('value = '+ '1 + '*200 + '1\n')
    packet = s.prepare(root, ref)
    page = s.read(root, ref, packet['review_session'], 'long.py', 1, 1)
    assert 'line_truncation' not in page
    assert page['lines'][0] == 'value = '+ '1 + '*200 + '1'
    review_all(s, root, ref, packet)
    s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert not any(v['reason'] == 'SOURCE_LINE_CHAR_BUDGET' for v in result['limitations']['items'])


def test_unrelated_unread_long_lines_do_not_widen_scoped_review_gaps(service):
    s, root, _ = service
    (root/'unrelated.py').write_text('value = '+ '1 + '*200 + '1\n')
    ref, session, packet = large_review(service, 106)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', [])
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert not any(v['reason'] == 'SOURCE_LINE_CHAR_BUDGET' for v in result['limitations']['items'])
    assert not any(value['path'] == 'unrelated.py' for value in s.load(root, ref)['evidence'].values())


def test_unique_read_budget_cannot_be_reset_and_missing_page_forces_partial(service):
    s, root, runtime = service
    (root/'auth.py').write_text(''.join(f'value_{i} = {i}\n' for i in range(1, 65)))
    ref = begin(service)
    (root/'routes.py').write_text('changed_route = True\n')
    packet = s.prepare(root, ref)
    session = packet['review_session']
    review_all(s, root, ref, packet)
    record = s.load(root, ref)
    record['review_ledger']['reads'] = record['review_ledger']['limits']['reads']-1
    s.store(root).save(record)
    issued = s.read(root, ref, session, 'auth.py', 1, 1)
    exhausted = s.load(root, ref)['review_ledger']['reads']
    assert exhausted == s.load(root, ref)['review_ledger']['limits']['reads']
    duplicate = s.read(root, ref, session, 'auth.py', 1, 1)
    assert duplicate['status'] == 'ALREADY_DELIVERED' and evidence_id(duplicate) == evidence_id(issued)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'auth.py', 2, 2)
    assert error.value.reason_code == 'TASK_CONTEXT_READ_BUDGET' and not error.value.recoverable
    assert s.prepare(root, ref)['review_session'] == session
    assert s.load(root, ref)['review_ledger']['reads'] == exhausted
    s.submit(root, ref, session, [], 'REVIEWED', [])
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['used_reads'] == exhausted
    assert result['context_read_coverage']['unread_ranges']['items'] == [dict(path='auth.py', start_line=2, end_line=2)]
    assert len(runtime.calls) == 1


def test_related_inventory_scales_without_reset_and_unknown_source_stays_excluded(service):
    s, root, runtime = service
    for number in range(25):
        (root/f'related{number:02}.py').write_text('def check():\n    pass\n')
    ref = begin(service)
    (root/'routes.py').write_text('changed_route = True\n')
    packet = s.prepare(root, ref)
    session = packet['review_session']
    limit = s.load(root, ref)['review_ledger']['limits']['related_files']
    assert limit >= 25
    for number in range(25):
        s.read(root, ref, session, f'related{number:02}.py', 1, 2)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'not-in-baseline.py', 1, 2)
    assert error.value.reason_code == 'TASK_CONTEXT_PATH_EXCLUDED'
    before = s.load(root, ref)['review_ledger']
    assert len(s.load(root, ref)['related_files']) == 25
    assert s.prepare(root, ref)['review_session'] == session
    after = s.load(root, ref)['review_ledger']
    assert after['source_bytes'] == before['source_bytes'] and after['reads'] == before['reads']
    assert after['total_bytes'] > before['total_bytes']
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
    assert result['pending_unit_count'] == 26 and not result['result_saved']
    assert len(runtime.calls) == 1


def test_failed_final_static_does_not_turn_retained_hook_risk_into_no_findings_pass(service):
    s, root, runtime = service
    ref = begin(service)
    record = s.load(root, ref)
    record.update(hook_recheck_files=['auth.py'])
    s.store(root).save(record)
    (root/'routes.py').write_text('changed route\n')
    def fail(root):
        raise RuntimeError('fixture failure')
    runtime.mutate = fail
    result = s.finish(root, ref)
    assert result['static']['status'] == 'FAILED'
    packet = s.prepare(root, ref)
    session = packet['review_session']
    s.read(root, ref, session, 'auth.py', 1, 2)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', [])
    complete = s.get(root, ref)
    summary = complete['development_summary']
    assert '未发现安全线索' not in summary and '当前风险尚待核实' in summary
    assert 'auth.py' in summary and '不足以证明先前提示已消除' in summary
    assert complete['repair_authorized'] is False and len(runtime.calls) == 1


def test_same_source_with_new_hook_inputs_refinishes_and_invalidates_old_context_packet(service):
    s, root, runtime = service
    ref, old_session, old_packet = prepared(service)
    s.read(root, ref, old_session, 'routes.py', 1, 2)
    current = (root/'routes.py').read_text()
    (root/'routes.py').write_text('temporary edit between hooks\n')
    (root/'routes.py').write_text(current)
    record = s.load(root, ref)
    record.update(hook_checks=[dict(status='SCANNED', change_digest='new-hook-revision')],
                  hook_recheck_files=['auth.py'])
    s.store(root).save(record)
    result = s.finish(root, ref)
    assert result['status'] == 'READY' and runtime.calls[-1] == ('auth.py', 'routes.py', 'service.py')
    refreshed = s.load(root, ref)
    assert not any(key in refreshed for key in ('packet', 'review_session'))
    assert refreshed['review_deadline'] == record['review_deadline']
    assert len(refreshed['review_history'][-1]['evidence']) == 1
    assert refreshed['review_ledger']['reads'] == record['review_ledger']['reads']
    assert refreshed['lifetime_context_bytes'] >= record['context_bytes']
    assert refreshed['evidence'] == {} and refreshed['context_requests'] == {}
    packet = s.prepare(root, ref)
    assert packet['review_session'] != old_session
    assert packet['review_session'] and old_packet['review_session'] == old_session
    with pytest.raises(ValueError, match='unavailable'):
        s.read(root, ref, old_session, 'auth.py', 1, 2)
    s.read(root, ref, packet['review_session'], 'auth.py', 1, 2)
    assert s.finish(root, ref)['status'] == 'REVIEWING'
    assert len(runtime.calls) == 2  # Read/session bookkeeping does not invalidate reuse.


def hook_failure(sample, ref, scope=()):
    s, root, _ = sample
    return s.store(root).record_hook_failure(ref, task_created_at=s.load(root, ref)['created_at'],
                                            scope_files=scope, scan_id='fixture-hook-scan')


def test_signed_hook_failure_scope_is_checked_but_recording_gap_is_preserved(service):
    s, root, runtime = service
    ref = begin(service)
    hook_failure(service, ref, ['auth.py'])
    (root/'routes.py').write_text('changed route\n')
    result = s.finish(root, ref)
    assert runtime.calls == [('auth.py', 'routes.py')]
    assert result['file_hook_checks']['recording_failure']['present']
    assert any(v['reason'] == 'TASK_HOOK_RECORDING_FAILED' for v in result['limitations'])
    packet = s.prepare(root, ref)
    session = packet['review_session']
    s.read(root, ref, session, 'auth.py', 1, 2)
    review_all(s, root, ref, packet)
    s.submit(root, ref, session, [], 'REVIEWED', [])
    complete = s.get(root, ref)
    assert complete['host_review']['coverage'] == 'PARTIAL'
    assert 'auth.py' in complete['development_summary'] and '未发现安全线索' not in complete['development_summary']


def test_hook_failure_marker_revision_invalidates_same_source_finish_cache(service):
    s, root, runtime = service
    ref = begin(service)
    (root/'routes.py').write_text('changed route\n')
    s.finish(root, ref)
    first_revision = s.load(root, ref)['finished_hook_revision']
    hook_failure(service, ref, ['auth.py'])
    s.finish(root, ref)
    assert s.load(root, ref)['finished_hook_revision'] != first_revision
    assert runtime.calls == [('routes.py',), ('auth.py', 'routes.py')]
    s.finish(root, ref)
    assert len(runtime.calls) == 2


def test_unknown_hook_failure_paths_prevent_silent_no_changes(service):
    s, root, runtime = service
    ref = begin(service)
    hook_failure(service, ref)
    result = s.finish(root, ref)
    assert result['status'] == 'INCOMPLETE' and '失败路径未知' in result['development_summary']
    assert result['file_hook_checks']['recording_failure']['failure_paths_unknown']
    assert any(v['reason'] == 'TASK_HOOK_FAILED_PATHS_UNKNOWN' for v in result['limitations'])
    assert runtime.calls == []


@pytest.mark.parametrize('error_type', [ValueError, OSError])
def test_unverifiable_hook_failure_marker_is_an_explicit_gap(service, monkeypatch, error_type):
    from security_runtime.tasks.security_state import TaskSecurityStore
    s, root, runtime = service
    ref = begin(service)
    def broken_marker(self, ref):
        raise error_type('untrusted failure marker diagnostic must not be returned')
    monkeypatch.setattr(TaskSecurityStore, 'get_hook_failure', broken_marker)
    result = s.finish(root, ref)
    assert result['status'] == 'INCOMPLETE' and '失败路径未知' in result['development_summary']
    assert any(v['reason'] == 'TASK_HOOK_FAILURE_MARKER_UNVERIFIED' for v in result['limitations'])
    assert 'untrusted failure marker diagnostic' not in json.dumps(result)
    assert runtime.calls == []


@pytest.mark.parametrize('new_input', ['ledger', 'marker'])
def test_hook_scope_revision_after_prepare_rejects_old_session_until_same_ref_refinish(service, new_input):
    s, root, runtime = service
    ref, session, _ = prepared(service)
    if new_input == 'ledger':
        record = s.load(root, ref)
        record.update(hook_checks=[dict(status='SCANNED', change_digest='late-hook')],
                      hook_recheck_files=['auth.py'])
        s.store(root).save(record)
    else:
        hook_failure(service, ref, ['auth.py'])
    assert s.prepare(root, ref)['status'] == 'STALE'
    with pytest.raises(ValueError, match='stale'):
        s.read(root, ref, session, 'auth.py', 1, 2)
    with pytest.raises(ValueError, match='stale'):
        s.submit(root, ref, session, [], 'REVIEWED', [])
    assert s.finish(root, ref)['status'] == 'READY'
    refreshed = s.prepare(root, ref)
    assert refreshed['review_session'] != session
    assert s.read(root, ref, refreshed['review_session'], 'auth.py', 1, 2)['evidence_id']
    assert len(runtime.calls) == 2

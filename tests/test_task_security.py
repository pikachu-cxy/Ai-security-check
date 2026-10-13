"""Real filesystem task boundaries; model submissions/scanner ledger are fixtures."""
from dataclasses import asdict
import json
import sqlite3
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.task_security import (TaskSecurityService, TaskContextError, MAX_CHANGED,
                                            MAX_CONTEXT, MAX_CONTEXT_WINDOW_LINES)
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
        scope = kwargs['_hook_scope']
        self.calls.append(tuple(scope))
        if self.mutate:
            self.mutate(root)
        return ScanResult('fixture-scan', mode, TargetProfile(str(root), files=scope), 'SUCCESS', self.findings,
                          [ScannerRun('fixture-only', '0', 'SUCCESS', 0)], '', '', 0,
                          coverage='SCOPED', capability_results={'code':'SUCCESS'})


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
    assert packet['quick_skill']['version'] == 'quick-task-review-v1'
    sink = s.read(root, ref, session, 'routes.py', 2, 2)
    control = s.read(root, ref, session, 'auth.py', 1, 2)
    result = s.submit(root, ref, session, [candidate(sink['evidence_id'], control['evidence_id'])], 'REVIEWED', [])
    finding = result['host_review']['findings'][0]
    assert finding['source'] == 'HOST_TASK_REVIEW' and finding['scanner_sources'] == []
    assert finding['validation'] == 'STRUCTURE_AND_VERSION_VALIDATED'
    assert '未确认' in result['development_summary'] and not result['repair_authorized']
    assert len(runtime.calls) == 1
    assert s.submit(root, ref, session, [], 'REVIEWED', []) == s.get(root, ref)  # idempotent


def test_counterevidence_empty_review_remains_scoped_and_host_reported(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    s.read(root, ref, session, 'auth.py', 1, 2)
    result = s.submit(root, ref, session, [], 'REVIEWED', ['部署可达性及隐藏字面量未确认'])
    assert not result['host_review']['findings']
    assert result['host_review']['model_invocation'] == 'HOST_ONLY_NOT_OBSERVED_BY_RUNTIME'
    assert '未验证运行行为' in result['development_summary']
    assert s.get(root, ref)['current_version'] is True


def test_missing_related_context_forces_partial(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert '关联' in result['development_summary']


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
    assert result['limitations']
    packet = s.prepare(root, ref)
    record = s.load(root, ref)
    record['context_bytes'] = MAX_CONTEXT
    s.store(root).save(record)
    with pytest.raises(ValueError, match='byte budget'):
        s.read(root, ref, packet['review_session'], 'file00.ts')


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
    assert evidence['location_version'] == 'BEFORE_DELETION'
    assert 'owner_id' in '\n'.join(evidence['numbered_lines'])
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
    ref, session, review = large_review(service, line_count)
    assert review['budget']['context_window_lines'] == MAX_CONTEXT_WINDOW_LINES
    assert runtime.calls == [('large.py',)]  # Static scope is the full file, not its first 80 lines.
    page = s.read(root, ref, session, 'large.py', 1, line_count)
    assert page['total_lines'] == line_count
    assert page['requested_range'] == {'start_line': 1, 'end_line': line_count}
    assert page['returned_range'] == {'start_line': 1, 'end_line': 80}
    assert page['has_more'] and page['next_read']['review_session'] == session
    seen, issued = [], []
    version = (page['file_sha256'], page['location_version'])
    while True:
        seen.extend(range(page['start_line'], page['end_line']+1))
        issued.append(page['evidence_id'])
        assert len(page['numbered_lines']) <= 80
        assert (page['file_sha256'], page['location_version']) == version
        if not page['has_more']:
            assert page['next_read'] is None
            break
        arguments = page['next_read']
        assert arguments['task_ref'] == ref and arguments['file_path'] == 'large.py'
        assert arguments['workspace_path'] == str(root.resolve())
        page = s.read(arguments['workspace_path'], arguments['task_ref'], arguments['review_session'],
                      arguments['file_path'], arguments['start_line'], arguments['end_line'])
    assert seen == list(range(1, line_count+1)) and len(set(issued)) == len(issued)
    assert s.get(root, ref)['context_read_coverage']['unread_ranges'] == []
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_unread_requested_continuation_cannot_claim_reviewed(service):
    s, root, runtime = service
    ref, session, _ = large_review(service, 500)
    s.read(root, ref, session, 'large.py', 1, 500)
    s.read(root, ref, session, 'auth.py', 1, 2)
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['unread_ranges'] == [dict(path='large.py', start_line=81, end_line=500)]
    assert any('large.py:81-500' in value for value in result['host_review']['limitations'])
    assert len(runtime.calls) == 1


def test_repeated_or_overlapping_pages_do_not_hide_unread_ranges_or_spend_again(service):
    s, root, _ = service
    ref, session, _ = large_review(service, 300)
    first = s.read(root, ref, session, 'large.py', 1, 300)
    cost = s.load(root, ref)['context_bytes']
    assert s.read(root, ref, session, 'large.py', 1, 300) == first
    assert s.load(root, ref)['context_bytes'] == cost
    s.read(root, ref, session, 'large.py', 40, 120)
    s.read(root, ref, session, 'large.py', 200, 300)
    assert s.get(root, ref)['context_read_coverage']['unread_ranges'] == [
        dict(path='large.py', start_line=120, end_line=199), dict(path='large.py', start_line=280, end_line=300)]


def test_invalid_ranges_and_unsupported_files_do_not_break_context_session(service):
    s, root, runtime = service
    ref, session, _ = large_review(service, 106)
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
    last = s.read(root, ref, session, 'large.py', 81, 110)
    assert first['has_more'] and last['end_line'] == 106 and not last['has_more']
    assert s.submit(root, ref, session, [], 'REVIEWED', [])['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_context_byte_budget_retains_pending_ranges_and_forces_partial(service):
    s, root, runtime = service
    ref, session, _ = large_review(service, 300)
    s.read(root, ref, session, 'large.py', 1, 300)
    record = s.load(root, ref)
    record['context_bytes'] = MAX_CONTEXT
    s.store(root).save(record)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'large.py', 81, 300)
    assert error.value.reason_code == 'TASK_CONTEXT_BYTE_BUDGET' and not error.value.recoverable
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['unread_ranges'] == [dict(path='large.py', start_line=81, end_line=300)]
    assert result['context_read_coverage']['gaps'][0]['reason'] == 'TASK_CONTEXT_BYTE_BUDGET'
    assert len(runtime.calls) == 1


def test_deleted_large_preimage_pages_keep_before_deletion_identity(service):
    s, root, runtime = service
    (root/'old.py').write_text(''.join(f'value_{i} = {i}\n' for i in range(1, 301)))
    ref = begin(service)
    (root/'old.py').unlink()
    s.finish(root, ref)
    packet = s.prepare(root, ref)
    page = s.read(root, ref, packet['review_session'], 'old.py', 1, 300)
    assert page['location_version'] == 'BEFORE_DELETION'
    while page['has_more']:
        next_page = page['next_read']
        page = s.read(root, ref, packet['review_session'], 'old.py', next_page['start_line'], next_page['end_line'])
        assert page['location_version'] == 'BEFORE_DELETION'
    assert s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])['host_review']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_task_summary_has_one_selected_risk_choice_and_bounded_risk_list(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    sink = s.read(root, ref, session, 'routes.py', 2, 2)
    control = s.read(root, ref, session, 'auth.py', 1, 2)
    findings = [dict(candidate(sink['evidence_id'], control['evidence_id']), title=f'风险 {i}') for i in range(4)]
    result = s.submit(root, ref, session, findings, 'REVIEWED', [])
    summary = result['development_summary']
    assert summary.count('请选择具体风险') == 1 and '“修复”或“忽略”' in summary
    assert summary.count('上下文核查线索：') == 3 and '另有 1 项' in summary
    assert '反证：' in summary and '未确认：' in summary and '条件：' in summary
    assert len(result['host_review']['findings']) == 4 and result['repair_authorized'] is False


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
    complete = s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert 'auth.py:1' in complete['development_summary'] and '请选择具体风险' in complete['development_summary']
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


def test_long_sanitized_lines_cannot_support_full_context_review(service):
    s, root, _ = service
    ref = begin(service)
    (root/'long.py').write_text('value = '+ '1 + '*200 + '1\n')
    s.finish(root, ref)
    packet = s.prepare(root, ref)
    page = s.read(root, ref, packet['review_session'], 'long.py', 1, 1)
    assert page['line_truncation']['complete_line_text'] is False
    assert page['line_truncation']['known_truncated_lines'] == [1]
    assert len(page['numbered_lines'][0]) <= 603
    result = s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert any(v['reason'] == 'SOURCE_LINE_CHAR_BUDGET' for v in result['limitations'])


def test_unrelated_unread_long_lines_do_not_widen_scoped_review_gaps(service):
    s, root, _ = service
    (root/'unrelated.py').write_text('value = '+ '1 + '*200 + '1\n')
    ref, session, _ = large_review(service, 106)
    s.read(root, ref, session, 'large.py', 1, 106)
    s.read(root, ref, session, 'large.py', 81, 106)
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert not any(v['reason'] == 'SOURCE_LINE_CHAR_BUDGET' for v in result['limitations'])


def test_unique_read_budget_cannot_be_reset_and_missing_page_forces_partial(service):
    s, root, runtime = service
    (root/'auth.py').write_text(''.join(f'value_{i} = {i}\n' for i in range(1, 65)))
    ref = begin(service)
    (root/'routes.py').write_text('changed route\n')
    s.finish(root, ref)
    packet = s.prepare(root, ref)
    session = packet['review_session']
    for line in range(1, 41):
        s.read(root, ref, session, 'auth.py', line, line)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'auth.py', 41, 41)
    assert error.value.reason_code == 'TASK_CONTEXT_READ_BUDGET' and not error.value.recoverable
    assert s.load(root, ref)['review_session'] == session
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['used_reads'] == 40
    assert result['context_read_coverage']['unread_ranges'] == [dict(path='auth.py', start_line=41, end_line=41)]
    assert result['context_read_coverage']['gaps'][0]['reason'] == 'TASK_CONTEXT_READ_BUDGET'
    assert '未发现安全线索' not in result['development_summary'] and len(runtime.calls) == 1


def test_related_file_budget_cannot_be_reset_and_excluded_file_forces_partial(service):
    s, root, runtime = service
    for number in range(11):
        (root/f'related{number:02}.py').write_text('def check():\n    pass\n')
    ref = begin(service)
    (root/'routes.py').write_text('changed route\n')
    s.finish(root, ref)
    session = s.prepare(root, ref)['review_session']
    for number in range(10):
        s.read(root, ref, session, f'related{number:02}.py', 1, 2)
    with pytest.raises(TaskContextError) as error:
        s.read(root, ref, session, 'related10.py', 1, 2)
    assert error.value.reason_code == 'TASK_CONTEXT_RELATED_FILE_BUDGET' and not error.value.recoverable
    result = s.submit(root, ref, session, [], 'REVIEWED', [])
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['context_read_coverage']['gaps'] == [dict(path='related10.py', reason='TASK_CONTEXT_RELATED_FILE_BUDGET')]
    assert '未发现安全线索' not in result['development_summary'] and len(runtime.calls) == 1


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
    session = s.prepare(root, ref)['review_session']
    s.read(root, ref, session, 'auth.py', 1, 2)
    complete = s.submit(root, ref, session, [], 'REVIEWED', [])
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
    assert not any(key in refreshed for key in ('packet', 'review_session', 'review_deadline'))
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
    session = s.prepare(root, ref)['review_session']
    s.read(root, ref, session, 'auth.py', 1, 2)
    complete = s.submit(root, ref, session, [], 'REVIEWED', [])
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
    from security_runtime.task_security_state import TaskSecurityStore
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

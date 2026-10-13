"""Real filesystem task boundaries; model submissions/scanner ledger are fixtures."""
from dataclasses import asdict
import json
import sqlite3
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.task_security import TaskSecurityService, MAX_CHANGED, MAX_CONTEXT
from security_runtime.mcp_server import create_server
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.codex_mcp_hook import codex_hook_output, handle_codex_hook
from test_mutation_reconciliation import start, edit
from test_hook_runtime import repo


class LedgerRuntime:
    def __init__(self):
        self.calls = []
        self.mutate = None

    def scan(self, root, mode, **kwargs):
        scope = kwargs['_hook_scope']
        self.calls.append(tuple(scope))
        if self.mutate:
            self.mutate(root)
        return ScanResult('fixture-scan', mode, TargetProfile(str(root), files=scope), 'SUCCESS', [],
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
    assert result['changed_file_count'] == MAX_CHANGED+1 and len(runtime.calls[0]) == MAX_CHANGED
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

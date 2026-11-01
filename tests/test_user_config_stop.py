"""Product preferences and bounded Stop behavior on real isolated journals."""
import json
import pytest

from test_development_check import check, execute, OWNER
from security_runtime.user_config import read_config, describe_config
from security_runtime.development_stop import fallback
from security_runtime.development_check import DevelopmentCheckStore
from security_runtime.tasks.durable import TaskOperationError


@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    path = tmp_path/'config.toml'
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(path))
    return path


def test_defaults_and_invalid_settings(config):
    values = read_config()['values']
    assert values['storage']['development_max_records'] == 1024
    assert all(values['agent'].values())
    assert values['development']['stop_fallback']['enabled']
    for text in ['oops = true', '[agent]\nreview_scanner_findings=1',
                 '[storage]\ndevelopment_max_records=0', 'invalid [']:
        config.write_text(text)
        assert describe_config()['status'] == 'INVALID'


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_global_config_read_never_requires_or_admits_a_workspace(config, host):
    import asyncio
    from types import SimpleNamespace
    from security_runtime.global_mcp import create_global_server

    def forbidden(*_args, **_kwargs):
        pytest.fail('User configuration must not resolve or admit a workspace')

    server = create_global_server(workspaces=SimpleNamespace(host=host, root=forbidden))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert 'workspace_path' not in tools['get_development_config'].inputSchema.get('required', [])
    result = structured(asyncio.run(server.call_tool('get_development_config', {})))
    assert result['status'] == 'VALID'
    assert result['values']['storage']['development_max_records'] == 1024
    config.write_text('[agent]\nreview_scanner_findings=false\n')
    result = structured(asyncio.run(server.call_tool('get_development_config', {})))
    assert result['values']['agent']['review_scanner_findings'] is False
    config.write_text('unknown=true')
    assert structured(asyncio.run(server.call_tool('get_development_config', {})))['status'] == 'INVALID'


def test_capacity_lowering_and_disabled_limit_preserve_completion(check, config):
    root, service, _, _ = check
    ref = service.begin(root, 'first')['check_ref']
    service.record(root, ref, ['app.ts'])
    config.write_text('[storage]\ndevelopment_max_records=1\n')
    assert service.get(root, ref)['dirty_seq'] == 1
    with pytest.raises(TaskOperationError):
        service.begin(root, 'second')
    assert service.finish(root, ref)['status'] == 'QUEUED'
    config.write_text('[storage]\ndevelopment_record_limit_enabled=false\n')
    assert service.begin(root, 'second')['check_ref'] != ref
    assert len(service.store(root).rows()) > 1


def test_stop_submits_once_waits_and_is_bounded(check):
    root, service, _, _ = check
    calls = []
    service.launcher = lambda *args: calls.append(args)
    ref = service.begin(root, 'work')['check_ref']
    service.record(root, ref, ['app.ts'])
    first = fallback(service.hooks, root, OWNER, service=service)
    assert first['decision'] == 'block' and len(calls) == 1
    second = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True)
    assert second['decision'] == 'block' and len(calls) == 1
    third = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True)
    assert third['status'] == 'STOP_FALLBACK_INCOMPLETE' and 'decision' not in third
    assert service.get(root, ref)['finish_requested']


def test_expired_stop_budget_preserves_pending_check(check):
    root, service, _, _ = check
    ref = service.begin(root, 'deadline')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service)
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row['stop_fallback']['deadline'] = 0
        store._put(db, ref, row)
    result = fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True)
    assert result['status'] == 'STOP_FALLBACK_INCOMPLETE'
    assert service.get(root, ref)['status'] == 'QUEUED'


def test_stop_empty_disabled_cancelled_and_legacy_do_not_dispatch(check, config):
    root, service, _, _ = check
    service.launcher = lambda *args: pytest.fail('unexpected scan launch')
    assert fallback(service.hooks, root, OWNER, service=service) is None
    config.write_text('[development.stop_fallback]\nenabled=false\n')
    ref = service.begin(root, 'disabled')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service) is None
    config.unlink()
    ref = service.begin(root, 'new')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service, stopped_normally=False) is None
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.pop('effective_config')
        store._put(db, ref, row)
    assert fallback(service.hooks, root, OWNER, service=service) is None


@pytest.mark.parametrize('review,audit', [(True,True),(True,False),(False,True),(False,False)])
def test_analysis_policy_is_snapshotted(check, config, review, audit):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings='+str(review).lower()+'\naudit_business_logic='+str(audit).lower())
    ref = service.begin(root, 'policy')['check_ref']
    config.unlink()
    result = service.get(root, ref)
    assert result['analysis_requirements'] == {
        'review_scanner_findings': 'REQUIRED' if review else 'SKIPPED_BY_CONFIG',
        'audit_business_logic': 'REQUIRED' if audit else 'SKIPPED_BY_CONFIG'}


def test_static_only_scanner_import_without_agent_review(check, config, monkeypatch):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false')
    ref = service.begin(root, 'static')['check_ref']
    service.record(root, ref, ['app.ts'])
    execute(check, monkeypatch)
    from security_runtime.development_risks import DevelopmentRisks
    risks = DevelopmentRisks(service, root, ref)
    assert risks.get()['review_versions'] == []
    assert service.get(root, ref)['host_review_completed'] is False
    with pytest.raises(ValueError, match='DEVELOPMENT_AGENT_ANALYSIS_DISABLED'):
        risks.submit([], 1)


def test_stop_does_not_select_other_owner_or_previous_task(check):
    root, service, _, _ = check
    old = service.begin(root, 'old')['check_ref']
    service.record(root, old, ['app.ts'])
    service.begin(root, 'current-empty')
    assert fallback(service.hooks, root, OWNER, service=service) is None
    assert fallback(service.hooks, root, dict(host='codex', session='f'*64)) is None


def test_new_edit_does_not_reset_continuation_budget(check):
    root, service, _, _ = check
    ref = service.begin(root, 'work')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service)
    deadline = service.store(root).load(ref)['stop_fallback']['deadline']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service, stop_hook_active=True)
    row = service.store(root).load(ref)
    assert row['stop_fallback']['deadline'] == deadline
    assert row['stop_fallback']['count'] == 2

from test_development_check_mcp import development_server, call
from test_global_integration import structured, projects, installed
from test_development_delivery_mcp import prepare


def test_codex_native_stop_dispatches_and_returns_wire_continuation(development_server, monkeypatch):
    import asyncio
    from test_development_check import DevelopmentCheckService
    server, root, hooks, launches = development_server
    ref, token = prepare(development_server)
    monkeypatch.setattr(DevelopmentCheckService, '_wake', lambda self, store: launches.append(str(store.root)))
    response = asyncio.run(server.call_tool('handle_stop_event', dict(event='Stop',
        workspace_path=str(root), session_id='delivery-session', stop_hook_active=False, turn_id='turn')))
    assert structured(response)['status'] == 'STOP_FALLBACK_CONTINUATION'
    wire = json.loads(response.content[0].text)
    assert wire['decision'] == 'block' and ref in wire['reason']
    for instruction in ['提交成功后必须从 offset=0 重新读取', '问题', '可能影响', '建议修复', '尚未确认']:
        assert instruction in wire['reason']
    assert len(launches) == 1
    assert call(server, 'get_development_check', workspace_path=str(root), check_ref=ref,
                session_ref=token)['finish_requested']


def test_cursor_cli_stop_followup_and_abort(check, tmp_path, monkeypatch):
    from security_runtime.cursor_automatic import handle_automatic_event
    from security_runtime.cursor_hook import CursorBindings
    from security_runtime.recent_hooks import RecentHookStore
    from security_runtime.tasks.ownership import session_owner
    from security_runtime.development_check import DevelopmentCheckService
    from test_cursor_host_adapter import payload
    root, original, runtime, _ = check
    session = 'private-cursor-conversation'
    service = DevelopmentCheckService(None, original.hooks, owner=session_owner('cursor', session),
                                     scan_path_provider=runtime.store.path, launcher=lambda *a: None)
    ref = service.begin(root, 'cursor-cli')['check_ref']
    service.record(root, ref, ['app.ts'])
    # The bridge also exposes explicit task services, but this lightweight path must not use them.
    from test_hook_runtime import coordinator, FakeRuntime
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    core.store = original.hooks
    bindings = CursorBindings(tmp_path/'bindings')
    monkeypatch.setattr(DevelopmentCheckService, '_wake', lambda *a: None)
    args = dict(core=core, bindings=bindings, project_dir=str(root), store=RecentHookStore(tmp_path/'recent'))
    output, result = handle_automatic_event(payload(root, 'stop', status='aborted', loop_count=0), **args)
    assert output == {} and not service.get(root, ref)['finish_requested']
    output, result = handle_automatic_event(payload(root, 'stop', status='completed', loop_count=0), **args)
    assert 'followup_message' in output, result
    assert ref in output['followup_message']
    assert '提交成功后必须从 offset=0 重新读取' in output['followup_message']
    assert service.get(root, ref)['finish_requested']
    handle_automatic_event(payload(root, 'stop', status='completed', loop_count=1), **args)
    output, result = handle_automatic_event(payload(root, 'stop', status='completed', loop_count=2), **args)
    assert output == {}
    assert result['development_stop']['status'] == 'STOP_FALLBACK_INCOMPLETE'


def test_static_only_keeps_stop_enabled_and_preserves_batch_config(check, config):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false\n')
    ref = service.begin(root, 'static-stop')['check_ref']
    service.record(root, ref, ['app.ts'])
    config.write_text('[development.stop_fallback]\nenabled=false\n')
    result = fallback(service.hooks, root, OWNER, service=service)
    assert result['decision'] == 'block'
    assert set(result['analysis_requirements'].values()) == {'SKIPPED_BY_CONFIG'}
    assert service.get(root, ref)['finish_requested']
    assert '不能冒充 Agent 确认' in result['reason']


def test_disabled_stop_snapshot_survives_reenable_until_new_check(check, config):
    root, service, _, _ = check
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false\n'
                      '[development.stop_fallback]\nenabled=false\n')
    old = service.begin(root, 'disabled-batch')['check_ref']
    service.record(root, old, ['app.ts'])
    config.unlink()
    assert fallback(service.hooks, root, OWNER, service=service) is None
    assert not service.get(root, old)['finish_requested']
    new = service.begin(root, 'new-enabled-batch')['check_ref']
    service.record(root, new, ['app.ts'])
    assert fallback(service.hooks, root, OWNER, service=service)['decision'] == 'block'
    assert not service.get(root, old)['finish_requested']


from test_development_risks import sample, scanner


def test_static_candidate_import_keeps_raw_findings_without_review(sample, config, monkeypatch):
    root, service, ref, risks = sample
    config.write_text('[agent]\nreview_scanner_findings=false\naudit_business_logic=false')
    # Set the batch snapshot before the synthetic saved scan is imported.
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, effective_config=read_config()))
    original = scanner(sample, monkeypatch)
    risks.sync_scanner()
    result = risks.get()
    assert result['total'] == 1 and result['review_versions'] == []
    assert result['risks'][0]['sources'] == ['SCANNER']
    assert result['risks'][0]['finding']['id'] == original['id']
    assert not risks.current_check().get('has_development_review')
    risks.sync_scanner()
    assert risks.get()['risks'][0]['observation_count'] == 1

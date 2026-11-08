"""Command hosts share the existing batch protocol without scanning on edits."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from test_development_check import check
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.tasks.ownership import session_owner
from security_runtime.host_development import audit_context, session_context
from security_runtime.development_check import record_hook, owner_key


@pytest.mark.parametrize('host', ['codex', 'cursor', 'workbuddy'])
def test_all_hosts_offer_existing_compact_review_schema(tmp_path, monkeypatch, host):
    from security_runtime.global_mcp import create_global_server
    from jsonschema import Draft202012Validator
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    server = create_global_server(host=host)
    try:
        tools = {t.name:t for t in asyncio.run(server.list_tools())}
        assert 'development_review' in tools
        if host != 'cursor':
            assert len(tools) <= 20
        context = session_context('test-session', tmp_path)
        request, _ = json.JSONDecoder().raw_decode(context.split('原批次：', 1)[1])
        Draft202012Validator(tools['development_review'].inputSchema).validate(request)
        assert 'REPORT/INCOMPLETE' in context and '不要重新扫描' in context
    finally:
        server.global_workspaces.close()


@pytest.mark.parametrize('host', ['codex', 'cursor', 'workbuddy'])
def test_recovery_scoped_to_owner_and_uses_one_existing_job(check, monkeypatch, host):
    from security_runtime.development_recovery import resume
    root, service, runtime, counters = check
    owner = session_owner(host, 'native-chat')
    row = record_hook(service.hooks, root, owner, ['app.ts'], turn_id='first',
                      scan_path=runtime.store.path, launcher=lambda *a: None)
    launched = []
    def launch(*args):
        launched.append(args[2])
    assert resume(service.hooks, root, session_owner(host, 'other'), launcher=launch) is None
    out = resume(service.hooks, root, owner, launcher=launch)
    assert out['reason'] == f"正在整理安全检查结果。（检查编号 {row['check_ref']}）"
    assert resume(service.hooks, root, owner, launcher=launch) is None
    assert launched == [row['check_ref']] and counters['calls'] == 0
    assert service.store(root).load(row['check_ref'])['dirty_seq'] == 1


@pytest.mark.parametrize('host', ['cursor', 'workbuddy'])
@pytest.mark.parametrize('enabled', [False, True])
def test_post_edit_audit_offer_once_and_no_scan(check, monkeypatch, host, enabled):
    root, service, runtime, counters = check
    config = root.parent/'product.toml'
    config.write_text('[agent]\naudit_business_logic='+str(enabled).lower()+'\n')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(config))
    core = HookCoordinator(runtime, service.hooks, task_audit_mode=True)
    if host == 'workbuddy':
        from security_runtime.workbuddy_hook import handle
        def event(name, **fields):
            p = dict(cwd=str(root), session_id='chat', generation_id='round', hook_event_name=name, **fields)
            return handle(p, core=core, root=root).get('hookSpecificOutput', {}).get('additionalContext', '')
        event('SessionStart')
        first = event('PostToolUse', tool_name='write_to_file', tool_use_id='one', tool_input={'path':str(root/'app.ts')})
        second = event('PostToolUse', tool_name='write_to_file', tool_use_id='one', tool_input={'path':str(root/'app.ts')})
        owner = session_owner(host, 'chat')
    else:
        from security_runtime.cursor_automatic import handle_automatic_event
        from security_runtime.cursor_hook import CursorBindings
        from security_runtime.recent_hooks import RecentHookStore
        from test_cursor_host_adapter import payload
        bindings = CursorBindings(root.parent/'binding')
        recent = RecentHookStore(root.parent/'recent.db')
        def event(name, **fields):
            out, result = handle_automatic_event(payload(root, name, **fields), core=core, bindings=bindings, store=recent, project_dir=str(root))
            assert result.get('reason') != 'CURSOR_AUTOMATIC_TASK_UNAVAILABLE', result
            return out.get('additional_context', '')
        event('sessionStart')
        fields = dict(tool_name='Write', tool_use_id='one', tool_input={'file_path':str(root/'app.ts')})
        event('preToolUse', **fields)
        first = event('postToolUse', **fields)
        second = event('postToolUse', **fields)
        owner = session_owner(host, 'private-cursor-conversation')
    assert ('action=stream_prepare' in first) is enabled
    assert 'action=stream_prepare' not in second
    store = service.store(root)
    row = store.load(store.read('focus:'+owner_key(owner))['check_ref'])
    assert row['observed_paths'] == ['app.ts'] and row['dirty_seq'] == 1
    assert not row['finish_requested'] and counters['calls'] == 0


def test_audit_disabled_context_has_no_store_access():
    class Forbidden:
        def __getattribute__(self, name):
            pytest.fail('No extra storage on disabled audit path')
    assert audit_context(Forbidden(), None, None, {'development_check_ref':'test',
        'analysis_requirements':{'audit_business_logic':'SKIPPED_BY_CONFIG'}}) == ''


def test_cursor_review_envelope_does_not_preapprove_repairs(tmp_path, monkeypatch):
    from security_runtime.global_mcp import create_global_server
    from security_runtime.cursor_permissions import REVIEW_OPERATIONS
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    def forbidden(*a, **kw):
        pytest.fail('Repair operation must be rejected before workspace access')
    server = create_global_server(workspaces=SimpleNamespace(host='cursor', root=forbidden, close=lambda:None))
    async def run():
        tools = {t.name:t for t in await server.list_tools()}
        assert set(tools['development_review'].inputSchema['properties']['operation']['enum']) == REVIEW_OPERATIONS
        for operation in ('prepare_development_risk_fix', 'submit_development_risk_resolution', 'set_development_risk_disposition'):
            result = await server.call_tool('development_review', dict(operation=operation, arguments={'workspace_path':str(tmp_path)}))
            assert result.isError
    asyncio.run(run())


def test_workbuddy_recovers_automatic_edits_without_generation_id(check):
    from security_runtime.development_recovery import resume, eligible
    root, service, runtime, counters = check
    owner = session_owner('workbuddy', 'native-chat')
    row = record_hook(service.hooks, root, owner, ['app.ts'],
                      scan_path=runtime.store.path, launcher=lambda *a:None)
    launched=[]
    out=resume(service.hooks, root, owner, launcher=lambda *a:launched.append(a[2]))
    assert out['check_ref']==row['check_ref'] and launched==[row['check_ref']]
    assert counters['calls']==0
    current=service.store(root).load(row['check_ref'])
    assert not eligible(dict(current, automatic=False))
    assert not eligible(dict(current, owner=session_owner('codex','native-chat')))


@pytest.mark.parametrize('host', ['cursor', 'workbuddy'])
@pytest.mark.parametrize('review', [False, True])
def test_command_hosts_read_and_save_same_batch_once(tmp_path, monkeypatch, host, review):
    import time
    import test_development_risks as fixture
    from test_closeout_notice import ready
    from security_runtime.development_stop import native_closeout, closeout_message
    from security_runtime.development_views import closeout_page
    monkeypatch.setattr(fixture, 'OWNER', session_owner(host, 'chat'))
    sample = fixture.sample.__wrapped__(tmp_path, monkeypatch)
    root, service, ref, risks = sample
    ready(sample, monkeypatch, review)
    out = native_closeout(service, root, risks.current_check(), time.monotonic(), set(), None)
    assert out['reason'] == closeout_message(ref)
    page = closeout_page(risks, 0, 20)
    assert page['closeout_mode'] == ('REVIEW' if review else 'REPORT')
    if review:
        candidate = page['candidates'][0]
        saved = risks.submit([dict(same_issue_as=candidate['same_issue_as'], decision='DISMISSED',
            rationale='Synthetic test validates a bound review protocol.', evidence_refs=candidate['evidence_refs'])],
            page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
        assert '1 条扫描告警为误报' in saved['report_text']
        assert not saved.get('next_action')
        assert native_closeout(service, root, risks.current_check(), time.monotonic(), set(), None) is None
    else:
        assert '未经 Agent' in page['report_text']
        assert page['scan_id'] == 'scan-1'

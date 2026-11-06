import asyncio
import pytest

from test_development_check import check, OWNER
from test_user_config_stop import config
from test_development_check_mcp import development_server, call, projects, installed
from test_global_integration import structured
from security_runtime.development_check import record_hook
from security_runtime.development_stop import fallback


def test_old_check_and_different_readonly_turn_are_quiet(check, config):
    root, service, _, _ = check
    ref = service.begin(root, 'old')['check_ref']
    service.record(root, ref, ['app.ts'])
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.pop('stop_activity')
        store._put(db, ref, row)
    assert fallback(service.hooks, root, OWNER, service=service) is None
    record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='edit')
    before = store.load(ref)
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='readonly') is None
    assert store.load(ref) == before
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='edit')['decision'] == 'block'
    # A new service/connection has no result-offer cache; persisted activity still prevents replay.
    assert fallback(service.hooks, root, OWNER, turn_id='readonly') is None
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='edit', stop_hook_active=True)['decision'] == 'block'
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='edit', stop_hook_active=True)['status'] == 'STOP_FALLBACK_INCOMPLETE'


def test_possible_write_without_new_changes_does_not_reopen_old_check(check, config):
    root, service, _, _ = check
    ref = service.begin(root, 'old')['check_ref']
    service.record(root, ref, ['app.ts'])
    fallback(service.hooks, root, OWNER, service=service)
    record_hook(service.hooks, root, OWNER, prepare_only=True, turn_id='read-script')
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='read-script') is None
    assert service.store(root).load(ref)['stop_fallback']['count'] == 1


def test_codex_native_stop_keeps_edit_and_readonly_turns_separate(development_server, config, monkeypatch):
    server, root, _, launches = development_server
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '0')
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', lambda *a, **kw: launches.append(a))
    common = dict(workspace_path=str(root), session_id='rounds')
    recorded = structured(call(server, 'handle_hook_event', event='PostToolUse', tool_name='Write',
        tool_input={'file_path': str(root/'src/A.java')}, tool_use_id='one', turn_id='editing', **common))
    assert recorded['development_check_ref']
    quiet = structured(call(server, 'handle_stop_event', event='Stop', stop_hook_active=False, turn_id='chat', **common))
    assert quiet.get('decision') != 'block' and not launches
    active = structured(call(server, 'handle_stop_event', event='Stop', stop_hook_active=False, turn_id='editing', **common))
    assert active['status'] == 'STOP_FALLBACK_INCOMPLETE' and 'decision' not in active
    assert active['check_ref'] == recorded['development_check_ref'] and len(launches) == 1


@pytest.mark.parametrize('refs', [[], ['query.py:2'], ['scanner-id'], 'stale', 'unread'])
def test_mcp_evidence_error_recovers_without_saving_or_scanning(development_server, config, refs):
    server, root, hooks, launches = development_server
    config.write_text('[agent]\naudit_business_logic=true\n')
    (root/'query.py').write_text('def query(db, value):\n    return db.execute(value)\n')
    args = dict(workspace_path=str(root))
    ref = call(server, 'begin_development_check', task_key='recovery', **args)['check_ref']
    args['check_ref'] = ref
    call(server, 'record_development_changes', paths=['query.py'], **args)
    if isinstance(refs, str):
        evidence = call(server, 'read_development_risk_context', file_path='query.py',
                        start_line=1 if refs == 'unread' else 2,
                        end_line=1 if refs == 'unread' else 2, **args)
        if refs == 'stale':
            (root/'query.py').write_text('def query(db, value):\n    return db.execute(value)\n# changed\n')
        refs = [evidence['evidence_ref']]
    value = dict(issue_key='sql', file_path='query.py', line_start=2, line_end=2,
        category='sql-injection', title='SQL', description='Unbound input', impact='Read rows',
        fix_advice='Bind value', severity='HIGH', decision='INCONCLUSIVE', rationale='Input reaches SQL', evidence_refs=refs)
    response = asyncio.run(server.call_tool('submit_development_review', dict(args, expected_seq=1, observations=[value])))
    assert response.isError
    result = structured(response)
    assert not result['review_saved'] and not launches
    assert '补读重试后仍失败' in result['message']
    assert call(server, 'get_development_risks', **args)['total'] == 0
    action = result['next_action']
    evidence = call(server, action['tool'], **action['arguments'])
    value['evidence_refs'] = [evidence['evidence_ref']]
    result = call(server, 'submit_development_review', expected_seq=1, observations=[value], **args)
    assert result['review_saved'] and result['next_action']['tool'] == 'get_development_risks'
    assert call(server, 'get_development_risks', **args)['total'] == 1
    assert not launches

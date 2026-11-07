"""Actual MCP routing and Hook result channels, with no scanner substitutes for delivery proof."""
import asyncio
import json
import pytest

from security_runtime.development_check import DevelopmentCheckStore
from security_runtime.development_delivery import publish
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.tasks.ownership import issue_session_ref
from test_development_check_mcp import development_server, call  # noqa: F401
from test_global_integration import projects, structured  # noqa: F401


def prepare(development_server):
    server, root, hooks, launches = development_server
    token = issue_session_ref(hooks, root, 'codex', 'delivery-session')
    row = call(server, 'begin_development_check', workspace_path=str(root), task_key='delivery', session_ref=token)
    ref = row['check_ref']
    call(server, 'record_development_changes', workspace_path=str(root), check_ref=ref,
         paths=['src/A.java'], session_ref=token)
    return ref, token


def test_complete_and_wait_use_one_submission_and_have_no_mcp_ack(development_server, monkeypatch):
    server, root, _, launches = development_server
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '0')
    ref, token = prepare(development_server)
    first = call(server, 'complete_development_check', workspace_path=str(root), check_ref=ref, session_ref=token)
    assert first['status'] == 'QUEUED'
    assert first['closeout_wait']['requested_seconds'] == 0
    assert len(launches) == 1
    again = call(server, 'wait_development_check', workspace_path=str(root), check_ref=ref, session_ref=token)
    assert again['status'] == 'QUEUED' and len(launches) == 1
    names = MCPRegistry(server).names()
    assert 'get_development_result' in names
    assert not any('acknowledge_development' in name for name in names)


def test_native_stop_wait_is_bounded_without_fake_delivery(development_server, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '0')
    server, root, hooks, _ = development_server
    ref, token = prepare(development_server)
    call(server, 'finish_development_check', workspace_path=str(root), check_ref=ref, session_ref=token)
    arguments = dict(event='Stop', workspace_path=str(root), session_id='delivery-session',
                     stop_hook_active=False, turn_id='delivery-turn')
    response = asyncio.run(server.call_tool('handle_stop_event', arguments))
    data = structured(response)
    # Native Stop waits inside the Hook. An unavailable worker is a bounded
    # incomplete notice, not the legacy host-poll continuation.
    assert data['status'] == 'STOP_FALLBACK_INCOMPLETE' and data['decision'] == 'block'
    assert ref in json.loads(response.content[0].text)['reason']
    page = call(server, 'get_development_risks', workspace_path=str(root), check_ref=ref,
                session_ref=token, view='closeout')
    assert page['closeout_mode'] == 'INCOMPLETE' and page['next_action'] is None
    queue = DevelopmentCheckStore(hooks, root)
    with queue.transaction() as db:
        row = queue._get(db, ref)
        row = queue._put(db, ref, dict(row, state='PARTIAL', scanned_seq=1,
            reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
        publish(queue, db, row)
    result = call(server, 'get_development_result', workspace_path=str(root), check_ref=ref,
                  scanned_seq=1, session_ref=token)
    assert result['delivery']['delivery'] == 'PENDING'
    arguments['stop_hook_active'] = True  # Continuation of the blocked turn, not a new read-only round.
    response = asyncio.run(server.call_tool('handle_stop_event', arguments))
    assert structured(response).get('decision') != 'block'  # No fresh edit: do not loop.
    pending = call(server, 'get_development_deliveries', workspace_path=str(root), session_ref=token)
    assert pending['total'] == 1 and not pending['automatic_host_ack']


def test_global_reconnect_does_not_inject_pending_check_context(audit_pool, projects):
    from test_task_audit_startup import start
    pool, server, _ = audit_pool
    root = projects[0]
    start(server, root, 'original')
    core = pool.children[root][1]
    from security_runtime.development_check import DevelopmentCheckService
    from security_runtime.tasks.ownership import session_owner
    service = DevelopmentCheckService(None, core.store, owner=session_owner('codex', 'original'), launcher=lambda *a: None)
    ref = service.begin(root, 'reconnect')['check_ref']
    service.record(root, ref, ['src/A.java'])
    service.finish(root, ref)
    original = asyncio.run(server.call_tool('handle_readiness_event', dict(
        event='SessionStart', workspace_path=str(root), session_id='original')))
    assert ref not in original.content[0].text
    other = asyncio.run(server.call_tool('handle_readiness_event', dict(
        event='SessionStart', workspace_path=str(root), session_id='other')))
    assert ref not in other.content[0].text


def test_bound_stop_configuration_failure_reports_current_edit_without_scan(audit_pool, projects, monkeypatch):
    from test_task_audit_startup import start
    pool, server, _ = audit_pool
    root = projects[0]
    ready = start(server, root, 'interrupted')
    edit = dict(workspace_path=str(root), session_id='interrupted', turn_id='edit',
                tool_use_id='edited', tool_name='Write', tool_input={'file_path': str(root/'src/A.java')})
    response = asyncio.run(server.call_tool('handle_hook_event', dict(edit, event='PostToolUse')))
    ref = structured(response)['development_check_ref']
    stop = dict(event='Stop', workspace_path=str(root), session_id='interrupted',
                turn_id='edit', stop_hook_active=False)
    validate = pool.validate_layers
    def unavailable(*args):
        raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
    monkeypatch.setattr(pool, 'validate_layers', unavailable)
    response = asyncio.run(server.call_tool('handle_stop_event', stop))
    assert structured(response)['status'] == 'STOP_FALLBACK_INCOMPLETE'
    assert json.loads(response.content[0].text) == dict(decision='block',
        reason=f'正在整理安全检查结果。（检查编号 {ref}）')
    monkeypatch.setattr(pool, 'validate_layers', validate)
    response = asyncio.run(server.call_tool('get_development_risks', dict(
        workspace_path=str(root), session_ref=ready['task_session_ref'], check_ref=ref, view='closeout')))
    page = structured(response)
    assert page['closeout_mode'] == 'INCOMPLETE' and page['next_action'] is None
    assert 'STOP_CLOSEOUT_FAILED' in page['gaps'] and '收尾处理发生异常' in page['report_text']


from test_task_audit_startup import audit_pool  # noqa: E402,F401
from test_global_integration import installed  # noqa: E402,F401


@pytest.mark.parametrize('change', ['unchanged', 'new_edit', 'new_result'])
def test_waiting_offer_only_suppresses_same_pending_batch(development_server, monkeypatch, change):
    server, root, hooks, launches = development_server
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '0')
    ref, token = prepare(development_server)
    waiting = call(server, 'complete_development_check', workspace_path=str(root),
                   check_ref=ref, session_ref=token)
    assert waiting['status'] == 'QUEUED' and len(launches) == 1
    if change == 'new_edit':
        call(server, 'record_development_changes', workspace_path=str(root),
             check_ref=ref, paths=['src/A.java'], session_ref=token)
    elif change == 'new_result':
        store = DevelopmentCheckStore(hooks, root)
        with store.transaction() as db:
            row = store._get(db, ref)
            row = store._put(db, ref, dict(row, state='PARTIAL', scanned_seq=row['dirty_seq'],
                reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
            publish(store, db, row)
    response = asyncio.run(server.call_tool('handle_stop_event', dict(event='Stop',
        workspace_path=str(root), session_id='delivery-session',
        stop_hook_active=False, turn_id='delivery-turn')))
    assert structured(response).get('decision') == 'block'
    # Synthetic rows here have no completed scan_id. Never invent a report
    # or ask the model to repeat a scan when the native wait has no result.
    assert structured(response)['status'] == 'STOP_FALLBACK_INCOMPLETE'
    page = call(server, 'get_development_risks', workspace_path=str(root), check_ref=ref,
                session_ref=token, view='closeout')
    assert page['closeout_mode'] == 'INCOMPLETE' and page['next_action'] is None
    if change == 'unchanged':
        assert len(launches) == 1
        row = call(server, 'get_development_check', workspace_path=str(root),
                   check_ref=ref, session_ref=token)
        assert row['status'] == 'QUEUED' and not row['host_review_completed']

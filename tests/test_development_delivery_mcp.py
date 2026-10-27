"""Actual MCP routing and Hook result channels, with no scanner substitutes for delivery proof."""
import asyncio
import json

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


def test_stop_continues_original_work_then_result_offer_stops_loop_without_fake_delivery(development_server):
    server, root, hooks, _ = development_server
    ref, token = prepare(development_server)
    call(server, 'finish_development_check', workspace_path=str(root), check_ref=ref, session_ref=token)
    arguments = dict(event='Stop', workspace_path=str(root), session_id='delivery-session',
                     stop_hook_active=False, turn_id='delivery-turn')
    response = asyncio.run(server.call_tool('handle_stop_event', arguments))
    data = structured(response)
    assert data['decision'] == 'block' and ref in json.loads(response.content[0].text)['reason']
    queue = DevelopmentCheckStore(hooks, root)
    with queue.transaction() as db:
        row = queue._get(db, ref)
        row = queue._put(db, ref, dict(row, state='PARTIAL', scanned_seq=1,
            reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
        publish(queue, db, row)
    result = call(server, 'get_development_result', workspace_path=str(root), check_ref=ref,
                  scanned_seq=1, session_ref=token)
    assert result['delivery']['delivery'] == 'PENDING'
    response = asyncio.run(server.call_tool('handle_stop_event', arguments))
    assert structured(response).get('decision') != 'block'
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


from test_task_audit_startup import audit_pool  # noqa: E402,F401
from test_global_integration import installed  # noqa: E402,F401

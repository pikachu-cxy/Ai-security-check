"""Default development transport stays scoped and never enters strict audit capture."""
import asyncio
import inspect

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.ownership import issue_session_ref
from test_global_integration import installed, projects, structured  # noqa: F401


@pytest.fixture
def development_server(projects, tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.development_scheduler.supervise', lambda *a: None)
    from security_runtime.development_check import DevelopmentCheckService
    root = projects[0]
    hooks = HookStateStore(tmp_path/'hooks')
    runtime = SecurityRuntime(store=SQLiteStore(tmp_path/'scans.db'))
    launches = []

    def service(*args, **kwargs):
        kwargs['launcher'] = lambda *a, **kw: launches.append((a, kw))
        return DevelopmentCheckService(*args, **kwargs)

    monkeypatch.setattr('security_runtime.development_check.DevelopmentCheckService', service)

    def forbidden(*args, **kwargs):
        pytest.fail('Lightweight development must not enter whole-workspace capture or inline scan')

    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr('security_runtime.hook_runtime.capture_snapshot', forbidden)
    monkeypatch.setattr('security_runtime.task_closeout_worker.recover', forbidden)
    monkeypatch.setattr(runtime, 'scan', forbidden)
    binding = WorkspaceBinding('development-test', str(root), str(root), 'codex', 'PROJECT', '')
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, hooks),
                           workspace_binding=binding, global_mode=False)
    return server, root, hooks, launches


def call(server, name, **arguments):
    result = server._tool_manager.get_tool(name).fn(**arguments)
    return asyncio.run(result) if inspect.isawaitable(result) else result


def test_begin_record_close_and_read_never_capture_workspace(development_server):
    server, root, hooks, launches = development_server
    first = call(server, 'begin_development_check', workspace_path=str(root), task_key='one')
    assert first['check_ref'].startswith('dc1-')
    assert not launches
    ref = first['check_ref']
    declared = call(server, 'declare_development_outputs', workspace_path=str(root),
                    check_ref=ref, paths=['arbitrary/build-output'])
    assert declared['scope']['generated_outputs']['declared_roots'] == ['arbitrary/build-output']
    assert not launches
    recorded = call(server, 'record_development_changes', workspace_path=str(root),
                    check_ref=ref, paths=['src/A.java', 'src/deleted.java'], event_id='one-edit')
    assert recorded['dirty_seq'] > 0
    call(server, 'finish_development_check', workspace_path=str(root), check_ref=ref)
    launch_count = len(launches)
    result = call(server, 'get_development_check', workspace_path=str(root), check_ref=ref)
    assert result['check_ref'] == ref and len(launches) == launch_count
    assert not (hooks.workspace_directory(root)/'task-security.db').exists()


def test_chat_without_edits_does_not_launch_worker(development_server):
    server, root, _, launches = development_server
    first = call(server, 'begin_development_check', workspace_path=str(root), task_key='no-edit')
    result = call(server, 'finish_development_check', workspace_path=str(root), check_ref=first['check_ref'])
    assert result['status'] == 'NO_OBSERVED_CHANGES'
    assert not launches


def test_session_ownership_not_inferred_from_check_reference(development_server):
    server, root, hooks, _ = development_server
    first_owner = issue_session_ref(hooks, root, 'codex', 'first')
    other_owner = issue_session_ref(hooks, root, 'codex', 'second')
    first = call(server, 'begin_development_check', workspace_path=str(root),
                 task_key='same-key', session_ref=first_owner)
    with pytest.raises(ValueError):
        call(server, 'get_development_check', workspace_path=str(root),
             check_ref=first['check_ref'], session_ref=other_owner)
    assert call(server, 'get_development_check', workspace_path=str(root),
                check_ref=first['check_ref'], session_ref=first_owner)['check_ref'] == first['check_ref']


def test_mcp_schema_rejects_extra_authority_and_boolean_coercion(development_server):
    server, root, _, launches = development_server
    registry = MCPRegistry(server)
    first = call(server, 'begin_development_check', workspace_path=str(root), task_key='schema')
    for extra in ({'repair_authorized': True}, {'scope_unknown': 'false'}):
        with pytest.raises(Exception):
            asyncio.run(registry.dispatch('record_development_changes', dict(
                workspace_path=str(root), check_ref=first['check_ref'], paths=['src/A.java'], **extra)))
    assert not launches
    assert registry.tool('get_development_check').annotations.readOnlyHint
    assert 'begin_security_task' in registry.names()  # Historical strict audits remain supported.


@pytest.mark.parametrize('value', [-1, 26, True, 0.5, '2', None])
def test_wait_schema_rejects_invalid_budget_before_finishing(development_server, value):
    server, root, _, launches = development_server
    registry = MCPRegistry(server)
    first = call(server, 'begin_development_check', workspace_path=str(root), task_key='wait-validation')
    with pytest.raises(Exception):
        asyncio.run(registry.dispatch('finish_development_check', dict(
            workspace_path=str(root), check_ref=first['check_ref'], wait_seconds=value)))
    current = call(server, 'get_development_check', workspace_path=str(root), check_ref=first['check_ref'])
    assert not current['finish_requested'] and not launches


def test_wait_mcp_dispatch_yields_to_another_read(development_server, monkeypatch):
    from security_runtime import development_check
    server, root, _, launches = development_server
    registry = MCPRegistry(server)
    first = call(server, 'begin_development_check', workspace_path=str(root), task_key='parallel-read')
    call(server, 'record_development_changes', workspace_path=str(root),
         check_ref=first['check_ref'], paths=['src/A.java'])
    original_factory = development_check.DevelopmentCheckService

    async def run():
        entered, blocked = asyncio.Event(), asyncio.Event()

        async def pause(seconds):
            entered.set()
            await blocked.wait()

        def factory(*args, **kwargs):
            service = original_factory(*args, **kwargs)
            service.wait_sleep = pause
            return service

        monkeypatch.setattr(development_check, 'DevelopmentCheckService', factory)
        pending = asyncio.create_task(registry.dispatch('finish_development_check', dict(
            workspace_path=str(root), check_ref=first['check_ref'], wait_seconds=25)))
        await asyncio.wait_for(entered.wait(), timeout=5)
        result = await asyncio.wait_for(registry.dispatch('get_development_check', dict(
            workspace_path=str(root), check_ref=first['check_ref'])), timeout=5)
        assert result['status'] == 'QUEUED' and result['finish_requested']
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

    asyncio.run(run())
    assert len(launches) == 1


def test_global_router_requires_workspace_and_keeps_session_scope(installed, projects, tmp_path, monkeypatch):
    from security_runtime.global_mcp import GlobalWorkspaces, create_global_server

    def forbidden(*args, **kwargs):
        pytest.fail('Routing and metadata must not capture sources, recover old work, or scan')

    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr('security_runtime.task_closeout_worker.recover', forbidden)
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', forbidden)
    installed.execute('setup')

    def child(root, directory, binding):
        runtime = SecurityRuntime(store=SQLiteStore(directory/'scans.db'))
        monkeypatch.setattr(runtime, 'scan', forbidden)
        core = HookCoordinator(runtime, HookStateStore(directory/'hooks'))
        return create_server(runtime, hook_coordinator=core, workspace_binding=binding,
                             global_mode=False), core

    pool = GlobalWorkspaces(base=tmp_path/'routing', integration=installed, child_factory=child)
    server = create_global_server(workspaces=pool)

    def routed(name, **arguments):
        return structured(asyncio.run(server.call_tool(name, arguments)))

    try:
        rejected = routed('begin_development_check', task_key='missing-workspace')
        assert rejected['reason_code'] == 'DEVELOPMENT_CHECK_REQUEST_INVALID'
        assert not pool.children
        root = str(projects[0])
        events = [routed('handle_readiness_event', event='SessionStart',
                         workspace_path=root, session_id=session)
                  for session in ('first', 'second')]
        assert all('task_session_ref' in event for event in events), events
        tokens = [event['task_session_ref'] for event in events]
        check = routed('begin_development_check', workspace_path=root,
                       session_ref=tokens[0], task_key='one')
        assert check['check_ref'].startswith('dc1-')
        other = routed('get_development_check', workspace_path=root,
                       session_ref=tokens[1], check_ref=check['check_ref'])
        assert other['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
        current = routed('get_development_check', workspace_path=root,
                         session_ref=tokens[0], check_ref=check['check_ref'])
        assert current['check_ref'] == check['check_ref']
        risks = routed('get_development_risks', workspace_path=root,
                       session_ref=tokens[0], check_ref=check['check_ref'])
        assert risks['total'] == 0 and not risks['scanner_run']
        other_risks = routed('get_development_risks', workspace_path=root,
                            session_ref=tokens[1], check_ref=check['check_ref'])
        assert other_risks['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
        invalid = routed('submit_development_review', workspace_path=root, session_ref=tokens[0],
                         check_ref=check['check_ref'], expected_seq=999, observations=[])
        assert invalid['reason_code'] == 'DEVELOPMENT_RISK_VERSION_STALE'
        schema = next(tool.inputSchema for tool in asyncio.run(server.list_tools())
                      if tool.name == 'finish_development_check')
        assert schema['properties']['wait_seconds']['minimum'] == 0
        assert schema['properties']['wait_seconds']['maximum'] == 25
        rejected = routed('finish_development_check', workspace_path=root,
                          session_ref=tokens[1], check_ref=check['check_ref'], wait_seconds=25)
        assert rejected['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
        empty = routed('finish_development_check', workspace_path=root,
                       session_ref=tokens[0], check_ref=check['check_ref'], wait_seconds=25)
        assert empty['status'] == 'NO_OBSERVED_CHANGES' and empty['dirty_seq'] == 0
        assert empty['closeout_wait']['requested_seconds'] == 25 and not empty['scanner_run']
    finally:
        pool.close()

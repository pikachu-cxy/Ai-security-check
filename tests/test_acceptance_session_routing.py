"""Native startup routing survives slow/failed bootstrap and reconnects safely."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from security_runtime.global_mcp import create_global_server, GLOBAL_READS, HOOKS
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.tasks.ownership import session_owner, verify_session_ref
from security_runtime.tasks.security import TaskSecurityService
from test_global_integration import complete_runtime, installed, projects, pool_fixture


def call(server, name, **arguments):
    response = asyncio.run(server.call_tool(name, arguments))
    if isinstance(response, list):
        return SimpleNamespace(structuredContent=json.loads(response[0].text), content=response)
    return response


def startup(server, root, session='acceptance-chat'):
    return call(server, 'handle_readiness_event', event='SessionStart',
                workspace_path=str(root), session_id=session)


@pytest.mark.parametrize('status', ['READY', 'INITIALIZING', 'DEGRADED'])
def test_every_valid_start_delivers_owner_without_claiming_scan_ready(
        installed, projects, tmp_path, status):
    pool = pool_fixture(installed, tmp_path)
    pool._initialize = lambda *args: dict(status=status, security_proof=False)
    server = create_global_server(workspaces=pool)
    try:
        response = startup(server, projects[0])
        data = response.structuredContent
        assert data['status'] == status and data['security_proof'] is False, data
        token = data['task_session_ref']
        core = pool.children[projects[0]][1]
        assert verify_session_ref(core.store, projects[0], token) == session_owner('codex', 'acceptance-chat')
        payload = json.loads(response.content[0].text)
        assert token in payload['hookSpecificOutput']['additionalContext']
        assert token not in payload.get('systemMessage', '')
        assert payload['hookSpecificOutput']['hookEventName'] == 'SessionStart'
        if status != 'READY':
            context = payload['hookSpecificOutput']['additionalContext']
            assert '不取消当前开发任务核查' in context
            assert '已有任务沿用原引用' in context
            assert '无需用户另发继续' in context
            assert '新建聊天' not in payload['systemMessage']
    finally:
        pool.close()


def task_pool(installed, tmp_path):
    def factory(root, directory, binding):
        runtime = complete_runtime()
        core = HookCoordinator(runtime, HookStateStore(directory / 'hooks'))
        return create_server(runtime, hook_coordinator=core, workspace_binding=binding,
                             global_mode=False), core
    pool = pool_fixture(installed, tmp_path, factory)
    # Deliberate unavailable startup scan, independent of native identity.
    pool._initialize = lambda *args: dict(status='DEGRADED', reason_code='BASELINE_BUSY', security_proof=False)
    return pool


def test_native_task_uses_host_owner_and_resumes_exact_pre_edit_record(
        installed, projects, tmp_path):
    root = projects[0]
    first = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=first)
    try:
        token = startup(server, root).structuredContent['task_session_ref']
        begun = call(server, 'begin_security_task', task_key='native-development',
                     workspace_path=str(root), session_ref=token).structuredContent
        assert begun['status'] == 'ACTIVE' and begun['task_scope'] == 'HOST_SESSION'
        ref = begun['task_ref']
        core = first.children[root][1]
        service = TaskSecurityService(core.runtime, core.store, owner=session_owner('codex', 'acceptance-chat'))
        before = service.load(root, ref)['baseline']['hashes'].copy()
        (root / 'src/A.java').write_text('class A { int count; }\n')
    finally:
        first.close()
    second = task_pool(installed, tmp_path)
    reconnected = create_global_server(workspaces=second)
    try:
        foreign = startup(reconnected, root, 'other-chat').structuredContent['task_session_ref']
        rejected = call(reconnected, 'finish_security_task', task_ref=ref,
                        workspace_path=str(root), session_ref=foreign).structuredContent
        assert rejected['status'] == 'INCONCLUSIVE'
        assert rejected['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
        assert '聊天身份与原任务不一致' in rejected['message']
        assert foreign not in json.dumps(rejected)
        assert session_owner('codex', 'other-chat')['session'] not in json.dumps(rejected)
        missing = call(reconnected, 'finish_security_task', task_ref=ref,
                       workspace_path=str(root)).structuredContent
        assert missing['reason_code'] == 'TASK_SESSION_BINDING_REQUIRED'
        same = startup(reconnected, root).structuredContent['task_session_ref']
        finished = call(reconnected, 'finish_security_task', task_ref=ref,
                        workspace_path=str(root), session_ref=same).structuredContent
        assert finished['status'] == 'READY', finished
        core = second.children[root][1]
        service = TaskSecurityService(core.runtime, core.store, owner=session_owner('codex', 'acceptance-chat'))
        record = service.load(root, ref)
        assert record['baseline']['hashes'] == before
        assert len(service.store(root).records()) == 1
        assert not list(root.glob('.reconnect*'))
    finally:
        second.close()


def test_new_native_owner_cannot_adopt_old_connection_only_task(
        installed, projects, tmp_path):
    root = projects[0]
    first = task_pool(installed, tmp_path)
    try:
        server = create_global_server(workspaces=first)
        begun = call(server, 'begin_security_task', task_key='unbound',
                     workspace_path=str(root)).structuredContent
        assert begun['task_scope'] == 'MCP_CONNECTION'
        ref = begun['task_ref']
        core = first.children[root][1]
        original = TaskSecurityService(core.runtime, core.store).store(root).get(ref)
    finally:
        first.close()
    second = task_pool(installed, tmp_path)
    try:
        server = create_global_server(workspaces=second)
        token = startup(server, root).structuredContent['task_session_ref']
        rejected = call(server, 'finish_security_task', task_ref=ref,
                        workspace_path=str(root), session_ref=token).structuredContent
        assert rejected['status'] == 'INCONCLUSIVE'
        assert rejected['reason_code'] == 'TASK_CONNECTION_SCOPE_MISMATCH'
        assert '没有可恢复的聊天身份' in rejected['message']
        assert token not in json.dumps(rejected)
        core = second.children[root][1]
        assert TaskSecurityService(core.runtime, core.store).store(root).get(ref) == original
    finally:
        second.close()


def test_global_task_feedback_tools_require_workspace_and_fence_native_owner(
        installed, projects, tmp_path):
    root = projects[0]
    pool = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    names = {'prepare_task_risk_feedback', 'submit_task_risk_feedback',
             'mark_task_risk_false_positive', 'revoke_task_risk_feedback', 'get_task_risk_feedback',
             'set_task_risk_disposition'}
    try:
        listed = {tool.name: tool for tool in asyncio.run(server.list_tools())}
        assert names <= listed.keys()
        for name, tool in listed.items():
            if name not in GLOBAL_READS | HOOKS:
                assert 'workspace_path' in tool.inputSchema['required']
                assert tool.inputSchema['properties']['workspace_path']['type'] == 'string'
                assert tool.inputSchema['properties']['workspace_path']['minLength'] == 1
        feedback_schema = listed['get_task_risk_feedback'].inputSchema
        assert 'session_ref' in feedback_schema['properties']
        assert 'session_ref' not in feedback_schema['required']
        assert feedback_schema['properties']['session_ref']['default'] is None
        token = startup(server, root).structuredContent['task_session_ref']
        begun = call(server, 'begin_security_task', task_key='selected-risk-review',
                     workspace_path=str(root), session_ref=token).structuredContent
        ref = begun['task_ref']
        core = pool.children[root][1]
        records = TaskSecurityService(core.runtime, core.store).store(root)
        original = records.get(ref)
        foreign = startup(server, root, 'other-chat').structuredContent['task_session_ref']
        arguments = dict(task_ref=ref, finding_id='unselected-finding')
        requests = {
            'prepare_task_risk_feedback': {},
            'submit_task_risk_feedback': dict(feedback_ref='unissued-feedback', verdict='FALSE_POSITIVE',
                rationale='fixture rationale', counterevidence=[], evidence_refs=[]),
            'mark_task_risk_false_positive': dict(reason='fixture user opinion', user_requested=True),
            'revoke_task_risk_feedback': dict(reason='fixture revocation', user_requested=True),
            'get_task_risk_feedback': {},
            'set_task_risk_disposition': dict(disposition='EXCLUDE', user_requested=True),
        }
        for name, extra in requests.items():
            missing = call(server, name, **arguments, **extra).structuredContent
            assert missing['reason_code'] == 'FEEDBACK_INPUT_INVALID'
            rejected = call(server, name, **arguments, **extra,
                workspace_path=str(root), session_ref=foreign).structuredContent
            assert rejected['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
            assert rejected['repair_authorized'] is False
            assert foreign not in json.dumps(rejected)
        assert records.get(ref) == original
    finally:
        pool.close()

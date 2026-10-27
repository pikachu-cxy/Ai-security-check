"""Default product startup validates routing without product A or task B."""
import asyncio
import json

import pytest

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.task_audit_mode import connection_readiness
from security_runtime.tasks.ownership import session_owner, verify_session_ref
from test_global_integration import installed, projects, complete_runtime, structured  # noqa: F401


@pytest.fixture
def audit_pool(installed, tmp_path, monkeypatch):
    monkeypatch.setattr('security_runtime.development_scheduler.supervise', lambda *a: None)
    installed.execute('setup')
    def forbidden(*args, **kwargs):
        pytest.fail('Startup must not create A, capture B, or inventory/scan project sources')
    monkeypatch.setattr('security_runtime.product_epoch_jobs.ProductEpochJobs.start', forbidden)
    monkeypatch.setattr('security_runtime.product_epoch_worker.launch', forbidden)
    monkeypatch.setattr('security_runtime.product_epoch_capture.platform_supported', lambda: False)
    monkeypatch.setattr('security_runtime.hook_runtime.capture_snapshot', forbidden)
    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', lambda *a, **k: None)
    engines = {}
    def factory(root, directory, binding):
        engine = complete_runtime()
        engines[root] = engine
        monkeypatch.setattr(engine, 'scan', forbidden)
        core = HookCoordinator(engine, HookStateStore(directory/'hooks'))
        return create_server(engine, hook_coordinator=core, workspace_binding=binding,
                             global_mode=False), core
    pool = GlobalWorkspaces(base=tmp_path/'workspaces', integration=installed, child_factory=factory)
    try:
        yield pool, create_global_server(workspaces=pool), engines
    finally:
        pool.close()


def start(server, root, session='demo'):
    response = asyncio.run(server.call_tool('handle_readiness_event', dict(
        event='SessionStart', workspace_path=str(root), session_id=session)))
    data = structured(response)
    if data.get('status') == 'CONNECTED':
        payload = json.loads(response.content[0].text)
        assert '不建立全项目基线' in payload['hookSpecificOutput']['additionalContext']
        assert '检查未完成' not in payload['hookSpecificOutput']['additionalContext']
    return data


def test_windows_new_project_and_chat_connect_without_any_baseline(audit_pool, projects):
    pool, server, _ = audit_pool
    for root, session in zip(projects, ('first-chat', 'second-chat')):
        data = start(server, root, session)
        assert data['status'] == 'CONNECTED'
        assert data['startup_comparison_baseline']['status'] == 'NOT_REQUIRED'
        assert not data['startup_comparison_baseline']['created']
        assert data['session_binding_status'] == 'MATCH'
        assert data['project_scan_status'] == 'NOT_REQUESTED'
        assert data['scan_preparation']['verified_now'] is False
        core = pool.children[root][1]
        assert verify_session_ref(core.store, root, data['task_session_ref']) == session_owner('codex', session)
        state = core.store.workspace_directory(root)
        assert not (state/'task-security.db').exists()
        assert not core.store.path(root, 'codex', session).exists()
        assert not pool.jobs
        assert not any('product-epoch' in path.name for path in state.iterdir())


def test_readonly_and_no_task_stop_do_not_create_baselines_or_scan(audit_pool, projects):
    pool, server, _ = audit_pool
    root = projects[0]
    start(server, root)
    data = structured(asyncio.run(server.call_tool('handle_hook_event', dict(
        event='PostToolUse', workspace_path=str(root), session_id='demo', turn_id='turn',
        tool_use_id='read', tool_name='Bash', tool_input={'command':'git status'}))))
    assert not data['scanner_run']
    stopped = structured(asyncio.run(server.call_tool('handle_stop_event', dict(
        event='Stop', workspace_path=str(root), session_id='demo', stop_hook_active=False))))
    assert not stopped.get('scanner_run') and stopped['status'] == 'ALLOW_STOP'
    core = pool.children[root][1]
    assert not (core.store.workspace_directory(root)/'task-security.db').exists()
    assert not core.store.path(root, 'codex', 'demo').exists()


def test_edit_without_baseline_records_observed_scope_without_backfill(audit_pool, projects):
    pool, server, _ = audit_pool
    root = projects[0]
    start(server, root)
    data = structured(asyncio.run(server.call_tool('handle_hook_event', dict(
        event='PostToolUse', workspace_path=str(root), session_id='demo', turn_id='turn',
        tool_use_id='edit', tool_name='apply_patch',
        tool_input='*** Begin Patch\n*** Update File: src/A.java\n@@\n-old\n+new\n*** End Patch'))))
    assert data['status'] == 'DIRTY'
    assert data['development_check_ref'].startswith('dc1-')
    assert data['scope']['paths'] == ['src/A.java']
    assert not data['baseline_created'] and not data['scope']['full_project']
    assert not data['scanner_run']
    core = pool.children[root][1]
    assert not (core.store.workspace_directory(root)/'task-security.db').exists()
    assert not core.store.path(root, 'codex', 'demo').exists()


def test_session_cannot_be_rebound_to_another_workspace(audit_pool, projects):
    _, server, _ = audit_pool
    start(server, projects[0])
    rejected = start(server, projects[1])
    assert rejected['status'] == 'INCONCLUSIVE'
    assert rejected['reason_code'] == 'SESSION_WORKSPACE_MISMATCH'


def test_saved_component_failure_and_stale_data_remain_separate_from_connection(monkeypatch):
    tools = {name: dict(status='READY', ready=True, version='1.0', expected_version='1.0')
             for name in ('semgrep', 'gitleaks', 'trivy')}
    tools['semgrep'].update(status='MISSING', ready=False, version='')
    receipt = dict(contract='installation-readiness-v1', status='PARTIAL', ready=False,
        message='private-saved-message', network_allowed=False, tools=tools, failures=[],
        vulnerability_db=dict(status='READY', freshness='STALE', ready=False,
            cached_usable=True, updated_at='2020-01-01T00:00:00+00:00',
            next_update='2020-01-02T00:00:00+00:00'))
    monkeypatch.setattr('security_runtime.background_preparation.current_preparation',
        lambda: dict(status='FAILED', receipt=receipt))
    data = connection_readiness()
    assert data['status'] == 'CONNECTED'
    assert data['scan_preparation']['status'] == 'KNOWN_GAPS'
    assert data['scan_preparation']['components']['semgrep']['saved_status'] == 'MISSING'
    assert data['scan_preparation']['vulnerability_data']['freshness'] == 'STALE'
    assert data['scan_preparation']['current_ready'] is None
    assert '漏洞数据已过期' in data['message']
    assert 'private' not in json.dumps(data)


def test_configuration_failure_still_rejects_startup(audit_pool, projects, monkeypatch):
    pool, server, _ = audit_pool
    monkeypatch.setattr(pool.integration, 'configuration_status', lambda: dict(overall='DEGRADED'))
    data = start(server, projects[0])
    assert data['status'] == 'INCONCLUSIVE'
    assert data['reason_code'] == 'GLOBAL_CONFIGURATION_NOT_READY'


def test_startup_does_not_read_or_rewrite_an_existing_unavailable_A(audit_pool, projects):
    pool, server, _ = audit_pool
    root = projects[0]
    start(server, root)
    core = pool.children[root][1]
    legacy = core.store.path(root, 'codex', 'demo')
    raw = b'old unavailable product A history'
    legacy.write_bytes(raw)
    result = start(server, root)
    assert result['status'] == 'CONNECTED'
    assert legacy.read_bytes() == raw


def edit_without_start(server, root, session, invocation):
    return asyncio.run(server.call_tool('handle_hook_event', dict(
        event='PostToolUse', workspace_path=str(root), session_id=session,
        turn_id='fixture-turn', tool_use_id=invocation, tool_name='apply_patch',
        tool_input={'command':'*** Begin Patch\n*** Update File: src/A.java\n@@\n-old\n+new\n*** End Patch'})))


def test_first_native_edit_recovers_its_own_routing_without_startup(audit_pool, projects):
    pool, server, _ = audit_pool
    root = projects[0]
    response = edit_without_start(server, root, 'late-start', 'first-edit')
    result = structured(response)
    assert result['status'] == 'DIRTY' and result['scope']['paths'] == ['src/A.java']
    token = result['task_session_ref']
    hooks = pool.children[root][1].store
    assert verify_session_ref(hooks, root, token) == session_owner('codex', 'late-start')
    output = json.loads(response.content[0].text)
    assert output['hookSpecificOutput']['hookEventName'] == 'PostToolUse'
    assert token in output['hookSpecificOutput']['additionalContext']
    assert result['development_check_ref'] in output['hookSpecificOutput']['additionalContext']
    adopted = structured(asyncio.run(server.call_tool('begin_development_check', dict(
        workspace_path=str(root), session_ref=token, task_key='adopt-native-edit'))))
    assert adopted['check_ref'] == result['development_check_ref']
    assert adopted['dirty_seq'] == 1 and not adopted['baseline_created']
    second = edit_without_start(server, root, 'late-start', 'second-edit')
    assert 'task_session_ref' not in structured(second)
    assert json.loads(second.content[0].text) == {}
    assert not (hooks.workspace_directory(root)/'task-security.db').exists()


def test_valid_startup_keeps_edit_routing_context_quiet(audit_pool, projects):
    _, server, _ = audit_pool
    root = projects[0]
    start(server, root, 'started')
    response = edit_without_start(server, root, 'started', 'edit-after-start')
    assert structured(response)['status'] == 'DIRTY'
    assert 'task_session_ref' not in structured(response)
    assert json.loads(response.content[0].text) == {}


def test_recovered_edit_token_cannot_adopt_another_sessions_record(audit_pool, projects):
    _, server, _ = audit_pool
    root = projects[0]
    first = structured(edit_without_start(server, root, 'first-owner', 'first-owner-edit'))
    second = structured(edit_without_start(server, root, 'second-owner', 'second-owner-edit'))
    rejected = structured(asyncio.run(server.call_tool('get_development_check', dict(
        workspace_path=str(root), session_ref=second['task_session_ref'],
        check_ref=first['development_check_ref']))))
    assert rejected['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'


def test_readonly_without_startup_recovers_only_routing_without_creating_a_check(audit_pool, projects):
    pool, server, _ = audit_pool
    root = projects[0]
    response = asyncio.run(server.call_tool('handle_hook_event', dict(
        event='PostToolUse', workspace_path=str(root), session_id='readonly-only',
        turn_id='readonly-turn', tool_use_id='readonly-call', tool_name='Bash',
        tool_input={'command':'git status --short'})))
    assert not structured(response)['scanner_run']
    token = structured(response)['task_session_ref']
    assert token.startswith('sh1-') and len(token) == 36
    hooks = pool.children[root][1].store
    assert verify_session_ref(hooks, root, token) == session_owner('codex', 'readonly-only')
    assert 'development_check_ref' not in structured(response)
    output = json.loads(response.content[0].text)
    assert token in output['hookSpecificOutput']['additionalContext']
    assert not (hooks.workspace_directory(root)/'development-checks.db').exists()
    again = asyncio.run(server.call_tool('handle_hook_event', dict(
        event='PostToolUse', workspace_path=str(root), session_id='readonly-only',
        turn_id='readonly-turn', tool_use_id='readonly-again', tool_name='Bash',
        tool_input={'command':'git status --short'})))
    assert 'task_session_ref' not in structured(again)
    assert json.loads(again.content[0].text) == {}


def test_short_native_handle_resumes_exact_check_created_with_legacy_reference(audit_pool, projects):
    from security_runtime.tasks.ownership import issue_session_ref
    pool, server, _ = audit_pool
    root = projects[0]
    short = start(server, root, 'same-owner')['task_session_ref']
    hooks = pool.children[root][1].store
    legacy = issue_session_ref(hooks, root, 'codex', 'same-owner')
    from security_runtime.storage import SQLiteStore
    pool.children[root][1].runtime.store = SQLiteStore(hooks.directory.parent/'scans.db')
    begun = structured(asyncio.run(server.call_tool('begin_development_check', dict(
        workspace_path=str(root), session_ref=legacy, task_key='preserve-original'))))
    assert 'check_ref' in begun, begun
    ref = begun['check_ref']
    resumed = structured(asyncio.run(server.call_tool('get_development_check', dict(
        workspace_path=str(root), session_ref=short, check_ref=ref))))
    assert resumed['check_ref'] == ref and resumed['dirty_seq'] == begun['dirty_seq'] == 0
    assert not resumed['baseline_created'] and not resumed['scanner_run']
    from security_runtime.development_check import DevelopmentCheckStore
    records = DevelopmentCheckStore(hooks, root).rows()
    assert len([row for row in records if row.get('kind') == 'check']) == 1

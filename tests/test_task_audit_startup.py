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

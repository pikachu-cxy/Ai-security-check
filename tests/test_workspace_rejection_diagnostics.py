"""Ordinary MCP tools retain bounded admission diagnostics, never raw errors."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from test_codex_worktree_admission import linked_worktree
from test_global_integration import installed, projects, pool_fixture, structured
from test_task_context_global_transport import task_pool


def invoke(server, name='begin_security_task', **arguments):
    return asyncio.run(server.call_tool(name, arguments))


def message(result):
    return json.loads(result.content[0].text)['systemMessage']


def assert_rejected(result, *, reason, stage, detail):
    data = structured(result)
    assert data['status'] == 'INCONCLUSIVE'
    assert data['reason_code'] == reason
    assert data['workspace_binding_stage'] == stage
    assert data['workspace_rejection_reason'] == detail
    assert data['scanner_run'] is False
    assert data['source_modified'] is False
    assert data['security_proof'] is False
    assert 'host_claim_status' not in data
    return data


def test_begin_in_excluded_host_state_reports_boundary_without_scanning(installed, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    try:
        before = {p: p.read_bytes() for p in installed.home.iterdir() if p.is_file()}
        result = invoke(server, workspace_path=str(installed.home), task_key='private-task-marker')
        assert_rejected(result, reason='WORKSPACE_OUTSIDE_ALLOWED_ROOT', stage='RESOLVING_ROOT',
                        detail='WORKSPACE_OUTSIDE_ALLOWED_ROOT')
        assert '不在允许的项目边界内' in message(result)
        assert '连接' not in message(result) and '配置' not in message(result)
        encoded = result.model_dump_json()
        assert str(installed.home) not in encoded and 'private-task-marker' not in encoded
        assert not pool.children and not pool.sessions and not pool.jobs
        assert before == {p: p.read_bytes() for p in installed.home.iterdir() if p.is_file()}
    finally:
        pool.close()


@pytest.mark.parametrize('raw, reason, phrase', [
    ('INVALID_WORKSPACE_CLAIM', 'WORKSPACE_CANONICALIZATION_MISMATCH', '核对项目目录'),
    ('WORKSPACE_DIRECTORY_REQUIRED', 'WORKSPACE_CANONICALIZATION_MISMATCH', '核对项目目录'),
    ('Hook state/configuration links are not supported', 'WORKSPACE_LINK_REJECTED', '包含链接'),
    ('UNSAFE_WORKSPACE', 'WORKSPACE_OUTSIDE_ALLOWED_ROOT', '项目边界'),
    ('WORKSPACE_BOUNDARY_REJECTED', 'WORKSPACE_OUTSIDE_ALLOWED_ROOT', '项目边界'),
    ('private-path-and-source-marker', 'WORKSPACE_RESOLUTION_FAILED', '是否存在且可访问'),
])
def test_begin_admission_uses_fixed_workspace_rejection_mapping(installed, tmp_path, monkeypatch,
                                                               raw, reason, phrase):
    pool = pool_fixture(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    def reject(_):
        raise ValueError(raw)
    monkeypatch.setattr(pool, 'root', reject)
    try:
        result = invoke(server, workspace_path=str(tmp_path / 'private-input-marker'),
                        task_key='private-reference-marker')
        assert_rejected(result, reason=reason, stage='RESOLVING_ROOT', detail=reason)
        assert phrase in message(result)
        assert 'private-' not in result.model_dump_json()
        assert not pool.children and not pool.jobs
    finally:
        pool.close()


def test_missing_workspace_preserves_existing_reason(installed, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    try:
        result = invoke(create_global_server(workspaces=pool), task_key='private-task-marker')
        assert_rejected(result, reason='WORKSPACE_CLAIM_REQUIRED', stage='RESOLVING_ROOT',
                        detail='WORKSPACE_RESOLUTION_FAILED')
        assert '缺少明确的项目工作区目录' in message(result)
        assert not pool.children and not pool.jobs
    finally:
        pool.close()


def test_ordinary_configuration_error_preserves_recovery(installed, projects, tmp_path, monkeypatch):
    pool = pool_fixture(installed, tmp_path)
    code = 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR'
    recovery = {'message': '请先核对已保留的旧项目接入。', 'question': '是否备份并迁移旧接入？'}
    def reject(_):
        raise IntegrationDiagnostic(code)
    monkeypatch.setattr(pool, 'validate_layers', reject)
    monkeypatch.setattr('security_runtime.integration_recovery.configuration_recovery',
                        lambda *args, **kwargs: dict(recovery))
    try:
        result = invoke(create_global_server(workspaces=pool), workspace_path=str(projects[0]),
                        task_key='private-task-marker')
        data = assert_rejected(result, reason=code, stage='VALIDATING_CONFIGURATION', detail=code)
        assert data['configuration_recovery'] == recovery
        assert recovery['message'] in message(result) and recovery['question'] in message(result)
        assert not pool.children and not pool.jobs
        assert str(projects[0]) not in result.model_dump_json()
    finally:
        pool.close()


@pytest.mark.parametrize('kind', [RuntimeError, ValueError])
@pytest.mark.parametrize('raw', ['private-handler-path-reference-marker', 'WORKSPACE_OUTSIDE_ALLOWED_ROOT'])
def test_child_exception_is_not_reclassified_as_admission(installed, projects, tmp_path, monkeypatch,
                                                          kind, raw):
    pool, ledgers = task_pool(installed, tmp_path)
    root = projects[0]
    child, _ = pool.admit(root)
    def reject(*args, **kwargs):
        raise kind(raw)
    monkeypatch.setattr(child._tool_manager, 'get_tool', reject)
    try:
        result = invoke(create_global_server(workspaces=pool), workspace_path=str(root),
                        task_key='private-task-marker')
        assert_rejected(result, reason='WORKSPACE_OR_REFERENCE_REJECTED', stage='FORWARDING_TOOL',
                        detail='WORKSPACE_TOOL_REJECTED')
        assert '项目边界' not in message(result)
        assert 'private-' not in result.model_dump_json()
        assert not ledgers[root].calls and not pool.jobs
    finally:
        pool.close()


def test_bad_task_reference_preserves_child_protocol(installed, projects, tmp_path):
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        result = invoke(server, 'finish_security_task', workspace_path=str(root),
                        task_ref='private-invalid-task-reference')
        assert_rejected(result, reason='WORKSPACE_OR_REFERENCE_REJECTED', stage='FORWARDING_TOOL',
                        detail='WORKSPACE_TOOL_REJECTED')
        assert 'private-invalid-task-reference' not in result.model_dump_json()
        assert not ledgers[root].calls and not pool.jobs
    finally:
        pool.close()


def test_managed_worktree_reaches_task_begin_and_no_change_finish(installed, projects, tmp_path):
    pool, ledgers = task_pool(installed, tmp_path)
    root = linked_worktree(projects[0], installed.home / 'worktrees' / 'managed-id' / 'project')
    server = create_global_server(workspaces=pool)
    try:
        assert pool.root(root / 'src') == root
        assert installed.project_layers(root / 'src')
        assert not any(row['related'] for row in installed.inspect_project(root / 'src'))
        begun = structured(invoke(server, workspace_path=str(root / 'src'), task_key='managed-development'))
        assert begun['status'] == 'ACTIVE' and begun['scanner_run'] is False
        assert root in pool.children and not pool.jobs
        finished = structured(invoke(server, 'finish_security_task', workspace_path=str(root),
                                     task_ref=begun['task_ref']))
        assert finished['status'] == 'NO_CHANGES' and finished['scanner_run'] is False
        assert finished['development_summary'] == ''
        assert not ledgers[root].calls
    finally:
        pool.close()


def test_cursor_home_does_not_gain_codex_worktree_exception(projects, tmp_path):
    home = tmp_path / 'cursor-home'
    root = linked_worktree(projects[0], home / 'worktrees' / 'managed-id' / 'project')
    pool = GlobalWorkspaces(base=tmp_path / 'state' / 'cursor-workspaces',
                            integration=SimpleNamespace(home=home), host='cursor')
    try:
        with pytest.raises(ValueError, match='RUNTIME_STATE_IS_NOT_A_WORKSPACE'):
            pool.root(root)
        assert not pool.children and not pool.jobs
    finally:
        pool.close()

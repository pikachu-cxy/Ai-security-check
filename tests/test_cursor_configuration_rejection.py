"""Cursor preflight failures retain bounded causes without admitting workspaces."""
import asyncio
import json

import pytest

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import workspace_rejection
from test_cursor_automatic import integration


@pytest.mark.parametrize('error,reason,action', [
    (ValueError('CONFIGURATION_BUSY'), 'CONFIGURATION_BUSY', 'RETRY_CONFIGURATION_VALIDATION'),
    (ValueError('UNOWNED_RUNTIME_MCP'), 'UNOWNED_RUNTIME_MCP', 'CHECK_INTEGRATION_CONFIGURATION'),
    (ValueError('UNOWNED_RUNTIME_HOOK'), 'UNOWNED_RUNTIME_HOOK', 'CHECK_INTEGRATION_CONFIGURATION'),
    (ValueError('DUPLICATE_REVIEW_SKILL'), 'DUPLICATE_REVIEW_SKILL', 'CHECK_INTEGRATION_CONFIGURATION'),
    (ValueError('CURSOR_PERMISSIONS_INVALID'), 'CURSOR_PERMISSIONS_INVALID', 'CHECK_INTEGRATION_CONFIGURATION'),
    (PermissionError('private-path secret'), 'WORKSPACE_CONFIGURATION_ACCESS_DENIED', 'CHECK_CONFIGURATION_ACCESS'),
    (ValueError('private-path secret'), 'WORKSPACE_CONFIGURATION_REJECTED', 'CHECK_INTEGRATION_CONFIGURATION'),
])
def test_cursor_configuration_failure_and_recovery(integration, tmp_path, monkeypatch, error, reason, action):
    integration.execute('setup')
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'pyproject.toml').write_text('[project]\nname="demo"\n')
    pool = GlobalWorkspaces(host='cursor', integration=integration, base=tmp_path/'workspaces')
    server = create_global_server(workspaces=pool)
    original = integration.configuration_status

    def fail():
        raise error

    monkeypatch.setattr(integration, 'configuration_status', fail)
    try:
        status = asyncio.run(server.call_tool('get_workspace_binding_status',
            {'workspace_path': str(root)})).structuredContent
        assert status['path_status'] == 'ALLOWED'
        assert status['configuration_status'] == 'REJECTED'
        assert status['reason_code'] == reason
        assert status['next_action'] == action
        result = asyncio.run(server.call_tool('begin_development_check',
            {'workspace_path': str(root), 'task_key': 'cursor-preflight'}))
        assert result.isError
        assert result.structuredContent['reason_code'] == reason
        assert not result.structuredContent['scanner_run']
        assert 'private-path secret' not in str(result)
        assert not pool.children and not pool.sessions and not pool.base.exists()
        monkeypatch.setattr(integration, 'configuration_status', original)
        recovered = asyncio.run(server.call_tool('get_workspace_binding_status',
            {'workspace_path': str(root)})).structuredContent
        assert recovered['configuration_status'] == 'VALIDATED'
        assert recovered['admission_status'] == 'ELIGIBLE'
        assert not pool.children and not pool.base.exists()
    finally:
        pool.close()


def test_permission_error_is_configuration_specific():
    assert workspace_rejection(PermissionError('private'), 'RESOLVING_ROOT') == 'WORKSPACE_RESOLUTION_FAILED'


def test_running_cursor_survives_newer_signed_permission_record(integration, tmp_path, monkeypatch):
    from security_runtime import cursor_permissions
    from security_runtime.workspace_binding_status import inspect_binding
    integration.execute('setup')
    root = tmp_path/'project'
    root.mkdir()
    (root/'pyproject.toml').write_text('[project]\nname="demo"\n')
    pool = GlobalWorkspaces(host='cursor', integration=integration, base=tmp_path/'workspaces')
    files = [integration.permissions().path, integration.permissions().manifest]
    before = [p.read_bytes() for p in files]
    # Reproduce an already-running process whose catalog predates the two
    # diagnostics added by another process's permission repair.
    old = tuple('ai-security-runtime:'+t for t in cursor_permissions.ROUTINE_TOOLS)
    monkeypatch.setattr(cursor_permissions, 'ENTRIES', old)
    try:
        status = integration.configuration_status()
        assert status['overall'] == 'CONFIGURED'
        assert status['routine_tool_approval']['ownership_compatibility'] == 'NEWER_SIGNED_RECORD'
        assert status['routine_tool_approval']['restart_required']
        assert inspect_binding(pool, str(root))['configuration_status'] == 'VALIDATED'
        for action in ('repair', 'remove'):
            with pytest.raises(ValueError, match='CURSOR_PERMISSION_OWNERSHIP_INVALID'):
                integration.permissions().execute(action)
        assert [p.read_bytes() for p in files] == before
        # Compatibility must not accept a record with a forged signature.
        signed = json.loads(files[1].read_bytes())
        signed['signature'] = '0'*64
        files[1].write_text(json.dumps(signed))
        with pytest.raises(ValueError, match='CURSOR_PERMISSION_OWNERSHIP_INVALID'):
            integration.permissions().status()
    finally:
        pool.close()


def test_text_only_advisory_contains_safe_reason():
    from security_runtime.global_mcp import _advisory
    reason = 'CURSOR_PERMISSION_OWNERSHIP_INVALID'
    result = _advisory(reason)
    text = json.loads(result.content[0].text)
    assert text['continue'] is True
    assert text['diagnostic']['reason_code'] == result.structuredContent['reason_code'] == reason
    assert not text['diagnostic']['scanner_run']
    assert 'private-path secret' not in _advisory('private-path secret').content[0].text

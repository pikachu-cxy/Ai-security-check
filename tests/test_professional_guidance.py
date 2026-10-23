"""Guide delivery is global read-only data, never repair authority or a remote Skill claim."""
import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from security_runtime.professional_guidance import get_professional_guidance, delivery_contract, MAX_BYTES
from security_runtime.mcp_server import create_server
from security_runtime.global_mcp import create_global_server, GlobalWorkspaces
from security_runtime.guidance.host_guidance import runtime_info
from test_global_integration import installed, projects


@pytest.fixture(autouse=True)
def isolated_guidance_environment(tmp_path, monkeypatch):
    import os
    from security_runtime.trial import isolated_environment
    for name in list(os.environ):
        if name.upper().startswith('SECURITY_RUNTIME_') or name == 'CODEX_HOME':
            monkeypatch.delenv(name, raising=False)
    for name, value in isolated_environment(tmp_path, {}).items():
        monkeypatch.setenv(name, value)


def test_bundled_guide_has_actual_digest_and_fixed_authority():
    data = get_professional_guidance()
    assert data['status'] == 'READY' and data['source'] == 'BUNDLED'
    assert hashlib.sha256(data['content'].encode()).hexdigest() == data['content_sha256']
    assert len(data['content'].encode()) <= MAX_BYTES
    assert not any(data['execution'].values())
    assert data['authority']['guidance_is_not_authorization']
    assert data['authority']['user_consent_required_for_fixes']
    assert not data['authority']['target_execution_allowed']
    assert delivery_contract()['remote_status'] == 'RESERVED_NOT_CONFIGURED'
    assert not delivery_contract()['remote_fetch_implemented']
    assert runtime_info()['professional_guidance'] == delivery_contract()


@pytest.mark.parametrize('raw', [b'', b'\xff', b'bad\x00content', b'x' * (MAX_BYTES + 1), None],
    ids=['empty', 'invalid-utf8', 'nul', 'oversized', 'missing'])
def test_invalid_bundled_text_is_bounded_unavailable(tmp_path, monkeypatch, raw):
    import security_runtime.professional_guidance as module
    fake_module = tmp_path / 'professional_guidance.py'
    path = tmp_path / 'skills/ai-security-review/references/deep-audit.md'
    path.parent.mkdir(parents=True)
    if raw is not None:
        path.write_bytes(raw)
    monkeypatch.setattr(module, '__file__', str(fake_module))
    data = get_professional_guidance()
    assert data['status'] == 'UNAVAILABLE' and 'content' not in data
    assert not any(data['execution'].values())


def test_mcp_schema_rejects_arbitrary_remote_or_source_inputs():
    from pydantic import ValidationError
    server = create_server(global_mode=False)
    tool = server._tool_manager.get_tool('get_professional_guidance')
    assert tool.parameters['additionalProperties'] is False
    assert tool.annotations.readOnlyHint and tool.annotations.openWorldHint is False
    assert tool.fn()['status'] == 'READY'
    for key in ['url', 'workspace_path', 'source', 'approve']:
        with pytest.raises(ValidationError) as exc:
            tool.fn_metadata.arg_model.model_validate({key: 'private-untrusted-input'})
        assert 'private-untrusted-input' not in str(exc.value)


def test_global_guide_needs_no_workspace_binding_or_child(installed, tmp_path, monkeypatch):
    pool = GlobalWorkspaces(base=tmp_path / 'workspace-state', integration=installed)
    def unexpected(*args, **kwargs):
        pytest.fail('Guide reads must not admit workspaces or probe configuration')
    monkeypatch.setattr(pool, 'admit', unexpected)
    monkeypatch.setattr(installed, 'configuration_status', unexpected)
    try:
        server = create_global_server(workspaces=pool)
        listed = {t.name: t for t in asyncio.run(server.list_tools())}
        schema = listed['get_professional_guidance'].inputSchema
        assert 'workspace_path' not in schema.get('properties', {})
        assert schema['additionalProperties'] is False
        result = asyncio.run(server.call_tool('get_professional_guidance', {}))
        assert result.structuredContent['status'] == 'READY'
        rejected = asyncio.run(server.call_tool('get_professional_guidance', {'url': 'PRIVATE'}))
        assert 'PRIVATE' not in rejected.model_dump_json()
        assert not pool.children and not pool.jobs and not pool.base.exists()
        assert not installed.home.exists()
    finally:
        pool.close()

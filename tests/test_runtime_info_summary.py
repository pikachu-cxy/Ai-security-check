"""Summary retains capability decisions while full discovery stays compatible."""
import copy
import json
import asyncio

import pytest

from security_runtime.compatibility import task_review_compatibility
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_server import create_server
from security_runtime.runtime_info_view import runtime_info_view
from security_runtime.global_mcp import create_global_server
from test_global_integration import structured


def test_real_summary_preserves_checks_and_reduces_response(monkeypatch, tmp_path):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'absent'))
    registry = MCPRegistry(create_server(global_mode=False))
    full = registry.tool('get_runtime_info').fn()
    before = copy.deepcopy(full)
    summary = registry.tool('get_runtime_info').fn(view='summary')
    assert runtime_info_view(full) is full and full == before
    assert task_review_compatibility(summary, registry.names()) == task_review_compatibility(full, registry.names())
    for key in ('build_identity', 'guidance_catalog', 'features', 'required_guidance_tools',
                'connection_recovery', 'same_environment_check', 'execution'):
        assert summary[key] == full[key]
    assert summary['delivery_manifest']['manifest_sha256'] == full['delivery_manifest']['manifest_sha256']
    assert summary['delivery_manifest']['compatibility'] == full['delivery_manifest']['compatibility']
    assert summary['delivery_manifest']['tools']['names'] == full['delivery_manifest']['tools']['names']
    assert len(json.dumps(summary)) < len(json.dumps(full)) * .65
    assert not (tmp_path / 'absent').exists()


def test_summary_is_read_only_on_both_routes_and_full_stays_default(monkeypatch, tmp_path):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'absent'))
    registry = MCPRegistry(create_server(global_mode=False))
    routed = create_global_server(workspaces=object())
    before = list(tmp_path.rglob('*'))
    for route in (lambda args: structured(asyncio.run(registry.dispatch('get_runtime_info', args, convert_result=True))),
                  lambda args: asyncio.run(routed.call_tool('get_runtime_info', args)).structuredContent):
        full = route({})
        assert route({'view': 'full'}) == full
        summary = route({'view': 'summary'})
        assert summary == runtime_info_view(full, 'summary')
        assert task_review_compatibility(summary, registry.names()) == task_review_compatibility(full, registry.names())
    assert list(tmp_path.rglob('*')) == before
    tools = {tool.name: tool for tool in asyncio.run(routed.list_tools())}
    assert tools['get_runtime_info'].inputSchema['properties']['view']['enum'] == ['full', 'summary']


@pytest.mark.parametrize('view', ['unknown', None, True])
def test_invalid_view_does_not_silently_change_contract(view):
    with pytest.raises(ValueError):
        runtime_info_view({}, view)

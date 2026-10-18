"""Fixed bundled methods stay read only across both public MCP routes."""
import asyncio

import pytest

from security_runtime.compatibility import storage_contracts
from security_runtime.guidance_catalog import TOPICS, get_runtime_guidance
from security_runtime.global_mcp import create_global_server
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_server import create_server
from test_global_integration import structured


@pytest.mark.parametrize('topic', TOPICS)
def test_guidance_routes_share_bundled_identity_without_workspace_admission(topic, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'private'))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    local=create_server(global_mode=False)
    routed=create_global_server(workspaces=object())
    before=list(tmp_path.rglob('*'))
    original=get_runtime_guidance(topic)
    project=asyncio.run(MCPRegistry(local).dispatch('get_runtime_guidance', {'topic':topic}, convert_result=True))
    global_result=asyncio.run(routed.call_tool('get_runtime_guidance', {'topic':topic}))
    assert structured(project)==global_result.structuredContent==original
    assert list(tmp_path.rglob('*'))==before
    tools={tool.name:tool for tool in asyncio.run(routed.list_tools())}
    tool=tools['get_runtime_guidance']
    assert set(tool.inputSchema['properties'])=={'topic'}
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False and tool.annotations.openWorldHint is False
    assert not any(original['execution'].values())


@pytest.mark.parametrize('arguments', [None, {}, {'topic':None}, {'topic':True},
    {'topic':'../../private-token'}, {'topic':'https://private.invalid/token'},
    {'topic':'task-review-v2'}, {'topic':'core','workspace_path':'C:/private-token'},
    {'topic':['core']}, {'topic':'core','session_ref':'private-token'}])
def test_guidance_raw_rejection_is_identical_bounded_and_does_not_echo_input(arguments, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'private'))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    local=create_server(global_mode=False)
    routed=create_global_server(workspaces=object())
    before=list(tmp_path.rglob('*'))
    project=asyncio.run(MCPRegistry(local).dispatch('get_runtime_guidance', arguments, convert_result=True))
    global_result=asyncio.run(routed.call_tool('get_runtime_guidance', arguments))
    result=global_result.structuredContent
    assert structured(project)==result
    assert result['reason_code']=='GUIDANCE_INPUT_INVALID'
    assert not result['scanner_run'] and not result['source_modified'] and not result['repair_authorized']
    assert 'private-token' not in str(result) and 'private.invalid' not in str(result)
    assert list(tmp_path.rglob('*'))==before


def test_runtime_manifest_declares_real_storage_formats_without_granting_authority(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'private'))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    local=create_server(global_mode=False)
    info=MCPRegistry(local).tool('get_runtime_info').fn()
    manifest=info['delivery_manifest']
    assert manifest['compatibility']['storage_contracts']==storage_contracts()
    assert 'task-risk-authority-v2' in storage_contracts()
    assert 'closure-authority-v2' in storage_contracts()
    assert info['build_identity']['state_schema']=='runtime-state-v1'
    assert manifest['security_proof'] is False and manifest['repair_authorized'] is False
    assert not (tmp_path/'private').exists()

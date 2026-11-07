"""Compact discovery must preserve operation schemas, routing and compatibility."""
import asyncio
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from jsonschema import Draft202012Validator

from security_runtime.codex_integration import REQUIRED_TOOLS, check_capabilities
from security_runtime.global_mcp import create_global_server, global_runtime_info
from security_runtime.mcp_tool_groups import GROUPS, available_operations, operation_schemas
from security_runtime.integration_lifecycle import IntegrationDiagnostic
import pytest


@pytest.mark.parametrize('usage_monitor', ['0', '1'])
def test_compact_discovery_keeps_required_contract_and_precise_schemas(tmp_path, monkeypatch, usage_monitor):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED', usage_monitor)
    server = create_global_server()
    try:
        tools = asyncio.run(server.list_tools())
        by_name = {tool.name: tool for tool in tools}
        info = global_runtime_info(tools=tools, host='codex')
        assert REQUIRED_TOOLS <= available_operations(info, by_name)
        assert set(info['required_guidance_tools']) <= by_name.keys()
        assert check_capabilities(info, set(by_name))['status'] == 'OK'
        with pytest.raises(IntegrationDiagnostic, match='CAPABILITY_MISMATCH'):
            check_capabilities(info, set(by_name) - {'task_review'})
        assert set(GROUPS) <= by_name.keys()
        assert not {'finding_feedback', 'repair_impact', 'closeout_check'} & by_name.keys()
        assert not {name for names in GROUPS.values() for name in names} & by_name.keys()
        assert len(tools) <= 20
        assert len(tools) == 15 + ('start_usage_monitor' in by_name)
        from security_runtime.tasks.ownership import session_context
        monkeypatch.setattr('security_runtime.user_config.describe_config', lambda: {
            'values': {'development': {'stop_fallback': {'enabled': True}}}})
        handoff = session_context('session-test', native_stop=True, workspace=tmp_path, grouped_codex=True)
        tool, payload = handoff.split('await tools.mcp__ai_security_runtime__', 1)[1].split('(', 1)
        request, _ = json.JSONDecoder().raw_decode(payload)
        assert request == {'operation': 'get_development_risks', 'arguments': {
            'workspace_path': str(tmp_path), 'session_ref': 'session-test',
            'check_ref': '<检查编号>', 'view': 'review'}}
        Draft202012Validator(by_name[tool].inputSchema).validate(request)
        for field in ('加粗漏洞名', '评级及来源', '实际风险文件链接及行号', '“问题”', '“可能影响”', '“建议修复”', '“尚未确认”', '不得合并或省略', '原样附上', '不重写'):
            assert field in handoff
        assert 'expected_seq=本次 dirty_seq' in handoff and 'return_risks=true' in handoff
        assert set(operation_schemas(tools)) == set(by_name) | {tool.name for tool in server._tool_manager.list_tools()}
        for tool in tools:
            Draft202012Validator.check_schema(tool.inputSchema)
        schema = by_name['scan'].inputSchema
        Draft202012Validator.check_schema(schema)
        valid = {'operation': 'scan_files', 'arguments': {'workspace_path': str(tmp_path), 'files': ['a.py']}}
        validator = Draft202012Validator(schema)
        assert validator.is_valid(valid)
        assert not validator.is_valid(dict(valid, arguments={'files': ['a.py']}))
        assert not validator.is_valid(dict(valid, arguments={'workspace_path': str(tmp_path), 'files': 'a.py'}))
        assert not validator.is_valid(dict(valid, operation='scan_project'))
        assert by_name['runtime_status'].annotations.readOnlyHint
        assert not by_name['scan'].annotations.readOnlyHint
        review_schema = by_name['development_review'].inputSchema
        submit_schema = next(branch['properties']['arguments'] for branch in review_schema['oneOf']
            if branch['properties']['operation']['const'] == 'submit_development_review')
        assert 'expected_seq' in submit_schema['required']
        business = submit_schema['properties']['business_reviews']['anyOf'][0]['items']
        assert business['properties']['limitations']['type'] == 'array'
        assert business['properties']['limitations']['items']['type'] == 'string'
    finally:
        server.global_workspaces.close()


def test_group_dispatch_keeps_workspace_and_original_validation(tmp_path, monkeypatch):
    from mcp.server.fastmcp import FastMCP
    child = FastMCP('fixture')
    calls = []

    @child.tool()
    def scan_files(files: list[str], workspace_path: str, summary: bool = True) -> dict:
        calls.append((files, workspace_path, summary))
        return {'status': 'fixture', 'files': files}

    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    admitted = []
    pool = SimpleNamespace(host='codex', task_audit_mode=True, root=lambda path, **kw: Path(path),
        validate_layers=lambda path: None,
        admit=lambda root: (admitted.append(root) or child, None), close=lambda: None)
    server = create_global_server(workspaces=pool)

    async def run():
        arguments = {'workspace_path': str(tmp_path), 'files': ['selected.py'], 'summary': False}
        direct = await server.call_tool('scan_files', arguments)
        grouped = await server.call_tool('scan', {'operation': 'scan_files', 'arguments': arguments})
        assert direct == grouped, direct
        assert calls == [(['selected.py'], str(tmp_path), False)] * 2
        rejected = await server.call_tool('scan', {'operation': 'scan_files', 'arguments': {**arguments, 'owner': 'other'}})
        assert rejected.structuredContent['scanner_run'] is False and len(admitted) == 2
        # Hidden aliases still use the original strict router too.
        direct_rejection = await server.call_tool('scan_files', {**arguments, 'owner': 'other'})
        assert rejected == direct_rejection
        # The hidden old group accepts its own operations only.
        args = {'workspace_path': str(tmp_path), 'unexpected': True}
        old = await server.call_tool('closeout_check', {'operation': 'get_closeout_status', 'arguments': args})
        new = await server.call_tool('scan', {'operation': 'get_closeout_status', 'arguments': args})
        assert old == new
        denied = await server.call_tool('closeout_check', {'operation': 'scan_files', 'arguments': arguments})
        assert denied.isError
        assert len(calls) == 2
    asyncio.run(run())


def test_grouped_tools_over_real_stdio(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    source = str(Path(__file__).resolve().parents[1] / 'src')
    env = dict(os.environ, PYTHONPATH=source, SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'),
               SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_CONTEXT_MONITOR='0')
    env.pop('__PYVENV_LAUNCHER__', None)
    params = StdioServerParameters(command=sys.executable,
        args=['-c', 'from security_runtime.global_mcp import create_global_server; create_global_server().run()'], env=env)

    async def run():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                init = await client.initialize()
                assert 'Compact global tool routing' in init.instructions
                tools = await client.list_tools()
                assert len(tools.tools) <= 20
                info = await client.call_tool('get_runtime_info', {'view': 'summary'})
                assert not info.isError
                assert check_capabilities(info.structuredContent, {tool.name for tool in tools.tools})['status'] == 'OK'
                assert 'runtime_status' in {tool.name for tool in tools.tools}
                direct = await client.call_tool('get_development_config', {})
                grouped = await client.call_tool('runtime_status', {'operation': 'get_development_config', 'arguments': {}})
                assert not grouped.isError and direct.structuredContent == grouped.structuredContent
                guidance = {'topic': 'core'}
                grouped = await client.call_tool('runtime_status', {'operation': 'get_runtime_guidance', 'arguments': guidance})
                direct = await client.call_tool('get_runtime_guidance', guidance)
                assert not grouped.isError and grouped.structuredContent == direct.structuredContent
                rejected = await client.call_tool('runtime_status', {'operation': 'scan_project', 'arguments': {}})
                assert rejected.isError
    asyncio.run(run())


@pytest.mark.parametrize('host', ['codex', 'workbuddy'])
def test_review_parameter_error_is_actionable_before_workspace_admission(tmp_path, monkeypatch, host):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    def forbidden(*args, **kwargs):
        pytest.fail('Invalid input must not open a workspace or save a review')
    pool = SimpleNamespace(host=host, task_audit_mode=True, root=forbidden, close=lambda: None)
    server = create_global_server(workspaces=pool)
    async def run():
        arguments = dict(check_ref='fixture', workspace_path=str(tmp_path), observations=[],
            business_reviews=[dict(file_path='a.py', rationale='reviewed', evidence_refs=[],
                                   limitations='PRIVATE_INPUT')])
        result = await server.call_tool('development_review',
            dict(operation='submit_development_review', arguments=arguments))
        content = result.structuredContent
        assert content['reason_code'] == 'DEVELOPMENT_REVIEW_INPUT_INVALID'
        assert content['review_saved'] is False
        assert {e['field'] for e in content['field_errors']} == {
            'expected_seq', 'business_reviews[0].limitations'}
        assert 'PRIVATE_INPUT' not in str(content)
        assert content == (await server.call_tool('submit_development_review', arguments)).structuredContent
    asyncio.run(run())


def test_installer_probe_accepts_compact_global_connection(tmp_path):
    from security_runtime.codex_integration import probe_runtime
    source = str(Path(__file__).resolve().parents[1] / 'src')
    home = tmp_path / 'codex-home'
    env = dict(os.environ, PYTHONPATH=source, SECURITY_RUNTIME_GLOBAL='1',
        SECURITY_RUNTIME_CODEX_HOME=str(home), SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'),
        SECURITY_RUNTIME_CONFIG=str(tmp_path / 'config.toml'), SECURITY_RUNTIME_CONTEXT_MONITOR='0')
    env.pop('__PYVENV_LAUNCHER__', None)
    result = probe_runtime({'command': sys.executable, 'prefix': ['-m', 'security_runtime.cli'],
                           'kind': 'PYTHON_VENV'}, home, env)
    assert result['status'] == 'OK'
    assert not home.exists()

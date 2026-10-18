"""Real global routing with inert scan handlers: request rejection never scans."""
import asyncio
import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import WorkspaceClaimError, workspace_rejection
from test_global_integration import projects, structured


@pytest.fixture
def routed(projects, tmp_path):
    calls = []

    def child(root, directory, binding):
        server = FastMCP('inert scan contract fixture')

        @server.tool()
        def scan_project(workspace_path: str | None = None, path: str | None = None,
                         summary: bool = False) -> dict:
            calls.append(('scan_project', workspace_path, path, summary))
            return {'status': 'ROUTED', 'workspace': workspace_path}

        @server.tool()
        def scan_diff(workspace_path: str | None = None, mode: str = 'quick',
                      path: str | None = None, summary: bool = False) -> dict:
            calls.append(('scan_diff', workspace_path, path, summary, mode))
            return {'status': 'ROUTED', 'workspace': workspace_path}

        return server, object()

    integration = SimpleNamespace(home=tmp_path / 'codex-home',
        configuration_status=lambda: {'overall': 'CONFIGURED'}, inspect_project=lambda root: [])
    pool = GlobalWorkspaces(base=tmp_path / 'state' / 'contract-workspaces',
                            integration=integration, child_factory=child)
    try:
        yield create_global_server(workspaces=pool), pool, calls
    finally:
        pool.close()


def invoke(server, name, arguments):
    return structured(asyncio.run(server.call_tool(name, arguments)))


@pytest.mark.parametrize('tool', ['scan_project', 'scan_diff'])
@pytest.mark.parametrize('file_argument', ['alias', 'workspace', 'both'])
def test_file_is_rejected_before_workspace_admission(routed, projects, tool, file_argument):
    server, pool, calls = routed
    file = projects[0] / 'demo.ts'
    file.write_text("export const demoToken = '';\n", encoding='utf-8')
    args = {'workspace_path': str(projects[0])}
    if file_argument in {'workspace', 'both'}:
        args['workspace_path'] = str(file)
    if file_argument in {'alias', 'both'}:
        args['path'] = str(file)
    out = invoke(server, tool, args)
    assert out['reason_code'] == 'WORKSPACE_DIRECTORY_REQUIRED'
    assert out['scanner_run'] is False and out['source_modified'] is False
    assert out['security_proof'] is False and out['coverage'] == 'UNKNOWN'
    assert 'path 只是项目目录的旧参数别名' in out['message']
    assert '不支持单文件扫描' in out['message']
    assert str(file) not in json.dumps(out)
    # A bad argument is not a broken preparation/connection diagnosis.
    assert 'workspace_readiness' not in out
    assert not calls and not pool.children and not pool.jobs


@pytest.mark.parametrize('tool', ['scan_project', 'scan_diff'])
def test_foreign_workspace_alias_cannot_change_scan_scope(routed, projects, tool):
    server, pool, calls = routed
    out = invoke(server, tool, {'workspace_path': str(projects[0]), 'path': str(projects[1])})
    assert out['reason_code'] == 'WORKSPACE_ALIAS_MISMATCH'
    assert out['scanner_run'] is False and out['security_proof'] is False
    assert '不同项目' in out['message']
    assert str(projects[0]) not in json.dumps(out) and str(projects[1]) not in json.dumps(out)
    assert not calls and not pool.children and not pool.jobs


@pytest.mark.parametrize('tool', ['scan_project', 'scan_diff'])
def test_link_alias_is_rejected_before_scan(routed, projects, tmp_path, tool):
    server, pool, calls = routed
    link = tmp_path / 'linked-project'
    if os.name == 'nt':
        subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(link), str(projects[0])],
                       check=True, capture_output=True)
    else:
        link.symlink_to(projects[0], target_is_directory=True)
    out = invoke(server, tool, {'workspace_path': str(projects[0]), 'path': str(link)})
    assert out['scanner_run'] is False and out['security_proof'] is False
    assert str(link) not in json.dumps(out)
    assert not calls and not pool.children and not pool.jobs


@pytest.mark.parametrize('tool', ['scan_project', 'scan_diff'])
@pytest.mark.parametrize('alias', [None, 'same', 'subdirectory'])
def test_directory_routing_keeps_normal_and_legacy_contract(routed, projects, tool, alias):
    server, pool, calls = routed
    args = {'workspace_path': str(projects[0]), 'summary': True}
    if alias:
        args['path'] = str(projects[0] if alias == 'same' else projects[0] / 'src')
    if tool == 'scan_diff':
        args['mode'] = 'feature'
    out = invoke(server, tool, args)
    assert out == {'status': 'ROUTED', 'workspace': str(projects[0])}
    assert calls == [(tool, str(projects[0]), None, True, *(['feature'] if tool == 'scan_diff' else []))]
    assert set(pool.children) == {projects[0]} and not pool.jobs


def test_scan_tool_discovery_explains_directory_alias(routed):
    server, _, _ = routed
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    for name in ('scan_project', 'scan_diff'):
        tool = tools[name]
        properties = tool.inputSchema['properties']
        assert 'Absolute project directory' in properties['workspace_path']['description']
        assert 'Legacy alias of workspace_path' in properties['path']['description']
        assert 'Single-file scans are not supported' in properties['path']['description']
        assert 'legacy directory alias' in tool.description
        assert 'workspace_path' in tool.inputSchema['required']


def test_directory_diagnostic_is_preserved():
    exc = WorkspaceClaimError('WORKSPACE_DIRECTORY_REQUIRED')
    assert exc.code == 'WORKSPACE_DIRECTORY_REQUIRED'
    assert workspace_rejection(exc, 'RESOLVING_ROOT') == 'WORKSPACE_DIRECTORY_REQUIRED'


"""Exercise the acceptance's personal contract over real MCP stdio transport."""
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import runpy
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('internal_opt_in', [False, True])
def test_personal_acceptance_rejects_internal_tool_exposure(tmp_path, monkeypatch, internal_opt_in):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts'))
    contract = runpy.run_path(str(ROOT / 'scripts/codex_integration_acceptance.py'))['assert_personal_tool_contract']
    # Explicit embedding is isolated to this test process; no CLI flag or
    # environment switch restores the hidden personal entrypoints.
    bootstrap = (
        f'import sys; sys.path.insert(0, {str(ROOT / "src")!r}); '
        'from security_runtime.mcp_server import create_server; '
        f'create_server(include_functional_verification={internal_opt_in!r}).run(transport="stdio")'
    )
    env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'),
               SECURITY_RUNTIME_DATA_DIR=str(tmp_path / 'data'), SECURITY_RUNTIME_OFFLINE='1',
               PYTHONUTF8='1')
    for name in ('SECURITY_RUNTIME_WORKSPACE', 'SECURITY_RUNTIME_GLOBAL'):
        env.pop(name, None)
    params = StdioServerParameters(command=sys.executable, args=['-c', bootstrap], cwd=tmp_path, env=env)

    async def run():
        with (tmp_path / 'mcp-stderr.log').open('w', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=30)) as client:
                    await client.initialize()
                    if internal_opt_in:
                        with pytest.raises(AssertionError):
                            await contract(client)
                        # Internal compatibility remains available, but opting in
                        # alone cannot create a verified repair or execution grant.
                        response = await client.call_tool('prepare_functional_verification', {
                            'remediation_ref': 'missing', 'task_ref': 'missing',
                            'workspace_path': str(tmp_path)})
                        assert not response.isError
                        data = response.structuredContent or json.loads(response.content[0].text)
                        data = data.get('result', data)
                        assert data['overall_status'] == 'SECURITY_NOT_VERIFIED'
                        assert not data.get('functional_ref') and not data.get('handoff')
                    else:
                        await contract(client)
                        response = await client.call_tool('prepare_functional_verification', {
                            'remediation_ref': 'missing', 'task_ref': 'missing'})
                        assert response.isError
                    info = await client.call_tool('get_runtime_info', {})
                    assert not info.isError
                    data = info.structuredContent or json.loads(info.content[0].text)
                    features = data.get('result', data)['features']
                    assert ('functional_verification' in features) is internal_opt_in

    asyncio.run(run())

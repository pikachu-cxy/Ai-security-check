"""Bound product tools retain their event observation after handler extraction."""
import asyncio
from types import SimpleNamespace

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from test_global_integration import structured


@pytest.mark.parametrize('name', ['generate_fix','verify'])
def test_bound_repair_tools_return_result_and_observe_exact_workspace(name,tmp_path,monkeypatch):
    root=tmp_path/'project';root.mkdir();(root/'app.py').write_text('value=1\n')
    runtime=SecurityRuntime(ScannerRegistry([]),SQLiteStore(tmp_path/'private/scans.db'))
    monkeypatch.setattr(runtime.store,'get_finding',lambda _:({}, {'target_profile':{'path':str(root)}}))
    expected={'status':'VERIFIED' if name=='verify' else 'PROPOSED','marker':'retained'}
    calls=[];events=[]
    monkeypatch.setattr(runtime,'generate_fix',lambda fid: calls.append((fid,)) or expected)
    monkeypatch.setattr(runtime,'verify',lambda fid,workspace: calls.append((fid,workspace)) or expected)
    monkeypatch.setattr('security_runtime.mcp_server.IntegrationStateStore',lambda:SimpleNamespace(event=events.append))
    monkeypatch.setenv('SECURITY_RUNTIME_MCP_SELF_TEST','0')
    binding=WorkspaceBinding('synthetic',str(root),str(root),'codex','PROJECT','')
    server=create_server(runtime,workspace_binding=binding,global_mode=False,
        hook_coordinator=HookCoordinator(runtime,HookStateStore(tmp_path/'private/hooks')))
    result=asyncio.run(MCPRegistry(server).dispatch(name,{'finding_id':'original'},convert_result=True))
    assert structured(result)==expected and len(calls)==1 and len(events)==1
    event=events[0]
    assert event.integration==binding.integration_id and str(event.workspace)==str(root)
    if name=='generate_fix':assert event.fix_generated is True
    else:assert event.verify_result=='VERIFIED' and calls[0]==('original',str(root))

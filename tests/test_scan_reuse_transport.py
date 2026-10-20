"""A real saved reusable scan survives MCP presentation and explicit rescans."""
import asyncio
import subprocess

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from test_global_integration import structured
from test_scan_reuse import engine, reusable  # noqa: F401


@pytest.fixture(autouse=True)
def isolated_transport_state(tmp_path,monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'transport-state'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)


def test_mcp_reuses_the_original_saved_scan_without_fabricating_publication(reusable,monkeypatch):
    runtime,root,_,_,_,calls,original,*_=reusable
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)
    hooks=HookStateStore(runtime.store.path.parent/'hooks')
    server=create_server(runtime,hook_coordinator=HookCoordinator(runtime,hooks),global_mode=False)
    assert 'execution_publication' not in runtime.store.get_scan(original.scan_id)['scanner_diagnostics']
    before=runtime.store.path.read_bytes()
    result=structured(asyncio.run(server.call_tool('scan_project',dict(workspace_path=str(root),summary=True))))
    assert result['scan_id']==original.scan_id and len(calls)==1
    assert result['execution']['result_reused'] and not result['execution']['scanner_run']
    assert not result['execution']['repair_authorized']
    assert result['result_reuse']['reused']
    assert result['execution_publication']['publication']!='COMMITTED'
    assert result['execution_publication'].get('current_task_proof') is not True
    assert result['timing']['scan_ms']==0 and result['timing']['historical_scan_ms']==original.duration_ms
    assert result['timing']['host_analysis_ms'] is None and result['timing']['conversation_total_ms'] is None
    assert runtime.store.path.read_bytes()==before

    # An explicit rescan still runs providers and publishes its own new result.
    rescanned=structured(asyncio.run(server.call_tool('scan_project',dict(
        workspace_path=str(root),summary=True,force_rescan=True))))
    assert rescanned['scan_id']!=original.scan_id and len(calls)==2
    assert rescanned['execution']['scanner_run'] and not rescanned['execution']['result_reused']
    assert rescanned['execution_publication']['publication']=='COMMITTED'
    assert rescanned['result_reuse']['reason_code']=='FORCE_RESCAN_REQUESTED'


def test_unbound_mcp_project_scan_uses_current_workspace_when_omitted(reusable,monkeypatch):
    runtime,root,_,_,_,calls,original,*_=reusable
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)
    monkeypatch.chdir(root)
    hooks=HookStateStore(runtime.store.path.parent/'hooks')
    server=create_server(runtime,hook_coordinator=HookCoordinator(runtime,hooks),global_mode=False)
    result=structured(asyncio.run(server.call_tool('scan_project',dict(summary=True))))
    assert result['scan_id']==original.scan_id and len(calls)==1
    assert result['execution']['result_reused']


@pytest.mark.parametrize('entry',['scan_diff','scan_project'])
def test_no_changes_or_supported_targets_never_claims_scanner_execution(reusable,monkeypatch,entry):
    runtime,root,path,_,_,calls,*_=reusable
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)
    if entry=='scan_diff':
        subprocess.run(['git','init','-q',str(root)],check=True)
        subprocess.run(['git','-C',str(root),'add','.'],check=True)
        subprocess.run(['git','-C',str(root),'-c','user.name=Fixture','-c',
            'user.email=fixture@example.invalid','commit','-qm','fixture'],check=True)
        arguments=dict(workspace_path=str(root),summary=True)
        expected='NO_CHANGES'
    else:
        path.unlink()
        (root/'image.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
        arguments=dict(workspace_path=str(root),summary=True,force_rescan=True)
        expected='NOT_APPLICABLE'
    hooks=HookStateStore(runtime.store.path.parent/'hooks')
    server=create_server(runtime,hook_coordinator=HookCoordinator(runtime,hooks),global_mode=False)
    result=structured(asyncio.run(server.call_tool(entry,arguments)))
    assert result['execution_state']==expected and len(calls)==1
    assert not result['execution']['scanner_run'] and not result['execution']['result_reused']


def test_failed_real_provider_execution_is_still_reported_as_executed(reusable,engine,monkeypatch):
    runtime,root,_,_,_,calls,_,secret,*_=reusable
    engine[-1]['mode']='failure'
    def fail(*args,**kwargs):
        raise RuntimeError('deterministic provider execution failure')
    monkeypatch.setattr(secret,'_scan',fail)
    hooks=HookStateStore(runtime.store.path.parent/'hooks')
    server=create_server(runtime,hook_coordinator=HookCoordinator(runtime,hooks),global_mode=False)
    result=structured(asyncio.run(server.call_tool('scan_project',dict(
        workspace_path=str(root),summary=True,force_rescan=True))))
    assert result['execution_state']=='FAILED' and len(calls)==2
    assert result['execution']['scanner_run'] and not result['execution']['result_reused']
    assert result['status']=='PARTIAL'

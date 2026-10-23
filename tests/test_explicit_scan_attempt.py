"""Shipped CLI/MCP scans share the actual task lane and private-input lifetime."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from security_runtime import cli
from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.explicit_scan import run_explicit_scan
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.progress import ScanCancelled
from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_attempt import ScanAttemptStore
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.security import TaskSecurityService
from test_global_integration import structured


@pytest.fixture
def actual(tmp_path,monkeypatch):
    root=tmp_path/'project'
    root.mkdir()
    subprocess.run(['git','init','-q',str(root)],check=True)
    (root/'source.ts').write_text('export const value = 1;\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'private'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)
    store=SQLiteStore(tmp_path/'private/scans.db')
    hooks=HookStateStore(store.path.parent/'hooks')
    state=dict(calls=0,callback=None)
    class ObservedNative(NativeFunctionScanner):
        def scan(self,context,normalizer):
            assert not hooks.lock_held(root)
            state['calls']+=1
            if state['callback'] is not None: state['callback'](context)
            return super().scan(context,normalizer)
    registry=ScannerRegistry([ObservedNative()],fallback_adapters=[])
    runtime=SecurityRuntime(registry,store)
    coordinator=HookCoordinator(runtime,hooks)
    server=create_server(runtime,hook_coordinator=coordinator,global_mode=False)
    monkeypatch.setattr(cli,'ScannerRegistry',lambda:registry)
    monkeypatch.setattr(cli,'SecurityRuntime',lambda **kwargs:runtime)
    monkeypatch.setattr(cli,'IntegrationStateStore',lambda:SimpleNamespace(event=lambda value:None))
    monkeypatch.setattr(cli,'configure_logging',lambda **kwargs:None)
    return root,runtime,hooks,server,state


@pytest.mark.parametrize('entry',['cli','scan_project','scan_diff'])
def test_actual_entry_points_publish_the_real_input_without_a_development_baseline(actual,entry,capsys):
    root,runtime,hooks,server,state=actual
    if entry=='cli':
        assert cli.main(['scan','--path',str(root),'--mode','release','--json','--no-progress'])==0
        result=json.loads(capsys.readouterr().out)
        receipt=result['scanner_diagnostics']['execution_publication']
    else:
        result=structured(asyncio.run(server.call_tool(entry,dict(workspace_path=str(root)))))
        receipt=result['execution_publication']
    assert state['calls']==1 and receipt['publication']=='COMMITTED'
    assert receipt['input_id'].startswith('si1-')
    assert receipt['provider_freshness']=='EXECUTION_TIME_ONLY'
    attempts=ScanAttemptStore(hooks,root)
    assert attempts.read()['lane']['kind']=='MANUAL'
    assert attempts.read()['lane']['state']=='COMPLETED'
    assert not attempts.read()['directories']
    assert not (hooks.workspace_directory(root)/'security-tasks.db').exists()
    stored=runtime.store.get_scan(result['scan_id'])
    assert stored['scan_context']['execution_attempt']['input_id']==receipt['input_id']


def test_cli_and_mcp_both_observe_the_injected_task_workspace_lane(actual,capsys):
    root,runtime,hooks,server,state=actual
    tasks=TaskSecurityService(runtime,hooks)
    ref=tasks.begin(root,'original')['task_ref']
    baseline=tasks.load(root,ref)['baseline']
    (root/'source.ts').write_text('export const value = 2;\n')
    entered,release=threading.Event(),threading.Event()
    def block(context):
        entered.set()
        assert release.wait(15)
    state['callback']=block
    done=[]
    thread=threading.Thread(target=lambda:done.append(tasks.finish(root,ref)))
    thread.start()
    try:
        assert entered.wait(10)
        before=tasks.store(root).path.read_bytes()
        mcp=structured(asyncio.run(server.call_tool('scan_project',dict(workspace_path=str(root)))))
        assert mcp['status']=='BUSY' and mcp['reason_code']=='SCAN_ATTEMPT_BUSY'
        assert cli.main(['scan','--path',str(root),'--mode','release','--json','--no-progress'])==2
        cli_result=json.loads(capsys.readouterr().out)
        assert cli_result==mcp and state['calls']==1
        assert tasks.store(root).path.read_bytes()==before
    finally:
        release.set()
        thread.join(20)
    assert not thread.is_alive() and done[0]['status']=='READY'
    assert tasks.load(root,ref)['baseline']==baseline


@pytest.mark.parametrize('entry',['cli','mcp'])
def test_cancellation_keeps_the_original_task_and_releases_raw_input(actual,entry,capsys):
    root,runtime,hooks,server,state=actual
    tasks=TaskSecurityService(runtime,hooks)
    ref=tasks.begin(root,'original')['task_ref']
    before=tasks.store(root).path.read_bytes()
    def stop(context): raise ScanCancelled('cancelled in actual provider')
    state['callback']=stop
    if entry=='cli':
        assert cli.main(['scan','--path',str(root),'--mode','release','--json','--no-progress'])==130
        result=json.loads(capsys.readouterr().out)
    else:
        result=structured(asyncio.run(server.call_tool('scan_project',dict(workspace_path=str(root)))))
    assert result['status']=='CANCELLED' and not result['check_completed']
    assert tasks.store(root).path.read_bytes()==before
    assert tasks.load(root,ref)['phase']=='ACTIVE'
    state=ScanAttemptStore(hooks,root).read()
    assert state['lane']['state']=='CANCELLED' and not state['directories']
    assert 'lease_owner' not in json.dumps(result)


def test_explicit_use_case_process_death_has_a_real_bounded_recovery_entry(actual):
    root,runtime,hooks,_,_=actual
    code=('import os,sys;from pathlib import Path;'
        'from security_runtime.runtime import SecurityRuntime;'
        'from security_runtime.scanners import ScannerRegistry;'
        'from security_runtime.dynamic_function import NativeFunctionScanner;'
        'from security_runtime.storage import SQLiteStore;'
        'from security_runtime.explicit_scan import run_explicit_scan;'
        '\nclass Crash(NativeFunctionScanner):\n def scan(self,context,normalizer): os._exit(0)\n'
        'r=SecurityRuntime(ScannerRegistry([Crash()],fallback_adapters=[]),SQLiteStore(Path(sys.argv[2])));'
        'run_explicit_scan(r,Path(sys.argv[1]),mode="release",now=lambda:100)')
    subprocess.run([sys.executable,'-c',code,str(root),str(runtime.store.path)],
                   capture_output=True,check=True,timeout=20)
    attempts=ScanAttemptStore(hooks,root,now=lambda:701)
    old=attempts.read()
    assert old['lane']['state']=='ACTIVE' and len(old['directories'])==1
    raw=attempts.private_parent/old['directories'][0]['name']
    assert (raw/'source/source.ts').is_file()
    # A real next explicit request performs bounded cleanup before claiming.
    result=run_explicit_scan(runtime,root,mode='release',hooks=hooks,now=lambda:701)
    new=attempts.read()
    assert new['lane']['generation']==old['lane']['generation']+1
    assert new['lane']['scan_id']==result.scan_id and new['lane']['state']=='COMPLETED'
    assert not raw.exists() and not new['directories']


def test_relative_private_state_uses_one_canonical_cleanup_namespace(actual,tmp_path,monkeypatch):
    root,runtime,_,_,state=actual
    monkeypatch.chdir(tmp_path)
    hooks=HookStateStore(Path('relative-private-state'))
    result=run_explicit_scan(runtime,root,mode='release',hooks=hooks)
    attempts=ScanAttemptStore(hooks,root)
    assert attempts.private_parent.is_absolute()
    assert attempts.private_parent==attempts.private_parent.resolve()
    assert state['calls']==1
    assert attempts.read()['lane']['scan_id']==result.scan_id
    assert not attempts.read()['directories']

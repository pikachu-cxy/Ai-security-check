"""Actual local MCP/scanners, disposable Windows native Host-edit fixture.

The fixture Host tool below is NOT a Codex API or a production Runtime tool.
It supplies target-file write/rename exclusion which default Codex lacks.
No model latency is simulated, no sleeps are inserted, no product install.
"""
import argparse
import asyncio
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from remediation_episode_acceptance import SAFE, UNSAFE
from codex_hook_fixture import invocation_claims


@contextmanager
def native_target_edit(path):
    """Host-side Windows handle: deny other writes/deletes until commit/abort."""
    if os.name!='nt':
        raise RuntimeError('WINDOWS_NATIVE_FIXTURE_REQUIRED')
    from security_runtime.hook_state import no_links
    no_links(path)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,
        ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.ReadFile.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
    kernel.WriteFile.argtypes=kernel.ReadFile.argtypes
    kernel.SetFilePointerEx.argtypes=[wintypes.HANDLE,ctypes.c_longlong,ctypes.c_void_p,wintypes.DWORD]
    kernel.SetEndOfFile.argtypes=[wintypes.HANDLE]
    kernel.FlushFileBuffers.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.GetFinalPathNameByHandleW.argtypes=[wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD]
    handle=kernel.CreateFileW(str(path),0xC0000000,1,None,3,0x00200000,None)
    if handle==ctypes.c_void_p(-1).value:
        raise RuntimeError('HOST_TARGET_EDIT_EXCLUSION_UNAVAILABLE')
    try:
        def bound():
            text=ctypes.create_unicode_buffer(4096)
            size=kernel.GetFinalPathNameByHandleW(handle,text,4096,0)
            if not 0<size<4096 or os.path.normcase(text.value.removeprefix('\\\\?\\'))!=os.path.normcase(str(path)):
                raise RuntimeError('HOST_TARGET_HANDLE_PATH_CHANGED')
        bound()
        buffer=ctypes.create_string_buffer(32769); read=wintypes.DWORD()
        if not kernel.ReadFile(handle,buffer,32769,ctypes.byref(read),None) or read.value>32768:
            raise RuntimeError('HOST_TARGET_READ_UNAVAILABLE')
        content=buffer.raw[:read.value]
        def commit(new):
            bound()
            if len(new)>32768:
                raise RuntimeError('HOST_EDIT_BUDGET_EXCEEDED')
            written=wintypes.DWORD()
            if not kernel.SetFilePointerEx(handle,0,None,0):raise RuntimeError('HOST_SEEK_FAILED')
            if not kernel.WriteFile(handle,new,len(new),ctypes.byref(written),None) or written.value!=len(new):
                raise RuntimeError('HOST_WRITE_FAILED')
            if not kernel.SetEndOfFile(handle) or not kernel.FlushFileBuffers(handle):
                raise RuntimeError('HOST_FLUSH_FAILED')
        yield content,commit
    finally:
        kernel.CloseHandle(handle)


def fixture_server(mode):
    from security_runtime.mcp_server import create_server
    from security_runtime.remediation import RemediationService
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.fast_fix import HOST_CONTRACT,sha
    root=Path(os.environ['SECURITY_RUNTIME_WORKSPACE']).resolve()
    if root.name!='project' or not root.parent.name.startswith('p04-fast-'):
        raise RuntimeError('DISPOSABLE_FIXTURE_ONLY')
    holder={}
    def factory(*args,**kwargs):
        service=RemediationService(*args,**kwargs,
            fast_fix_host_contract=HOST_CONTRACT if mode=='fast' else None)
        holder['service']=service
        return service
    server=create_server(remediation_factory=factory,hook_coordinator=HookCoordinator(cooldown_ms=0))
    @server.tool()
    def fixture_host_edit(plan:dict|None=None)->dict:
        """Test-only native Host operation. Never registered by normal Runtime."""
        service=holder['service'];target=root/'src/main/java/demo/CodeModeTlsService.java'
        with service.state.lock(root) as acquired:
            if not acquired:return {'status':'HOST_EDIT_BUSY'}
            with native_target_edit(target) as (content,commit):
                if plan is not None:
                    result=service.fast_fix.validate_and_claim(plan,root)
                    if result['status']!='FAST_FIX_APPLY_AUTHORIZED':return result
                    left,right=plan['byte_range']['start'],plan['byte_range']['end']
                    if sha(content)!=plan['expected_file_sha256'] or sha(content[left:right])!=plan['expected_segment_sha256']:
                        return {'status':'FAST_FIX_STALE','reason_code':'FAST_FIX_EXPECTED_BYTES_MISMATCH'}
                    new=content[:left]+content[right:]
                    if sha(new)!=plan['expected_result_sha256']:
                        return {'status':'FAST_FIX_STALE','reason_code':'FAST_FIX_PLAN_TAMPERED'}
                else:
                    path=service.state.path(root,'codex','fast-fix-trial')
                    rows=service._read(path,service.state.key(root))
                    current=[r for r in rows.values() if r.get('token_hash') in service.prepared]
                    if len(current)!=1 or content!=UNSAFE.encode():
                        return {'status':'AGENT_PREPARATION_REQUIRED'}
                    new=SAFE.encode()
                commit(new)  # Fixture Host owns this write; product Runtime never writes.
                return {'status':'HOST_EDIT_APPLIED','source_modified':True,
                        'target_edit_exclusion':'WINDOWS_KERNEL_DENY_WRITE_DELETE'}
    server.run(transport='stdio')


async def trial(mode):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters,stdio_client
    episodes=[]; calls=[]
    with tempfile.TemporaryDirectory(prefix='p04-fast-') as temporary:
        parent=Path(temporary).resolve();root=parent/'project';root.mkdir()
        subprocess.run(['git','init',str(root)],check=True,capture_output=True)
        target=root/'src/main/java/demo/CodeModeTlsService.java';target.parent.mkdir(parents=True)
        target.write_bytes(SAFE.encode())
        env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(root),SECURITY_RUNTIME_STATE_DIR=str(parent/'state'),
                 SECURITY_RUNTIME_OFFLINE='1',SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1')
        params=StdioServerParameters(command=sys.executable,args=[str(Path(__file__).resolve()),'--fixture-server',mode],
                                    cwd=root,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(params,errlog=errors) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize()
                    async def call(tool,arguments,*,record=True):
                        assert tool in {'handle_hook_event','prepare_task_fix','fixture_host_edit'}
                        response=await client.call_tool(tool,invocation_claims(tool, arguments))
                        assert not response.isError,tool
                        data=response.structuredContent or json.loads(response.content[0].text)
                        data=data.get('result',data)
                        if record:calls.append({'tool':tool,'status':data.get('status')})
                        return data
                    claims={'event':'PostToolUse','workspace_path':str(root),'session_id':'fast-fix-trial','tool_name':'apply_patch'}
                    baseline=await call('handle_hook_event',claims)
                    assert baseline['status']=='BASELINE_ESTABLISHED'
                    first=None; first_episode=None
                    for number in range(1,4 if mode=='fast' else 2):
                        target.write_bytes(UNSAFE.encode())
                        start=time.perf_counter();offset=len(calls)
                        found=await call('handle_hook_event',claims);grant=found['remediation']
                        assert grant['action']=='AUTO_FIX' and grant['episode_number']==number
                        fast=mode=='fast' and number!=3
                        if mode=='fast':
                            plan=grant['fast_fix_plan']  # Opaque refs retained verbatim.
                            assert 'prepare' not in grant and grant['fast_fix']['plan_ready']
                            if first:
                                assert plan['episode_id']!=first_episode
                                assert plan['remediation_ref']!=first['remediation_ref']
                                rejected=await call('fixture_host_edit',{'plan':first},record=False)
                                assert rejected['status']!='HOST_EDIT_APPLIED'
                            if number==3:
                                bad={**plan,'replacement':'tampered'}
                                rejected=await call('fixture_host_edit',{'plan':bad},record=False)
                                assert rejected['reason_code']=='FAST_FIX_PLAN_TAMPERED'
                                assert target.read_bytes()==UNSAFE.encode()
                            values=grant['agent_fallback']['arguments']
                        else:
                            assert grant['fix_path']=='AGENT_FIX'
                            assert grant['fast_fix']['fallback_reason']=='FAST_FIX_HOST_CAPABILITY_UNAVAILABLE'
                            values=grant['prepare']['arguments']
                        if not fast:
                            prepared=await call('prepare_task_fix',values)
                            assert prepared['status']=='READY_FOR_HOST_FIX'
                        applied=await call('fixture_host_edit',{'plan':plan} if fast else {})
                        assert applied['status']=='HOST_EDIT_APPLIED'
                        assert target.read_bytes()==SAFE.encode()
                        closed=await call('handle_hook_event',claims)
                        wall=round((time.perf_counter()-start)*1000,3)
                        decision=closed['remediation'];receipt=decision['security_verification']
                        assert receipt['status']=='SCANNER_VERIFIED_RESOLVED' and receipt['phase']=='CLOSED'
                        assert receipt['task_ref']==values['task_ref'] and receipt['grant_id']==grant['grant_id']
                        assert decision['next_action']=='RETURN_TO_HOST'
                        assert closed['scanner_run'] and closed['status']=='SCANNED'
                        assert decision['verification']['runtime_observed_execution']['engine_process_observed']
                        current_calls=calls[offset:]
                        prepare_count=sum(c['tool']=='prepare_task_fix' for c in current_calls)
                        assert prepare_count==(0 if fast else 1)
                        timing=closed['remediation_cycle_breakdown_ms']
                        assert closed['remediation_cycle_breakdown_measurement']['status']=='OBSERVED'
                        assert abs(sum(v for v in timing.values() if v is not None)-closed['remediation_cycle_wall_ms'])<=.01
                        if fast:
                            assert timing['prepare_fix'] is None and timing['host_fix_window'] is None
                            assert closed['remediation_cycle_timepoints_ms']['prepare_task_fix_started'] is None
                        diagnostics=[found['scanner_diagnostics'],closed['scanner_diagnostics']]
                        rechecks=decision['verification']['scanner_diagnostics']
                        sast=sum(d['providers']['semgrep']['counts']['process_invocations'] for d in diagnostics)
                        secrets=sum(d['providers']['gitleaks']['counts']['process_invocations'] for d in diagnostics)
                        recheck_count=sum(d['counts']['process_invocations'] for d in rechecks)
                        assert sast==2 and secrets==2 and recheck_count==1
                        episodes.append({'number':number,'fix_path':decision['fix_path'],
                            'prepare_task_fix_calls':prepare_count,'runtime_mcp_calls':len(current_calls)-1,
                            'fixture_host_edit_calls':1,'all_fixture_transport_calls':len(current_calls),
                            'driver_wall_ms':wall,'remediation_cycle_wall_ms':closed['remediation_cycle_wall_ms'],
                            'breakdown_ms':timing,'timepoints_ms':closed['remediation_cycle_timepoints_ms'],
                            'detail_ms':closed['remediation_cycle_detail_ms'],
                            'boundary':closed['remediation_cycle_boundary'],
                            'scanner_invocations':{'hook_sast':sast,'hook_secret':secrets,'original_rule_recheck':recheck_count},
                            'status':receipt['status'],'stage':receipt['phase'],'next_action':decision['next_action']})
                        if mode=='fast':first=first or plan;first_episode=first_episode or plan['episode_id']
                    assert not list(target.parent.glob('*.class'))
            errors.seek(0);assert '0x80131506' not in errors.read()
    return {'path':mode,'episodes':episodes,'calls':calls}


async def run():
    started=time.perf_counter()
    agent=await trial('agent');fast=await trial('fast')
    return {'status':'PASS','transport':'ACTUAL_LOCAL_MCP_STDIO','scanner':'ACTUAL_MANAGED_OFFLINE',
            'host':'DISPOSABLE_WINDOWS_NATIVE_EDIT_FIXTURE_NOT_CODEX_API','actual_desktop':'NOT_RUN_USER_REQUEST',
            'agent':agent,'fast':fast,'runtime_edits_source':False,'model':False,'network':False,
            'functional_calls':0,'build_test_sandbox':False,'injected_sleep':False,
            'raw_references_persisted':False,'duration_seconds':round(time.perf_counter()-started,2)}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-server',choices=['agent','fast'])
    parser.add_argument('--output',type=Path);arguments=parser.parse_args()
    if arguments.fixture_server:fixture_server(arguments.fixture_server)
    else:
        result=asyncio.run(run())
        if arguments.output:arguments.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))

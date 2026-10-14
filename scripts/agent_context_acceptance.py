"""Offline actual MCP/scanners, equal deterministic Host fixture for context A/B.

P0-4 baseline is a locally verified extracted wheel, not an active installation.
No LLM, artificial waiting, source/artifact persistence, or Desktop trial.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from fast_fix_acceptance import native_target_edit
from remediation_episode_acceptance import SAFE, UNSAFE
from codex_hook_fixture import invocation_claims
from remediation_acceptance import approve_reported_risk


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def fixture_server():
    from security_runtime.mcp_server import create_server
    from security_runtime.remediation import RemediationService
    from security_runtime.hook_runtime import HookCoordinator
    root=Path(os.environ['SECURITY_RUNTIME_WORKSPACE']).resolve()
    if root.name!='project' or not root.parent.name.startswith('p05-context-'):
        raise RuntimeError('DISPOSABLE_FIXTURE_ONLY')
    holder={}
    def factory(*args,**kwargs):
        holder['service']=RemediationService(*args,**kwargs)
        return holder['service']
    server=create_server(remediation_factory=factory,hook_coordinator=HookCoordinator(cooldown_ms=0))
    @server.tool()
    def fixture_host_edit()->dict:
        """Independent test Host owns native target read/edit; not a product tool."""
        service=holder['service'];target=root/'src/main/java/demo/CodeModeTlsService.java'
        with service.state.lock(root) as acquired:
            if not acquired:return {'status':'HOST_EDIT_BUSY'}
            path=service.state.path(root,'codex','context-trial')
            rows=service._read(path,service.state.key(root))
            current=[r for r in rows.values() if r.get('token_hash') in service.prepared]
            with native_target_edit(target) as (content,commit):
                if len(current)!=1 or content!=UNSAFE.encode():
                    return {'status':'HOST_PREPARATION_REQUIRED'}
                commit(SAFE.encode())
            return {'status':'HOST_EDIT_APPLIED','source_modified':True,
                    'fixture_target_read_operations':1,'fixture_search_operations':0}
    server.run(transport='stdio')


def information_payload(grant,prepared):
    """Same projection for both versions; metadata/code stays in memory only."""
    keys=('security_fix_context','security_fix_context_ref','security_context_status',
          'security_context_diagnostics','guidance','security_goal','root_cause','known_facts',
          'affected_findings','existing_reviews','unknown_conditions','fix_constraints',
          'recommended_changes','regression_requirements','bounded_evidence','host_protocol')
    return {'hook':{k:grant[k] for k in keys if k in grant},
            'prepare':{k:prepared[k] for k in keys if k in prepared},
            'prepare_guidance':prepared['remediation_authorization']['guidance']}


async def trial(mode,baseline):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters,stdio_client
    repository=Path(__file__).resolve().parents[1]
    source=baseline if mode=='before' else repository/'src'
    episodes=[]
    with tempfile.TemporaryDirectory(prefix='p05-context-') as temporary:
        parent=Path(temporary).resolve();root=parent/'project';root.mkdir()
        subprocess.run(['git','init',str(root)],check=True,capture_output=True)
        target=root/'src/main/java/demo/CodeModeTlsService.java';target.parent.mkdir(parents=True)
        target.write_bytes(SAFE.encode())
        env=dict(os.environ,PYTHONPATH=str(source),SECURITY_RUNTIME_WORKSPACE=str(root),
                 SECURITY_RUNTIME_STATE_DIR=str(parent/'state'),SECURITY_RUNTIME_OFFLINE='1',
                 SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1')
        parameters=StdioServerParameters(command=sys.executable,
            args=[str(Path(__file__).resolve()),'--fixture-server'],cwd=root,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(parameters,errlog=errors) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize()
                    tools=(await client.list_tools()).tools
                    schema=next(t.inputSchema for t in tools if t.name=='prepare_task_fix')
                    assert ('security_context_ref' in schema['properties'])==(mode=='after')
                    calls=[]
                    async def call(name,arguments):
                        assert name in {'handle_hook_event','confirm_remediation','prepare_task_fix','fixture_host_edit'}
                        response=await client.call_tool(name,invocation_claims(name, arguments))
                        assert not response.isError,name
                        data=response.structuredContent or json.loads(response.content[0].text)
                        calls.append(name)
                        return data.get('result',data)
                    claims={'event':'PostToolUse','workspace_path':str(root),
                            'session_id':'context-trial','tool_name':'apply_patch'}
                    assert (await call('handle_hook_event',claims))['status']=='BASELINE_ESTABLISHED'
                    previous=None
                    for number in range(1,3):
                        target.write_bytes(UNSAFE.encode());offset=len(calls);start=time.perf_counter()
                        hook=await call('handle_hook_event',claims)
                        grant=await approve_reported_risk(call,hook['remediation'],target)
                        assert grant['action']=='AUTO_FIX' and grant['episode_number']==number
                        assert grant['fix_path']=='AGENT_FIX'
                        assert grant['fast_fix']['fallback_reason']=='FAST_FIX_HOST_CAPABILITY_UNAVAILABLE'
                        args=grant['prepare']['arguments']  # Original opaque strings, no reconstruction.
                        if mode=='after':
                            context=grant['security_fix_context']
                            assert len(canonical(context))==grant['security_context_diagnostics']['security_context_size_bytes']
                            assert context['target']['file']==target.relative_to(root).as_posix()
                            args={**args,'security_context_ref':grant['security_fix_context_ref']}
                            if previous:
                                assert args['security_context_ref']!=previous['security_context_ref']
                        prepared=await call('prepare_task_fix',args)
                        assert prepared['status']=='READY_FOR_HOST_FIX'
                        assert prepared['verification_plan']['arguments']['remediation_ref']==args['remediation_ref']
                        if mode=='after':
                            assert prepared['security_context_status']=='REUSE_HOOK_CONTEXT'
                            assert prepared['security_fix_context_ref']==args['security_context_ref']
                            assert 'security_fix_context' not in prepared and UNSAFE not in json.dumps(prepared)
                        information_bytes=len(canonical(information_payload(grant,prepared)))
                        applied=await call('fixture_host_edit',{})
                        assert applied['status']=='HOST_EDIT_APPLIED' and target.read_bytes()==SAFE.encode()
                        closed=await call('handle_hook_event',claims);driver_ms=(time.perf_counter()-start)*1000
                        receipt=closed['remediation']['security_verification']
                        assert receipt['status']=='SCANNER_VERIFIED_RESOLVED' and receipt['phase']=='CLOSED'
                        assert receipt['task_ref']==args['task_ref'] and receipt['grant_id']==grant['grant_id']
                        assert closed['remediation']['next_action']=='RETURN_TO_HOST'
                        current=calls[offset:]
                        assert current.count('prepare_task_fix')==1
                        runs=[hook,closed]
                        sast=sum(r['scanner_diagnostics']['providers']['semgrep']['counts']['process_invocations'] for r in runs)
                        secrets=sum(r['scanner_diagnostics']['providers']['gitleaks']['counts']['process_invocations'] for r in runs)
                        rechecks=closed['remediation']['verification']['scanner_diagnostics']
                        count=sum(r['counts']['process_invocations'] for r in rechecks)
                        assert sast==2 and secrets==2 and count==1
                        episodes.append({'number':number,'status':receipt['status'],'stage':receipt['phase'],
                            'fix_path':'AGENT_FIX','context_version':grant.get('security_fix_context',{}).get('version','LEGACY_TASK_FIX_REPORT'),
                            'security_context_size_bytes':grant.get('security_context_diagnostics',{}).get('security_context_size_bytes'),
                            'fix_information_size_bytes':information_bytes,'information_projection':'HOOK_AND_PREPARE_FACTS_PLUS_GUIDANCE',
                            'runtime_mcp_calls':len(current)-current.count('fixture_host_edit'),'prepare_calls':1,
                            'host_fixture_edit_calls':1,'host_fixture_target_reads':applied['fixture_target_read_operations'],
                            'host_fixture_searches':applied['fixture_search_operations'],
                            'actual_agent_reads':None,'actual_agent_searches':None,'model_reasoning_duration_ms':None,
                            'remediation_cycle_wall_ms':closed['remediation_cycle_wall_ms'],
                            'driver_wall_ms':round(driver_ms,3),'timing_ms':closed['timing_ms'],
                            'scanner_invocations':{'hook_sast':sast,'hook_secret':secrets,'original_rule_recheck':count},
                            'scanner_diagnostics':{key:r['scanner_diagnostics'] for key,r in zip(('initial','post_edit'),runs)},
                            'recheck_diagnostics':closed['remediation']['verification']['scanner_diagnostics']})
                        if mode=='after' and previous:
                            rejected=await call('prepare_task_fix',previous)
                            assert rejected.get('status')!='READY_FOR_HOST_FIX'
                            assert target.read_bytes()==SAFE.encode()
                            episodes[-1]['old_reference_rejected_after_measured_cycle']=True
                        previous=args
    return {'episodes':episodes}


async def main(args):
    start=time.perf_counter();root=Path(__file__).resolve().parents[1]
    baseline=Path(args.baseline).resolve()
    assert baseline==root/'.security-runtime/p05-baseline' and (baseline/'security_runtime/remediation.py').is_file()
    before=await trial('before',baseline);after=await trial('after',baseline)
    assert all(a['fix_information_size_bytes']<b['fix_information_size_bytes'] for a,b in zip(after['episodes'],before['episodes']))
    result={'status':'PASS','duration_seconds':round(time.perf_counter()-start,2),
        'transport':'ACTUAL_LOCAL_MCP_STDIO','scanner':'ACTUAL_MANAGED_OFFLINE',
        'host':'SIMULATED_WINDOWS_NATIVE_EDIT_FIXTURE','before':before,'after':after,
        'network':False,'model':False,'sleep_injected':False,'deep_verification':False,
        'target_build':False,'active_runtime_replaced':False,'source_persisted':False,
        'host_behavior_comparison':'IDENTICAL_FIXED_FIXTURE; NOT_LLM_BEHAVIOR',
        'baseline':'HASH_VERIFIED_P04_WHEEL_SOURCE'}
    Path(args.output).write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'status':result['status'],'duration_seconds':result['duration_seconds']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-server',action='store_true')
    parser.add_argument('--baseline');parser.add_argument('--output');args=parser.parse_args()
    if args.fixture_server:fixture_server()
    else:asyncio.run(main(args))

"""Actual offline MCP/scanners; simulated native Host. No Desktop/model speed claim."""
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


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def fixture_source(mode):
    if mode != 'fallback': return UNSAFE, SAFE
    statement = 'connection.setHostnameVerifier((hostname, session) -> true);'
    unsafe = UNSAFE.replace(statement, statement + ' // preserve this unrelated comment')
    return unsafe, unsafe.replace(statement, '')


def fixture_server():
    from security_runtime.mcp_server import create_server
    from security_runtime.remediation import RemediationService
    from security_runtime.hook_runtime import HookCoordinator
    root = Path(os.environ['SECURITY_RUNTIME_WORKSPACE']).resolve()
    if root.name != 'project' or not root.parent.name.startswith('p06-ticket-'):
        raise RuntimeError('DISPOSABLE_FIXTURE_ONLY')
    after = os.environ.get('TICKET_ACCEPTANCE_MODE') == 'after'
    mode = os.environ.get('TICKET_ACCEPTANCE_MODE')
    unsafe, safe = fixture_source(mode)
    holder = {}
    def factory(*args, **kwargs):
        if mode in {'after','fallback','legacy-client'}: kwargs['inline_agent_tickets'] = True
        holder['service'] = RemediationService(*args, **kwargs)
        return holder['service']
    server = create_server(remediation_factory=factory, hook_coordinator=HookCoordinator(cooldown_ms=0))
    @server.tool()
    def fixture_host_edit(task_ref: str, remediation_ref: str, prepared_attestation: str | None = None) -> dict:
        """Test Host only. Runtime product never owns this native reader/editor."""
        service = holder['service']; target = root/'src/main/java/demo/CodeModeTlsService.java'
        with service.state.lock(root) as acquired:
            if not acquired: return {'status':'HOST_EDIT_BUSY'}
            _, _, _, record = service._reference(root, remediation_ref, task_ref)
            if record['token_hash'] not in service.prepared:
                return {'status':'HOST_PREPARATION_REQUIRED'}
            if after:
                item = service.agent_tickets.items.get(record['token_hash'])
                if not item or item['ticket']['prepared_attestation'] != prepared_attestation:
                    return {'status':'HOST_TICKET_MISMATCH'}
            with native_target_edit(target) as (content, commit):
                if content != unsafe.encode(): return {'status':'HOST_TARGET_CHANGED'}
                commit(safe.encode())
        return {'status':'HOST_EDIT_APPLIED','target_reads':1,'searches':0,'native_edits':1}
    server.run(transport='stdio')


async def trial(mode, baseline):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    repository = Path(__file__).resolve().parents[1]
    source = baseline if mode == 'before' else repository/'src'
    unsafe, safe = fixture_source(mode)
    episodes = []
    with tempfile.TemporaryDirectory(prefix='p06-ticket-') as temporary:
        parent = Path(temporary).resolve(); root = parent/'project'; root.mkdir()
        subprocess.run(['git','init',str(root)], check=True, capture_output=True)
        target = root/'src/main/java/demo/CodeModeTlsService.java'; target.parent.mkdir(parents=True)
        target.write_bytes(safe.encode())
        env = dict(os.environ, PYTHONPATH=str(source), SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_STATE_DIR=str(parent/'state'), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1', TICKET_ACCEPTANCE_MODE=mode)
        parameters = StdioServerParameters(command=sys.executable,
            args=[str(Path(__file__).resolve()),'--fixture-server'], cwd=root, env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(parameters,errlog=errors) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize(); calls=[]
                    async def call(name, arguments):
                        assert name in {'handle_hook_event','prepare_task_fix','fixture_host_edit'}
                        response = await client.call_tool(name,invocation_claims(name, arguments))
                        assert not response.isError, name
                        if mode == 'after' and name == 'handle_hook_event':
                            # Simulate lost model-readable/prose channel. Formal
                            # SDK structuredContent is still the original object.
                            response.content = []
                        data = response.structuredContent
                        if name == 'handle_hook_event':
                            assert data is not None  # Formal Hook ticket channel is mandatory.
                        elif data is None:
                            # Legacy tools may still use the SDK JSON text envelope.
                            data = json.loads(response.content[0].text)
                        calls.append(name)
                        return data.get('result',data)
                    claims = {'event':'PostToolUse','workspace_path':str(root),
                              'session_id':'ticket-trial','tool_name':'apply_patch'}
                    assert (await call('handle_hook_event',claims))['status']=='BASELINE_ESTABLISHED'
                    previous = None
                    for number in range(1,3):
                        target.write_bytes(unsafe.encode()); offset=len(calls); start=time.perf_counter()
                        hook=await call('handle_hook_event',claims); grant=hook['remediation']
                        assert grant['action']=='AUTO_FIX' and grant['episode_number']==number
                        assert grant['fix_path']=='AGENT_FIX'
                        context=grant['security_fix_context']
                        t=grant.get('agent_fix_ticket')
                        if mode=='after':
                            assert t and t['mode']=='INLINE_PREPARED'
                            assert t['task_ref']==grant['prepare']['arguments']['task_ref']
                            assert t['remediation_ref']==grant['prepare']['arguments']['remediation_ref']
                            assert t['security_context_ref']==grant['security_fix_context_ref']
                            assert t['allowed_target_paths']==[target.relative_to(root).as_posix()]
                            args={'task_ref':t['task_ref'],'remediation_ref':t['remediation_ref']}
                            host_args={**args,'prepared_attestation':t['prepared_attestation']}
                            if previous:
                                assert t['episode_id']!=previous['episode_id']
                                assert t['prepared_attestation']!=previous['prepared_attestation']
                        else:
                            if mode == 'fallback':
                                assert t is None
                                assert grant['agent_fix_ticket_diagnostics']['inline_prepare_reason']=='FAST_FIX_AMBIGUOUS_TARGET'
                            args=grant['prepare']['arguments']
                            prepared=await call('prepare_task_fix',{**args,'security_context_ref':grant['security_fix_context_ref']})
                            assert prepared['status']=='READY_FOR_HOST_FIX'
                            assert prepared['verification_plan']['arguments']['remediation_ref']==args['remediation_ref']
                            host_args=args
                        applied=await call('fixture_host_edit',host_args)
                        assert applied['status']=='HOST_EDIT_APPLIED' and target.read_bytes()==safe.encode()
                        closed=await call('handle_hook_event',claims); driver_ms=(time.perf_counter()-start)*1000
                        receipt=closed['remediation']['security_verification']
                        assert receipt['status']=='SCANNER_VERIFIED_RESOLVED' and receipt['phase']=='CLOSED'
                        assert receipt['task_ref']==args['task_ref'] and receipt['grant_id']==grant['grant_id']
                        assert closed['remediation']['next_action']=='RETURN_TO_HOST'
                        current=calls[offset:]; prepares=current.count('prepare_task_fix')
                        assert prepares==(0 if mode=='after' else 1)
                        runs=[hook,closed]
                        sast=sum(r['scanner_diagnostics']['providers']['semgrep']['counts']['process_invocations'] for r in runs)
                        secret=sum(r['scanner_diagnostics']['providers']['gitleaks']['counts']['process_invocations'] for r in runs)
                        rechecks=closed['remediation']['verification']['scanner_diagnostics']
                        count=sum(r['counts']['process_invocations'] for r in rechecks)
                        assert (sast,secret,count)==(2,2,1)
                        episodes.append({'number':number,'status':receipt['status'],'stage':receipt['phase'],
                            'runtime_mcp_calls':len(current)-current.count('fixture_host_edit'), 'prepare_calls':prepares,
                            'host_fixture_rpc_calls':1,'simulated_host_steps':prepares+applied['target_reads']+applied['native_edits'],
                            'host_target_reads':applied['target_reads'],'host_searches':applied['searches'],
                            'context_bytes':len(canonical(context)),'ticket_bytes':len(canonical(t)) if t else 0,
                            'hook_model_context_bytes':len(hook['hookSpecificOutput']['additionalContext'].encode()),
                            'remediation_cycle_wall_ms':closed['remediation_cycle_wall_ms'],
                            'driver_wall_ms':round(driver_ms,3),'initial_timing_ms':hook['timing_ms'],
                            'post_timing_ms':closed['timing_ms'],
                            'cycle_breakdown_ms':closed['remediation_cycle_breakdown_ms'],
                            'scanner_invocations':{'hook_sast':sast,'hook_secret':secret,'original_rule_recheck':count},
                            'reference_integrity':'ORIGINAL_VALUES_EXACT; NO_RECONSTRUCTION',
                            'structured_handoff_survived_prose_loss':mode=='after',
                            'actual_desktop_agent_steps':None,'model_speedup':None})
                        if mode=='after' and previous:
                            rejected=await call('prepare_task_fix',{'task_ref':previous['task_ref'],
                                'remediation_ref':previous['remediation_ref']})
                            assert rejected.get('status')!='READY_FOR_HOST_FIX'
                            episodes[-1]['old_episode_refs_rejected_after_measurement']=True
                        previous=t
    return {'episodes':episodes}


async def main(args):
    started=time.perf_counter(); root=Path(__file__).resolve().parents[1]; baseline=Path(args.baseline).resolve()
    assert baseline==root/'.security-runtime/p06-baseline' and (baseline/'security_runtime/fix_context.py').is_file()
    if args.fallback_only or args.legacy_client_only:
        mode = 'legacy-client' if args.legacy_client_only else 'fallback'
        fallback = await trial(mode, baseline)
        result={'status':'PASS','duration_seconds':round(time.perf_counter()-started,2),
                'runtime':'CURRENT_P06','transport':'ACTUAL_LOCAL_MCP_STDIO','scanner':'ACTUAL_MANAGED_OFFLINE',
                'host':'SIMULATED_NATIVE_EDIT_FIXTURE','case':mode,'fallback':fallback,'network':False,'model':False,
                'sleep_injected':False,'active_runtime_replaced':False}
        Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps({'status':result['status'],'duration_seconds':result['duration_seconds']}))
        return
    before=await trial('before',baseline); after=await trial('after',baseline)
    result={'status':'PASS','duration_seconds':round(time.perf_counter()-started,2),
        'transport':'ACTUAL_LOCAL_MCP_STDIO','scanner':'ACTUAL_MANAGED_OFFLINE',
        'host':'SIMULATED_NATIVE_EDIT_FIXTURE; NOT_DESKTOP','baseline':'HASH_VERIFIED_P05_WHEEL_SOURCE',
        'before':before,'after':after,'network':False,'model':False,'sleep_injected':False,
        'deep_verification':False,'target_build':False,'active_runtime_replaced':False,
        'source_persisted':False,'model_host_visibility':'UNKNOWN_PENDING_DESKTOP',
        'native_edit_bridge_installed':False}
    Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'status':result['status'],'duration_seconds':result['duration_seconds']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--fixture-server',action='store_true')
    parser.add_argument('--fallback-only',action='store_true')
    parser.add_argument('--legacy-client-only',action='store_true')
    parser.add_argument('--baseline'); parser.add_argument('--output'); args=parser.parse_args()
    if args.fixture_server: fixture_server()
    else: asyncio.run(main(args))

"""Actual offline MCP/scanners with disposable simulated native Host edits.

No Desktop trial, model call, opaque-reference serialization, build or sleep.
The original P0-6 wheel source can reproduce the same blank-line rejection.
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

STATEMENT = b'connection.setHostnameVerifier((hostname, session) -> true);'


def fixture_bytes(case):
    eol = b'\r\n' if 'crlf' in case else b'\n'
    raw = UNSAFE.encode().replace(b'\n', eol).replace(STATEMENT+eol, STATEMENT+eol+eol)
    if 'mixed' in case:
        raw = raw.replace(STATEMENT+eol+eol, STATEMENT+b'\n\n')
    if 'bom' in case:
        raw = b'\xef\xbb\xbf'+raw
    start = raw.index(STATEMENT)
    left = raw.rfind(b'\n', 0, start)+1
    end = raw.index(b'\n', start)+1
    blank_end = end+(2 if raw[end:end+2]==b'\r\n' else 1)
    if 'statement' in case:
        fixed = raw.replace(STATEMENT, b'', 1)
    elif 'canonical' in case:
        fixed = raw[:left]+raw[end:]
    else:
        fixed = raw[:left]+raw[blank_end:]
    if 'neighbor' in case:
        fixed = fixed.replace(b'1000', b'2000')
    return raw, fixed


def fixture_server():
    from security_runtime.mcp_server import create_server
    from security_runtime.remediation import RemediationService
    from security_runtime.hook_runtime import HookCoordinator
    root = Path(os.environ['SECURITY_RUNTIME_WORKSPACE']).resolve()
    if root.name != 'project' or not root.parent.name.startswith('p061-exact-'):
        raise RuntimeError('DISPOSABLE_FIXTURE_ONLY')
    raw, fixed = fixture_bytes(os.environ['EXACTNESS_CASE'])
    holder = {}
    def factory(*args, **kwargs):
        kwargs['inline_agent_tickets'] = True
        holder['service'] = RemediationService(*args, **kwargs)
        return holder['service']
    server = create_server(remediation_factory=factory, hook_coordinator=HookCoordinator(cooldown_ms=0))
    @server.tool()
    def fixture_host_edit(task_ref: str, remediation_ref: str, prepared_attestation: str) -> dict:
        """Test Host implementation; no Runtime product editor is introduced."""
        service=holder['service'];target=root/'src/main/java/demo/CodeModeTlsService.java'
        with service.state.lock(root) as acquired:
            if not acquired: return {'status':'HOST_EDIT_BUSY'}
            _, _, _, record=service._reference(root,remediation_ref,task_ref)
            item=service.agent_tickets.items.get(record['token_hash'])
            if (record['token_hash'] not in service.prepared or not item
                    or item['ticket']['prepared_attestation']!=prepared_attestation):
                return {'status':'HOST_TICKET_MISMATCH'}
            with native_target_edit(target) as (content, commit):
                if content!=raw: return {'status':'HOST_TARGET_CHANGED'}
                commit(fixed)
        return {'status':'HOST_EDIT_APPLIED','target_reads':1,'searches':0,'native_edits':1}
    @server.tool()
    def fixture_episode_state(task_ref: str, remediation_ref: str) -> dict:
        """Source-free acceptance inspection, outside the measured Core cycle."""
        service=holder['service']
        with service.state.lock(root) as acquired:
            if not acquired: return {'status':'BUSY'}
            _, _, _, record=service._reference(root,remediation_ref,task_ref)
            return {'stage':record['phase'],'resolution_status':(record.get('resolution') or {}).get('status')}
    server.run(transport='stdio')


async def trial(case, source, *, before=False, recurrence=False):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    raw, fixed=fixture_bytes(case);episodes=[]
    with tempfile.TemporaryDirectory(prefix='p061-exact-') as temporary:
        parent=Path(temporary).resolve();root=parent/'project';root.mkdir()
        subprocess.run(['git','init',str(root)],check=True,capture_output=True)
        target=root/'src/main/java/demo/CodeModeTlsService.java';target.parent.mkdir(parents=True)
        target.write_bytes(SAFE.encode())
        env=dict(os.environ,PYTHONPATH=str(source),SECURITY_RUNTIME_WORKSPACE=str(root),
            SECURITY_RUNTIME_STATE_DIR=str(parent/'state'),SECURITY_RUNTIME_OFFLINE='1',
            SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1',EXACTNESS_CASE=case)
        params=StdioServerParameters(command=sys.executable,args=[str(Path(__file__).resolve()),'--fixture-server'],
                                    cwd=root,env=env)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(params,errlog=errors) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize();calls=[]
                    async def call(name,args):
                        response=await client.call_tool(name,invocation_claims(name, args))
                        assert not response.isError,name
                        data=response.structuredContent or json.loads(response.content[0].text)
                        calls.append(name);return data.get('result',data)
                    claims={'event':'PostToolUse','workspace_path':str(root),
                            'session_id':'exactness-trial','tool_name':'apply_patch'}
                    assert (await call('handle_hook_event',claims))['status']=='BASELINE_ESTABLISHED'
                    previous=None
                    for number in range(1,3 if recurrence else 2):
                        target.write_bytes(raw);offset=len(calls);started=time.perf_counter()
                        hook=await call('handle_hook_event',claims);grant=hook['remediation']
                        assert grant['action']=='AUTO_FIX' and grant['episode_number']==number
                        ticket=grant['agent_fix_ticket'];args={k:ticket[k] for k in ('task_ref','remediation_ref')}
                        assert args==grant['prepare']['arguments']
                        if previous:
                            assert ticket['episode_id']!=previous['episode_id']
                            assert ticket['origin_scan_id']!=previous['origin_scan_id']
                        host=await call('fixture_host_edit',{**args,'prepared_attestation':ticket['prepared_attestation']})
                        assert host['status']=='HOST_EDIT_APPLIED' and target.read_bytes()==fixed
                        post=await call('handle_hook_event',claims);decision=post['remediation']
                        elapsed=(time.perf_counter()-started)*1000
                        diag=decision['agent_fix_ticket_diagnostics'];exact=diag.get('exact_target_verification')
                        negative=before or 'neighbor' in case
                        if negative:
                            assert decision['reason_code']!='SCANNER_VERIFIED_RESOLVED'
                            if before: assert diag['ticket_stale_reason']=='TICKET_TARGET_NOT_EXACT'
                            else: assert exact['outside_envelope_changed']
                        else:
                            receipt=decision['security_verification']
                            assert receipt['status']=='SCANNER_VERIFIED_RESOLVED' and receipt['phase']=='CLOSED'
                            assert receipt['task_ref']==args['task_ref'] and receipt['grant_id']==grant['grant_id']
                            assert decision['next_action']=='RETURN_TO_HOST' and exact['status']=='MATCHED'
                        cycle_calls=calls[offset:]
                        assert cycle_calls.count('prepare_task_fix')==0 and len(cycle_calls)==3
                        assert diag['prepare_task_fix_call_count']==0 and target.read_bytes()==fixed
                        providers=[r['scanner_diagnostics']['providers'] for r in (hook,post)]
                        invocations={engine:sum(p[engine]['counts']['process_invocations'] for p in providers)
                                     for engine in ('semgrep','gitleaks')}
                        rechecks=decision.get('verification',{}).get('scanner_diagnostics',[])
                        invocations['original_rule_recheck']=sum(r['counts']['process_invocations'] for r in rechecks)
                        assert invocations['semgrep']==invocations['gitleaks']==2
                        assert invocations['original_rule_recheck']==(0 if negative else 1)
                        state=await call('fixture_episode_state',args)
                        assert state['stage']==('ESCALATED' if negative else 'CLOSED')
                        assert state['resolution_status']==(None if negative else 'SCANNER_VERIFIED_RESOLVED')
                        assert post['resolved_families']>=1
                        episodes.append({'number':number,'reason_code':decision['reason_code'],'stage':state['stage'],
                            'ticket_stale_reason':diag['ticket_stale_reason'],'exact_target_verification':exact,
                            'scanner_invocations':invocations,'prepare_calls':0,'runtime_mcp_calls':2,
                            'host_fixture_rpc_calls':1,'host_target_reads':1,'host_searches':0,
                            'diagnostic_state_rpc_after_measurement':1,
                            'reference_integrity':'ORIGINAL_VALUES_EXACT; NO_RECONSTRUCTION',
                            'ticket_bytes':len(json.dumps(ticket,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()),
                            'driver_wall_ms':round(elapsed,3),'timing_ms':post['timing_ms'],
                            'remediation_cycle_wall_ms':post.get('remediation_cycle_wall_ms'),
                            'remediation_cycle_breakdown_ms':post.get('remediation_cycle_breakdown_ms')})
                        if previous:
                            rejected=await call('prepare_task_fix',{k:previous[k] for k in ('task_ref','remediation_ref')})
                            assert rejected.get('status')!='READY_FOR_HOST_FIX'
                            episodes[-1]['old_episode_refs_rejected_after_measurement']=True
                        previous=ticket
            errors.seek(0);assert '0x80131506' not in errors.read()
    return {'case':case,'source':'HASH_VERIFIED_P06_WHEEL' if before else 'CURRENT_P061','episodes':episodes}


async def main(args):
    started=time.perf_counter();root=Path(__file__).resolve().parents[1];baseline=Path(args.baseline).resolve()
    assert baseline==root/'.security-runtime/p061-baseline' and (baseline/'security_runtime/agent_fix_ticket.py').is_file()
    cases=[await trial('lf',baseline,before=True)]
    for case in ('lf','crlf','lf-bom','crlf-bom','crlf-mixed-bom','lf-statement','lf-canonical','lf-neighbor'):
        cases.append(await trial(case,root/'src',recurrence=case=='crlf-mixed-bom'))
    result={'status':'PASS','duration_seconds':round(time.perf_counter()-started,2),'cases':cases,
        'transport':'ACTUAL_LOCAL_MCP_STDIO','scanner':'ACTUAL_MANAGED_OFFLINE',
        'host':'SIMULATED_NATIVE_EDIT; NOT_DESKTOP','actual_desktop':'NOT_RUN_THIS_SCOPE',
        'network':False,'model':False,'sleep_injected':False,'deep_verification':False,'target_build':False,
        'active_runtime_replaced':False,'source_persisted':False,'opaque_references_persisted':False}
    Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'status':'PASS','duration_seconds':result['duration_seconds']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-server',action='store_true')
    parser.add_argument('--baseline');parser.add_argument('--output');args=parser.parse_args()
    if args.fixture_server: fixture_server()
    else: asyncio.run(main(args))

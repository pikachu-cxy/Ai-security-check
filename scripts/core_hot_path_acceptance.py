"""Offline real MCP/scanner Core trial; driver stands in for host edits only."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from remediation_episode_acceptance import SAFE, UNSAFE
from codex_hook_fixture import invocation_claims
from remediation_acceptance import assert_closed_scanner_proof

# Exercise explicit prepare/Stop fallback. A comment prevents inline tickets;
# already prepared tickets correctly do not request another prepare handoff.
UNSAFE = UNSAFE.replace('-> true);', '-> true); // preserve fixture comment')


async def run():
    started=time.perf_counter()
    calls=[]
    with tempfile.TemporaryDirectory(prefix='asr-core-') as directory:
        parent=Path(directory).resolve(); root=parent/'project'; root.mkdir()
        subprocess.run(['git','init',str(root)],check=True,capture_output=True)
        path=root/'src/main/java/demo/CodeModeTlsService.java'
        path.parent.mkdir(parents=True); path.write_text(SAFE,encoding='utf-8')
        env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(root),
                 SECURITY_RUNTIME_STATE_DIR=str(parent/'state'),SECURITY_RUNTIME_OFFLINE='1',
                 SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1')
        params=StdioServerParameters(command=sys.executable,args=['-m','security_runtime.cli','mcp'],env=env,cwd=root)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(params,errlog=errors) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize()
                    async def call(name,arguments):
                        assert name in {'handle_hook_event','confirm_remediation','prepare_task_fix','verify_task_fix','handle_stop_event'}
                        response=await client.call_tool(name,invocation_claims(name, arguments))
                        assert not response.isError,name
                        data=response.structuredContent or json.loads(response.content[0].text)
                        data=data.get('result',data)
                        calls.append(dict(tool=name,status=data.get('status'),timing_ms=data.get('timing_ms'),
                            runtime_instance_id=data.get('runtime_instance_id'), cache_generation=data.get('cache_generation'),
                            remediation_cycle_wall_ms=data.get('remediation_cycle_wall_ms'),
                             remediation_cycle_measurement=data.get('remediation_cycle_measurement'),
                             remediation_cycle_timepoints_ms=data.get('remediation_cycle_timepoints_ms'),
                             remediation_cycle_breakdown_ms=data.get('remediation_cycle_breakdown_ms'),
                             remediation_cycle_detail_ms=data.get('remediation_cycle_detail_ms'),
                             remediation_cycle_boundary=data.get('remediation_cycle_boundary'),
                             remediation_cycle_breakdown_measurement=data.get('remediation_cycle_breakdown_measurement'),
                            scanner_diagnostics=data.get('scanner_diagnostics'),
                            security_rescan_diagnostics=data.get('remediation',{}).get('verification',{}).get('scanner_diagnostics')))
                        return data
                    claims=dict(event='PostToolUse',workspace_path=str(root),session_id='core-trial',tool_name='apply_patch')
                    assert (await call('handle_hook_event',claims))['status']=='BASELINE_ESTABLISHED'
                    await asyncio.sleep(1.1)
                    path.write_text(SAFE+'\n// ordinary safe edit\n',encoding='utf-8')
                    safe=await call('handle_hook_event',claims)
                    assert safe['new_families']==0 and safe['remediation']['action']=='NONE'
                    for index in (2,3):
                        await asyncio.sleep(1.1)  # Existing Hook cooldown, not Scanner benchmark time.
                        path.write_text(SAFE+f'\n// ordinary safe edit {index}\n',encoding='utf-8')
                        next_safe=await call('handle_hook_event',claims)
                        assert next_safe['new_families']==0 and next_safe['remediation']['action']=='NONE'
                        assert next_safe['runtime_instance_id']==safe['runtime_instance_id']
                        for provider in ('semgrep','gitleaks'):
                            assert next_safe['scanner_diagnostics']['providers'][provider]['cache']['version_probe']=='HIT'
                    episodes=[]; original=None; family=None
                    for number in (1,2):
                        await asyncio.sleep(1.1)
                        path.write_text(UNSAFE,encoding='utf-8')
                        cycle_started=time.perf_counter()
                        detected=await call('handle_hook_event',claims)
                        pending=detected['remediation']
                        assert pending['action']=='CONFIRM_REQUIRED' and 'prepare' not in pending
                        assert path.read_text()==UNSAFE
                        # Simulated explicit user choice, renewed for recurrence.
                        grant=await call('confirm_remediation',dict(pending['confirmation']['arguments'],approve=True))
                        assert grant['authorization_kind']=='USER_CONFIRMED'
                        assert grant['action']=='AUTO_FIX' and grant['episode_number']==number
                        assert 'prepare_functional_verification' not in grant['guidance']
                        assert detected['runtime_instance_id']==safe['runtime_instance_id']
                        assert detected['remediation_cycle_measurement']['status']=='IN_PROGRESS'
                        values=dict(grant['prepare']['arguments'])  # Opaque, exact values only.
                        if original:
                            assert values!=original and grant['finding_family']==family
                            assert (await call('prepare_task_fix',original))['reason_code']=='REPAIR_GRANT_REJECTED'
                        if number == 2:
                            stop=await call('handle_stop_event',dict(event='Stop',workspace_path=str(root),
                                           session_id='core-trial',stop_hook_active=False))
                            assert stop['status']=='CONTINUATION_REQUIRED'
                            assert not any(stop['execution'].values())
                            retained=json.loads(stop['reason'][stop['reason'].index('{'):])
                            assert retained==grant['prepare']  # Exact original handoff, no reconstruction.
                        packet=await call('prepare_task_fix',values)
                        assert packet['status']=='READY_FOR_HOST_FIX'
                        await asyncio.sleep(1.1)
                        path.write_text(SAFE,encoding='utf-8')  # Simulated host edit, never Runtime.
                        closed=await call('handle_hook_event',claims)
                        driver_cycle_ms=round((time.perf_counter()-cycle_started)*1000,3)
                        receipt=closed['remediation']['security_verification']
                        assert receipt['status']=='SCANNER_VERIFIED_RESOLVED' and receipt['phase']=='CLOSED'
                        assert receipt['task_ref']==values['task_ref'] and receipt['grant_id']==grant['grant_id']
                        assert closed['remediation']['next_action']=='RETURN_TO_HOST'
                        assert closed['remediation_cycle_measurement']['status']=='OBSERVED'
                        points=closed['remediation_cycle_timepoints_ms']
                        breakdown=closed['remediation_cycle_breakdown_ms']
                        assert closed['remediation_cycle_boundary']['host_continuation_source']==(
                            'STOP_GUARD' if number==2 else 'PREPARE_REQUEST')
                        assert closed['remediation_cycle_breakdown_measurement']['status']=='OBSERVED'
                        assert abs(sum(breakdown.values())-closed['remediation_cycle_wall_ms'])<=0.01
                        for unknown in ('host_edit_completed','host_fix_started','initial_hook_response_sent',
                                         'host_received_advisory'):
                             assert points[unknown] is None
                        assert 0<closed['remediation_cycle_wall_ms']<=driver_cycle_ms+5
                        assert all(v is not None and v>=0 for v in closed['timing_ms'].values())
                        checked=await call('verify_task_fix',values)
                        assert checked['verification_status']=='SCANNER_VERIFIED_RESOLVED'
                        assert_closed_scanner_proof(closed, checked, values, grant['grant_id'])
                        assert 'functional_status' not in checked
                        assert checked['remediation_cycle_wall_ms']==closed['remediation_cycle_wall_ms']
                        assert checked['remediation_cycle_timepoints_ms']==points
                        assert checked['remediation_cycle_breakdown_ms']==breakdown
                        assert not list(path.parent.glob('*.class'))
                        episodes.append(dict(number=number,stage=receipt['phase'],timing_ms=closed['timing_ms'],
                                              remediation_cycle_wall_ms=closed['remediation_cycle_wall_ms'],
                                               driver_cycle_wall_ms=driver_cycle_ms,
                                               cycle_timepoints_ms=points, cycle_breakdown_ms=breakdown,
                                               cycle_detail_ms=closed['remediation_cycle_detail_ms'],
                                               cycle_boundary=closed['remediation_cycle_boundary'],
                                             security=receipt['status'],next_action=closed['remediation']['next_action']))
                        original=original or values;family=family or grant['finding_family']
            errors.seek(0)
            assert '0x80131506' not in errors.read()
    return dict(status='PASS',transport='ACTUAL_LOCAL_MCP_STDIO',
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE',calls=calls,episodes=episodes,
                actual_desktop='PENDING_CORE_HOST_TRIAL',host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',
                timing_contract='core-hook-timing-v1',functional_calls=0,build_test_sandbox=False,
                runtime_source_edit=False,network=False,model=False,raw_references_persisted=False,
                duration_seconds=round(time.perf_counter()-started,2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);args=parser.parse_args()
    result=asyncio.run(run())
    if args.output: args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

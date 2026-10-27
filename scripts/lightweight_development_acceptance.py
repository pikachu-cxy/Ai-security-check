"""Real MCP/scanner acceptance in a disposable 6000-file fixture.

Uses a synthetic host and isolated Codex settings. Never modifies user settings,
downloads components, executes fixture source, or measures desktop/model speed.
An incomplete run retains its private fixture for diagnosis.
"""
import argparse
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from security_runtime.closeout_state import readonly_uri

SAFE = 'export function compute(value) { return value + 1; }\n'
RISK = 'export function compute(expression) { const calculate = new Function(`return (${expression});`); return calculate(); }\n'


def checked(condition, message):
    if not condition:
        raise AssertionError(message)


def unpack(response):
    checked(not response.isError, 'MCP returned an error')
    if response.structuredContent is not None:
        return response.structuredContent
    for block in response.content:
        if block.type == 'text':
            return json.loads(block.text)
    raise AssertionError('MCP result unavailable')


async def run(output=None, wait_seconds=0):
    parent = Path(tempfile.mkdtemp(prefix='lightweight-mcp-6000-')).resolve()
    print('Disposable acceptance fixture: '+str(parent), file=sys.stderr, flush=True)
    root, private, home = parent/'project', parent/'private', parent/'codex-home'
    root.mkdir()
    root.joinpath('src').mkdir()
    root.joinpath('bulk').mkdir()
    names = ['app.js', 'legacy.js', 'deleted.js', 'unobserved.js']
    for name in names:
        (root/'src'/name).write_text(RISK if name == 'unobserved.js' else SAFE)
    for i in range(5996):
        (root/'bulk'/f'm{i:05}.js').write_text(f'export const value = {i};\n')
    def git(*args):
        subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True,timeout=30)
    git('init','-q')
    git('add','.')
    git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
    env = dict(os.environ, CODEX_HOME=str(home), SECURITY_RUNTIME_STATE_DIR=str(private),
        SECURITY_RUNTIME_SKILLS_DIR=str(parent/'skills'), SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_WORKSPACE='', SECURITY_RUNTIME_GLOBAL='0')
    env.pop('SECURITY_RUNTIME_CODEX_HOME', None)
    env.pop('SECURITY_RUNTIME_INTEGRATION', None)
    setup = subprocess.run([sys.executable,'-m','security_runtime.cli','setup','codex',
        '--dev','--path',str(root),'--json'],env=env,cwd=parent,capture_output=True,timeout=120)
    checked(setup.returncode == 0, 'Isolated setup failed; fixture retained')
    configured = json.loads(setup.stdout)
    checked(configured['mcp']['status'] == 'CONFIGURED', 'Isolated MCP not configured')
    entry = tomllib.loads((home/'config.toml').read_text())['mcp_servers']['ai_security_runtime']
    params = StdioServerParameters(command=entry['command'],args=entry['args'],env={**env,**entry['env']})
    timings, cases, waits = {}, [], []
    def scans():
        rows = []
        for path in private.rglob('scans.db'):
            with sqlite3.connect(readonly_uri(path),uri=True) as db:
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'").fetchone():
                    rows.extend(db.execute('SELECT id,data FROM scans').fetchall())
        return rows
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write,read_timeout_seconds=timedelta(seconds=180)) as client:
            await client.initialize()
            async def call(name,**args):
                start=time.perf_counter()
                result=unpack(await client.call_tool(name,args))
                timings.setdefault(name,[]).append(1000*(time.perf_counter()-start))
                return result
            common={'workspace_path':str(root)}
            session='isolated-fixture-'+uuid.uuid4().hex
            ready=await call('handle_readiness_event',event='SessionStart',session_id=session,**common)
            checked(ready['status']=='CONNECTED','Startup not connected')
            checked(not ready['startup_comparison_baseline']['created'],'Unexpected startup baseline')
            token=ready['task_session_ref']
            routed={**common,'session_ref':token}
            info=await call('get_runtime_info',view='summary')
            if wait_seconds:
                checked(info['features'].get('development_check_wait','').startswith('bounded-closeout-wait-v1;'),
                    'Bounded closeout wait capability missing')
                schema=next(tool.inputSchema for tool in (await client.list_tools()).tools
                    if tool.name=='finish_development_check')
                checked(schema['properties']['wait_seconds'].get('maximum')==25,
                    'Bounded wait schema unavailable')
            async def hook(tool,inputs):
                result=await call('handle_hook_event',event='PostToolUse',session_id=session,
                    turn_id='synthetic-fixture-turn',tool_use_id=uuid.uuid4().hex,
                    tool_name=tool,tool_input=inputs,**common)
                checked(not result.get('scanner_run'),'Editing/readonly hook started a scan')
                return result
            async def begin(key):
                result=await call('begin_development_check',task_key=key,**routed)
                checked(result.get('check_ref') is not None,'Missing observed-edit reference')
                checked(not result['baseline_created'],'Unexpected task baseline')
                return result['check_ref']
            async def get(ref):
                return await call('get_development_check',check_ref=ref,**routed)
            async def finish(ref):
                options={'wait_seconds':wait_seconds} if wait_seconds else {}
                submitted=await call('finish_development_check',check_ref=ref,**routed,**options)
                if wait_seconds:
                    checked(submitted.get('closeout_wait',{}).get('contract')=='bounded-closeout-wait-v1',
                        'Bounded wait receipt missing')
                    checked(not submitted['closeout_wait']['scanner_dispatched_by_wait'],
                        'Wait dispatched extra scanner work')
                    waits.append(dict(submitted['closeout_wait'],status=submitted['status'],
                        terminal_without_extra_read=submitted['status'] not in {'QUEUED','RUNNING'}))
                    if submitted['status'] not in {'QUEUED','RUNNING'}:
                        return submitted
                deadline=time.monotonic()+180
                while time.monotonic()<deadline:
                    result=await get(ref)
                    if result['status'] not in {'QUEUED','RUNNING'}:
                        return result
                    await asyncio.sleep(1)
                raise AssertionError('Worker timed out; fixture retained')
            def saved_case(label,result):
                checked(not result['scope']['full_project'],'Scope expanded to project')
                checked(not result['baseline_created'],'Baseline created')
                cases.append(dict(name=label,status=result['status'],paths=result['scope']['paths'],
                    gaps=result['gaps'],dirty_seq=result['dirty_seq'],scanned_seq=result['scanned_seq'],
                    findings=(result.get('static_result') or {}).get('finding_count'),
                    scanner_runs=[{'scanner':r['scanner'],'status':r['status']} for r in
                        (result.get('static_result') or {}).get('scanner_runs',[])]))
            for _ in range(10):
                await hook('Bash',{'command':'git status --short'})
                stop=await call('handle_stop_event',event='Stop',session_id=session,
                    stop_hook_active=False,**common)
                checked(not stop.get('scanner_run'),'Stop started a scan')
            checked(not scans(),'Quiet operations created scans')
            checked(not list(private.rglob('task-security.db')),'Strict task store created')
            cases.append({'name':'quiet-startup-readonly-stop','scanner_results':0,'samples_per_operation':10})
            ref=await begin('burst')
            for index in range(100):
                (root/'src/app.js').write_text(f'export const value = {index};\n')
                event=await hook('Write',{'file_path':str(root/'src/app.js')})
                checked(event.get('development_check_ref')==ref,'Hook/check reference mismatch')
            checked(not scans(),'Burst started scanning before finish')
            result=await finish(ref)
            checked(result['dirty_seq']==result['scanned_seq']==100,'Burst sequence mismatch')
            checked(len(scans())==1,'Burst did not merge into one scan')
            checked(result['scope']['paths']==['src/app.js'],'Unobserved file selected')
            checked((result.get('static_result') or {}).get('finding_count')==0,'Unobserved risk leaked into selected scan')
            saved_case('100-edits-one-finish',result)
            for _ in range(10):
                await get(ref)
            checked(len(scans())==1,'Result read rescanned')
            (root/'src/app.js').write_text('export const value = 101;\n')
            await hook('Write',{'file_path':str(root/'src/app.js')})
            result=await get(ref)
            checked(result['dirty_seq']>result['scanned_seq'],'New edit hidden by old result')
            await asyncio.sleep(2)
            checked(len(scans())==1,'New edit automatically scanned')
            result=await finish(ref)
            checked(result['dirty_seq']==result['scanned_seq']==101,'Second finish missed new edit')
            checked(len(scans())==2,'Second finish missing scan')
            saved_case('edit-after-finish',result)
            ref=await begin('multi-file')
            for name in ('one.js','two.js'):
                (root/'src'/name).write_text(SAFE)
            patch='*** Begin Patch\n*** Add File: src/one.js\n+'+SAFE.rstrip()+'\n*** Add File: src/two.js\n+'+SAFE.rstrip()+'\n*** End Patch'
            await hook('apply_patch',{'command':patch})
            result=await finish(ref)
            checked(result['scope']['paths']==['src/one.js','src/two.js'],'Multi-file scope mismatch')
            saved_case('multi-file-patch',result)
            ref=await begin('rename-delete')
            (root/'src/legacy.js').rename(root/'src/renamed.js')
            (root/'src/deleted.js').unlink()
            patch='*** Begin Patch\n*** Update File: src/legacy.js\n*** Move to: src/renamed.js\n@@\n-old\n+new\n*** Delete File: src/deleted.js\n*** End Patch'
            await hook('apply_patch',{'command':patch})
            result=await finish(ref)
            checked(result['scope']['paths']==['src/deleted.js','src/legacy.js','src/renamed.js'],'Rename/delete scope mismatch')
            checked('DELETED_PATH_SEMANTICS_NOT_REVIEWED' in result['gaps'],'Deletion gap missing')
            saved_case('rename-and-delete',result)
            before=len(scans())
            ref=await begin('unknown-shell')
            await hook('Bash',{'command':'python opaque_edit_script.py'})
            result=await finish(ref)
            checked(result['scope']['scope_unknown'],'Unknown shell scope hidden')
            checked(not result['scope']['paths'] and len(scans())==before,'Unknown shell triggered project fallback')
            saved_case('unknown-shell',result)
            ref=await begin('observed-risk')
            (root/'src/risk.js').write_text(RISK)
            await hook('Write',{'file_path':str(root/'src/risk.js')})
            result=await finish(ref)
            checked(result['dirty_seq']==result['scanned_seq'],'Observed risk not checked')
            checked((result.get('static_result') or {}).get('finding_count',0)>0,'Observed dynamic-code fixture not reported')
            saved_case('observed-risk',result)
            checked(not list(private.rglob('task-security.db')),'Strict task store created')
            saved=scans()
            checked(len(saved)==5,'Unexpected scan count')
            for _,raw in saved:
                scan=json.loads(raw)
                inputs=scan.get('scan_context',{}).get('input_files')
                checked(isinstance(inputs,list),'Actual scanner input list unavailable')
                checked('src/unobserved.js' not in inputs,'Unobserved input scanned')
            report=dict(scope='ISOLATED_6000_FILE_PROJECT; REAL_MCP_AND_LOCAL_SCANNERS; SYNTHETIC_HOST',
                desktop_dialogue_acceptance=False,model_or_dialogue_speedup_measured=False,
                files=6000,build=info['build_identity'],cases=cases,scan_results=len(saved),
                finish_wait_seconds=wait_seconds,finish_wait_receipts=waits,
                tool_roundtrip_ms={name:{'samples':len(values),'median':round(statistics.median(values),3),
                    'maximum':round(max(values),3)} for name,values in timings.items()})
            if output is not None:
                Path(output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)
    shutil.rmtree(parent)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,help='Optional JSON report outside the disposable fixture')
    parser.add_argument('--wait-seconds',type=int,default=0,
        help='Optional bounded closeout wait, 0-25 seconds; default keeps the original async path')
    args=parser.parse_args()
    if not 0 <= args.wait_seconds <= 25:
        parser.error('--wait-seconds must be between 0 and 25')
    asyncio.run(run(args.output,args.wait_seconds))

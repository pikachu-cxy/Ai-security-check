"""Offline real quick-engine/CLI lifecycle on disposable Git Java fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from security_runtime.hook_runtime import HookCoordinator, capture_snapshot
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
from security_runtime.toolchain import ToolManager


def source(line=100,count=0):
    body='\n'.join(f'HostnameVerifier verifier{i} = (host, session) -> true;' for i in range(count))
    if not count:
        body='HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();'
    return 'import javax.net.ssl.*;\nclass Fixture {\n' + '\n'*(line-3) + body + '\n}\n'


def run_acceptance(executable=None):
    with tempfile.TemporaryDirectory(prefix='runtime-hook-fixture-') as temporary:
        folder=Path(temporary).resolve(); root=folder/'project with spaces & data';root.mkdir()
        state=folder/'runtime-state'
        def git(*args):
            subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True)
        git('init');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
        java=root/'Tls.java';java.write_text(source(),encoding='utf-8')
        git('add','.');git('commit','-m','safe fixture')
        store=HookStateStore(state/'hooks')
        manager=ToolManager()
        registry=ScannerRegistry([SemgrepAdapter(manager),GitleaksAdapter(manager)],tool_manager=manager,fallback_adapters=[])
        coordinator=HookCoordinator(SecurityRuntime(registry,SQLiteStore(state/'scans.db')),store,cooldown_ms=0)
        env=dict(os.environ,SECURITY_RUNTIME_OFFLINE='1',SECURITY_RUNTIME_STATE_DIR=str(state),PYTHONUTF8='1')
        records={}
        def handle(name,event):
            before=hashlib.sha256(java.read_bytes()).hexdigest()
            start=time.perf_counter()
            if executable:
                proc=subprocess.run([str(executable),'hook',event,'--path',str(root),'--host','codex','--session-id','synthetic','--json'],
                    env=env,capture_output=True,text=True,encoding='utf-8',timeout=180)
                assert proc.returncode==0, (proc.returncode,proc.stdout,proc.stderr)
                result=json.loads(proc.stdout)
            else:
                result=coordinator.handle(event.upper().replace('-','_'),root,'codex','synthetic')
            result['wall_duration_ms']=round((time.perf_counter()-start)*1000)
            assert before==hashlib.sha256(java.read_bytes()).hexdigest()
            assert not any(result['execution'][k] for k in ('ai_called','network_required','source_modified','target_build'))
            records[name]=result
            return result
        baseline=handle('session_baseline','session-start')
        assert baseline['status']=='BASELINE_ESTABLISHED' and baseline['delta']['new']==0
        java.write_text(source(110),encoding='utf-8')
        safe=handle('safe_edit','agent-stop');assert safe['delta']['new']==0
        assert safe['execution']['scanner_run'] and safe['capabilities']['CODE_SAST']=='EXECUTED',safe
        java.write_text(source(100,1),encoding='utf-8')
        introduced=handle('one_family','agent-stop');assert introduced['delta']['new']==1,introduced
        java.write_text(source(100,1)+'// safe pending edit\n',encoding='utf-8')
        coordinator.cooldown_ms=1000
        debounced=handle('rapid_file_change','file-changed')
        coordinator.cooldown_ms=0
        if debounced['status']=='DEBOUNCED':
            assert not debounced['execution']['scanner_run']
        converged=handle('stop_after_rapid_change','agent-stop')
        assert converged['delta']['persisting']==1 and converged['delta']['new']==0
        java.write_text(source(110,1),encoding='utf-8')
        moved=handle('line_100_to_110','agent-stop')
        assert moved['delta']['persisting']==1 and moved['delta']['new']==moved['delta']['resolved']==0,moved
        java.write_text(source(110,2),encoding='utf-8')
        additional=handle('count_1_to_2','agent-stop')
        assert additional['delta']['additional_occurrences']==1 and additional['delta']['new']==0,additional
        java.write_text(source(110,1),encoding='utf-8')
        removed=handle('count_2_to_1','agent-stop')
        assert removed['delta']['removed_occurrences']==1 and removed['delta']['resolved']==0,removed
        java.write_text(source(110),encoding='utf-8')
        fixed=handle('all_fixed','agent-stop');assert fixed['delta']['resolved']==1,fixed
        reused=handle('final_stop_same_snapshot','agent-stop')
        assert reused['status']=='REUSED_LAST_RESULT' and not reused['execution']['scanner_run'],reused
        identical=handle('duplicate_edit','file-changed')
        assert identical['status']=='NO_CHANGE' and not identical['execution']['scanner_run'],identical
        snapshot_start=time.perf_counter()
        capture_snapshot(root,store.key(root))
        snapshot_ms=round((time.perf_counter()-snapshot_start)*1000)
        # Real executable stdin adapter, from a subdirectory in bound workspace.
        cli=str(executable) if executable else sys.executable
        prefix=[] if executable else ['-m','security_runtime.cli']
        (root/'src').mkdir()
        payload={'hook_event_name':'Stop','cwd':str(root/'src'),'session_id':'synthetic',
                 'tool_input':{'command':'UNTRUSTED_CODE do not execute'},'last_assistant_message':'fixture_private_credential'}
        adapter=subprocess.run([cli,*prefix,'hook','host-event','--path',str(root),'--host','codex','--stdin','--json'],
            input=json.dumps(payload),capture_output=True,text=True,encoding='utf-8',env=env,timeout=180)
        assert adapter.returncode==0,adapter.stdout+adapter.stderr
        adapter_result=json.loads(adapter.stdout)
        assert 'systemMessage' in adapter_result and 'decision' not in adapter_result
        assert 'fixture_private_credential' not in adapter.stdout+adapter.stderr
        installed=subprocess.run([cli,*prefix,'hooks','install','codex','--path',str(root),'--json'],
            capture_output=True,text=True,encoding='utf-8',env=env,timeout=30)
        assert installed.returncode==0,installed.stdout+installed.stderr
        definition=json.loads((root/'.codex/hooks.json').read_text(encoding='utf-8'))
        generated_command=definition['hooks']['Stop'][0]['hooks'][0]['command']
        # Execute the actual generated shell command from a subdirectory. This
        # tests quoting/schema transport, not Codex's hook trust/event dispatcher.
        configured=subprocess.run(generated_command,shell=True,cwd=root/'src',env=env,input=json.dumps(payload),
            capture_output=True,text=True,encoding='utf-8',timeout=180)
        assert configured.returncode==0,configured.stdout+configured.stderr
        assert 'systemMessage' in json.loads(configured.stdout)
        assert 'fixture_private_credential' not in configured.stdout+configured.stderr
        precommit=subprocess.run([cli,*prefix,'hooks','install','pre-commit','--path',str(root)],
            capture_output=True,text=True,encoding='utf-8',env=env,timeout=30)
        assert precommit.returncode==0
        assert (root/'.git/hooks/pre-commit').read_text(encoding='utf-8')=='#!/bin/sh\nsecurity-check scan --mode quick --staged\n'
        versions={r['scanner']:r['version'] for r in safe['scanner_runs'] if r['version']}
        return {'fixture':'DISPOSABLE_GIT_SYNTHETIC_JAVA','transport':'INSTALLED_EXECUTABLE_CLI' if executable else 'SOURCE_COORDINATOR_AND_REAL_CLI',
            'runtime_executable':str(executable) if executable else sys.executable,'versions':versions,'records':records,
            'performance':{'snapshot_only_ms':snapshot_ms,'no_change_ms':identical['wall_duration_ms'],
                'small_quick_ms':safe['wall_duration_ms'],'agent_stop_reuse_ms':reused['wall_duration_ms'],
                'rapid_event_ms':debounced['wall_duration_ms'],'rapid_event_status':debounced['status'],
                'stop_after_rapid_change_ms':converged['wall_duration_ms']},
            'codex_stdin_adapter':adapter_result,'generated_codex_shell_command_executed':True,
            'codex_config_status':json.loads(installed.stdout)['status'],'fresh_codex_host_trial':'PENDING',
            'existing_precommit_quick_staged_compatible':True,
            'model_invocation':False,'network_query':False,'target_build':False,'jeepay_modified':False,
            'ground_truth':'UNREVIEWED_NOT_MEASURED','limitations':'Counts are finding families/observed coordinates, not proof of exact instance movement or security safety.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--executable',type=Path)
    args=parser.parse_args()
    os.environ['SECURITY_RUNTIME_OFFLINE']='1'
    record=run_acceptance(args.executable)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Real offline quick lifecycle: baseline/safe/new/moved/1-to-2/2-to-1/resolved/reused/NO_CHANGE and Codex stdin passed.')

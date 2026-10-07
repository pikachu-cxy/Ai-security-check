"""Actual installed command transport + managed offline Scanner, simulated Cursor."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import venv


def main():
    root=Path(__file__).resolve().parents[1]
    start=time.perf_counter()
    wheel=root/'dist/cursor-host-adapter/ai_security_runtime-0.3.1-py3-none-any.whl'
    with tempfile.TemporaryDirectory(prefix='cursor local fixture ') as directory:
        base=Path(directory);venv.EnvBuilder(with_pip=True,system_site_packages=True).create(base/'candidate')
        python=base/'candidate'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        env={**os.environ,'PYTHONUTF8':'1','SECURITY_RUNTIME_OFFLINE':'1','PIP_NO_INDEX':'1',
             'SECURITY_RUNTIME_STATE_DIR':str(base/'state'),'SECURITY_RUNTIME_CURSOR_HOME':str(base/'cursor home'),
             'CODEX_HOME':str(base/'codex home')}
        for key in ('PYTHONPATH','SECURITY_RUNTIME_GLOBAL','SECURITY_RUNTIME_CODEX_HOME','CURSOR_CODE_REMOTE'):
            env.pop(key,None)
        def run(argv,**kwargs):
            p=subprocess.run(argv,capture_output=True,timeout=120,env=env,**kwargs)
            if p.returncode:
                raise RuntimeError('Fixture process failed: '+str(p.returncode))
            return p
        run([str(python),'-m','pip','install','--no-index','--no-deps','--force-reinstall',str(wheel)])
        def cli(*args):return json.loads(run([str(python),'-I','-m','security_runtime.cli',*args,'--json']).stdout)
        assert cli('setup','cursor','--scope','global')['overall']=='CONFIGURED'
        config=Path(env['SECURITY_RUNTIME_CURSOR_HOME'])/'hooks.json';installed=config.read_bytes()
        assert cli('setup','cursor','--scope','global')['changed'] is False
        assert cli('integration','repair','cursor','--scope','global')['changed'] is False
        assert config.read_bytes()==installed
        cmd=json.loads(installed)['hooks']['afterFileEdit'][0]['command']
        origin=run([str(python),'-I','-c','import security_runtime.cursor_hook as c; print(c.__file__)']).stdout.decode().strip()
        assert str(base/'candidate').lower() in origin.lower()
        project=base/'project space';project.mkdir();file=project/'A.java'
        safe=b'import javax.net.ssl.HttpsURLConnection; class A { void configure(HttpsURLConnection connection) { connection.setConnectTimeout(2000); } }\n'
        file.write_bytes(safe)
        run(['git','init','-q',str(project)]);run(['git','-C',str(project),'add','.'])
        run(['git','-C',str(project),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'])
        env['CURSOR_PROJECT_DIR']=str(project)
        def event(name,**fields):
            data=dict(hook_event_name=name,workspace_roots=[str(project)],conversation_id='fixture-conversation',generation_id='fixture-generation',cursor_version='simulated')
            if name=='sessionStart':data.update(session_id='fixture-conversation',is_background_agent=False)
            elif name=='afterFileEdit':data.update(file_path=str(file),edits=[])
            elif name=='afterShellExecution':data.update(command='git status',output='fixture-secret-do-not-persist',duration=1,sandbox=False)
            else:data.update(status='completed',loop_count=0)
            data.update(fields)
            output=json.loads(run(cmd,shell=True,input=json.dumps(data).encode()).stdout)
            row=cli('hooks','recent','--path',str(project),'--limit','1')['records'][0]
            assert row['host']=='cursor' and row['host_claim_status']=='VALID'
            return output,row
        results=[]
        _,row=event('sessionStart');results.append(dict(case='SESSION_START',diagnostic=row))
        _,row=event('afterShellExecution');assert not row['scanner_run'];results.append(dict(case='READ_ONLY',diagnostic=row))
        file.write_bytes(safe.replace(b'2000',b'2100'))
        _,row=event('afterFileEdit');assert row['scanner_run'] and row['changed_file_count']==1;results.append(dict(case='ORDINARY_DELTA',diagnostic=row))
        _,row=event('afterFileEdit');assert not row['scanner_run'] and row['handler_status']=='NO_CHANGE'
        results.append(dict(case='SAME_BYTES',diagnostic=row))
        risk=safe.replace(b'connection.setConnectTimeout(2000);',b'connection.setHostnameVerifier((hostname, session) -> true);')
        file.write_bytes(risk);_,row=event('afterFileEdit');assert row['scanner_run'];results.append(dict(case='TLS_FINDING',diagnostic=row))
        sys.path.insert(0,str(root/'src'))
        from security_runtime.storage import ReadOnlySQLiteStore
        dbs=list((base/'state'/'cursor-workspaces').glob('*/scans.db'));assert len(dbs)==1
        scans=ReadOnlySQLiteStore(dbs[0])._rows('findings','SELECT data FROM findings',())
        assert any('ai-security.java.trust-all-hostname' in str(record) for record in scans)
        # Simulated Host's bounded edit, not automatic Cursor continuation proof.
        file.write_bytes(safe);_,row=event('afterFileEdit');assert row['scanner_run'];results.append(dict(case='HOST_MANUAL_FIX_RESCAN',diagnostic=row))
        _,row=event('stop');assert not row['scanner_run'];results.append(dict(case='STOP_CONVERGENCE',diagnostic=row))
        journal=base/'state'/'hook-diagnostics.db'
        assert b'fixture-secret-do-not-persist' not in journal.read_bytes()
        assert cli('integration','remove','cursor','--scope','global')['overall']=='REMOVED'
        assert cli('setup','cursor','--scope','global')['overall']=='CONFIGURED'
    report=dict(status='PASS',duration_seconds=round(time.perf_counter()-start,2),cases=results,
        host='SIMULATED_CURSOR',transport='INSTALLED_NATIVE_COMMAND_STDIO',scanner='ACTUAL_MANAGED_OFFLINE',
        clean_install='PASS_BORROWED_SYSTEM_DEPENDENCIES',cross_process_recent=True,actual_desktop='PENDING',
        continuation='PENDING_CURSOR_CONTINUATION_CAPABILITY',network=False,model=False,target_build=False,
        active_runtime_replaced=False,real_user_configuration_modified=False)
    (root/'docs/cursor-host-adapter-local-trial.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}))


if __name__=='__main__':main()

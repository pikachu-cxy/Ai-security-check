"""Record actual Jeepay CLI feedback and isolated stream/preparation acceptance."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
from unittest.mock import patch
from urllib.error import URLError

from security_runtime.cli_progress import CLIProgressRenderer
from security_runtime.human import diagnostic_zh
from security_runtime.progress import progress_context
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus


def command():
    executable=Path(sysconfig.get_path('scripts'))/('security-check.exe' if os.name=='nt' else 'security-check')
    return [str(executable)] if executable.is_file() else [sys.executable,'-m','security_runtime.cli']


def capture(args, root, env):
    started=time.monotonic()
    process=subprocess.Popen(command()+args,cwd=root,env=env,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
    output={'stdout':[],'stderr':[]};timeline=[];lock=threading.Lock()
    def read(stream,name):
        for line in stream:
            elapsed=round((time.monotonic()-started)*1000)
            with lock:
                output[name].append(line)
                timeline.append({'stream':name,'elapsed_ms':elapsed,'line':line.rstrip('\n')})
            if name=='stderr':
                print(f'{elapsed/1000:.1f}s {line.strip()}',flush=True)
        stream.close()
    readers=[threading.Thread(target=read,args=(process.stdout,'stdout')),threading.Thread(target=read,args=(process.stderr,'stderr'))]
    for reader in readers: reader.start()
    try:
        process.wait(timeout=180)
    finally:
        if process.poll() is None: process.kill()
        for reader in readers: reader.join(timeout=3)
    return {'command':'security-check '+' '.join(args),'entrypoint':command(),
        'exit_code':process.returncode,'duration_ms':round((time.monotonic()-started)*1000),
        'stdout':''.join(output['stdout']),'stderr':''.join(output['stderr']),'timeline':timeline}


def run(jeepay, output):
    evidence={'notes':['Jeepay is an actual existing project; rate limits are not bypassed.',
        'First download timeout is an explicit safe mock, with the production ToolManager/provider.',
        'TTY example is an in-memory terminal renderer demonstration; actual CLI capture is non-TTY.']}
    with tempfile.TemporaryDirectory(prefix='progress-acceptance-') as temporary:
        base=Path(temporary)
        env=dict(os.environ,SECURITY_RUNTIME_STATE_DIR=str(base/'state'))
        actual=capture(['scan','--mode','release'],jeepay,env)
        assert actual['exit_code'] in (0,1),actual
        feedback=[line for line in actual['timeline'] if line['stream']=='stderr']
        assert feedback and feedback[0]['elapsed_ms']<3000,feedback
        for scanner in ('semgrep','gitleaks','trivy'): assert scanner in actual['stderr']
        assert '仍在处理' in actual['stderr'] and '安全检查' in actual['stdout']
        evidence['jeepay']=actual
        root=base/'source';root.mkdir()
        (root/'app.py').write_text('import os\nos.system(input())\n')
        (root/'requirements.txt').write_text('requests==2.31.0\n')
        evidence['json']=capture(['scan','--mode','release','--json'],root,env)
        evidence['json_no_progress']=capture(['scan','--mode','release','--json','--no-progress'],root,env)
        for key in ('json','json_no_progress'):
            assert evidence[key]['exit_code'] in (0,1)
            assert json.loads(evidence[key]['stdout'])['findings']
        assert evidence['json']['stderr'] and evidence['json_no_progress']['stderr']==''
        evidence['first_preparation']={}
        for configured in (False,True):
            manager=ToolManager(root=base/('data-'+str(configured)))
            manager.resolve=lambda tool:ResolvedTool(tool,'','',None,ToolStatus.MISSING)
            stream=io.StringIO();events=[]
            renderer=CLIProgressRenderer(stream,tty=False,delay=0)
            original_sink=renderer.reporter.sink
            def sink(event): events.append(asdict(event));original_sink(event)
            renderer.reporter.sink=sink
            proxy_env={key:'' for key in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy')}
            if configured:
                for key in ('HTTPS_PROXY','https_proxy'):
                    proxy_env[key]='http://user:PROGRESS_PRIVATE_VALUE@proxy.invalid/?token=PROGRESS_PRIVATE_VALUE'
            with patch.dict(os.environ,proxy_env),patch('urllib.request.urlopen',side_effect=URLError(TimeoutError())), \
                 renderer as reporter,progress_context(reporter):
                resolved=manager.ensure('gitleaks',offline=False)
            assert resolved.diagnostic.error_code=='NETWORK_TIMEOUT'
            assert resolved.diagnostic.https_proxy == ('configured' if configured else 'not configured')
            evidence['first_preparation'][str(configured)]={'events':events,'stderr':stream.getvalue(),
                'diagnostic':diagnostic_zh(resolved.diagnostic.to_dict(),retry='security-check tools install gitleaks')}
        clock=[0.];stream=io.StringIO()
        renderer=CLIProgressRenderer(stream,tty=True,delay=0,clock=lambda:clock[0])
        renderer.reporter.emit('SCANNER_STARTED',scanner='trivy',scanner_version='0.74.0')
        for second in (5,10,15): clock[0]=second;renderer.tick()
        renderer.reporter.emit('SCANNER_FAILED',scanner='trivy',scanner_version='0.74.0',duration_ms=16000,error_code='MAVEN_RATE_LIMITED')
        evidence['tty_demo']=stream.getvalue()
        assert 'PROGRESS_PRIVATE_VALUE' not in json.dumps(evidence)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Progress acceptance passed: '+str(output),flush=True)


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser()
    parser.add_argument('--jeepay',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    run(args.jeepay,args.output)

"""Disposable Maven A/B acceptance through actual MCP and existing scanners.

Never installs/fetches dependencies or falls back to direct project execution.
Missing isolation/tool/cache => honest PENDING, even when protocol checks pass.
"""
import argparse
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SAFE='''import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
public class UnsafeTlsService {
 public static HttpsURLConnection connection(String url) throws Exception {
  HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
  connection.setConnectTimeout(1000);
  return connection;
 }
}
'''
UNSAFE=SAFE.replace('  connection.setConnectTimeout',
    '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout')
POM='''<project xmlns="http://maven.apache.org/POM/4.0.0">
 <modelVersion>4.0.0</modelVersion><groupId>local.fixture</groupId><artifactId>functional</artifactId><version>1</version>
 <properties><maven.compiler.release>17</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
 <dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency></dependencies>
 <build><plugins>
 <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.11.0</version></plugin>
 <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version></plugin>
 </plugins></build>
</project>
'''


def fixture(root, failure=False):
    (root/'pom.xml').write_text(POM)
    path=root/'src/main/java/UnsafeTlsService.java'; path.parent.mkdir(parents=True); path.write_text(SAFE)
    tests=root/'src/test/java/UnsafeTlsServiceTest.java'; tests.parent.mkdir(parents=True)
    assertion='assertNotSame' if failure else 'assertSame'
    tests.write_text('''import javax.net.ssl.HttpsURLConnection;
import org.junit.Test;
import static org.junit.Assert.*;
public class UnsafeTlsServiceTest {
 @Test public void existingBehavior() throws Exception {
  '''+assertion+'''(HttpsURLConnection.getDefaultHostnameVerifier(),
      UnsafeTlsService.connection("https://fixture.invalid").getHostnameVerifier());
 }
}
''')
    return path


async def run(command,failure=False,mode='smart_auto'):
    start=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='functional-maven-') as temporary:
        parent=Path(temporary).resolve(); root=parent/'project'; root.mkdir()
        path=fixture(root,failure)
        for argv in [('init',),('config','user.name','Synthetic Fixture'),('config','user.email','fixture@example.invalid')]:
            subprocess.run(['git','-C',str(root),*argv],check=True,capture_output=True)
        # Keep main source untracked so the unchanged Hook scope includes it.
        subprocess.run(['git','-C',str(root),'add','pom.xml','src/test'],check=True,capture_output=True)
        subprocess.run(['git','-C',str(root),'commit','-m','disposable local tests'],check=True,capture_output=True)
        state=parent/'state'; state.mkdir()
        (state/'remediation.json').write_text(json.dumps({'remediation':{'mode':mode}}))
        env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(root),SECURITY_RUNTIME_STATE_DIR=str(state),
                 SECURITY_RUNTIME_OFFLINE='1',SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1')
        params=StdioServerParameters(command=command[0],args=[*command[1:],'mcp'],env=env,cwd=root)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(params,errlog=errors) as (read,write):
                async with ClientSession(read,write,read_timeout_seconds=timedelta(seconds=180)) as client:
                    await client.initialize()
                    async def call(name,args):
                        response=await client.call_tool(name,args)
                        assert not response.isError,name
                        data=response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result',data)
                    info=await call('get_runtime_info',{})
                    assert info['features']['functional_verification']=='v0.1'
                    assert info['remediation']=={'mode':mode,'configuration_status':'VALID'}
                    assert str(state) not in json.dumps(info)
                    claims=dict(event='PostToolUse',workspace_path=str(root),session_id='functional-maven',tool_name='apply_patch')
                    baseline=await call('handle_hook_event',claims)
                    assert baseline['status']=='BASELINE_ESTABLISHED' and baseline['new_families']==0
                    await asyncio.sleep(1.1); path.write_text(UNSAFE)
                    hook=await call('handle_hook_event',claims)
                    assert hook['new_families']==1,hook
                    if mode=='ask_before_fix':
                        decision=await call('confirm_remediation',dict(hook['remediation']['confirmation']['arguments'],approve=True))
                        assert decision['status']=='AUTHORIZED'
                    else: decision=hook['remediation']; assert decision['action']=='AUTO_FIX'
                    assert decision['interaction']=={'phase':'AUTO_REMEDIATION_AUTHORIZED',
                        'user_confirmation_required':False,'must_not_ask_user':True,
                        'must_continue_automatically':True,'next_action':'PREPARE_TASK_FIX'}
                    assert 'USER CONFIRMATION IS NOT REQUIRED' in decision['guidance']
                    assert 'WAIT' not in decision['guidance'] and '是否允许我修复这个安全问题？' not in decision['guidance']
                    assert 'confirmation_ref' not in json.dumps(decision)
                    if mode=='smart_auto':
                        assert hook['decision']=='block' and 'continue' not in hook
                        assert 'Do not ask the user for confirmation' in hook['systemMessage']
                    grant=decision['prepare']['arguments']
                    rejected=await call('prepare_functional_verification',grant)
                    assert rejected['overall_status']=='SECURITY_NOT_VERIFIED'
                    prepared=await call('prepare_task_fix',grant)
                    assert prepared['status']=='READY_FOR_HOST_FIX'
                    await asyncio.sleep(1.1); path.write_text(SAFE)  # simulated Host; Runtime never source-edits
                    closed=await call('handle_hook_event',claims)
                    assert closed['resolved_families']==1
                    checked=await call('verify_task_fix',grant)
                    assert checked['verification_status']=='SCANNER_VERIFIED_RESOLVED'
                    planned=await call('prepare_functional_verification',grant)
                    assert planned['status']=='PLANNED',planned
                    out=await call('run_functional_verification',planned['handoff']['arguments'])
                    assert out['security_verification']['status']=='SCANNER_VERIFIED_RESOLVED'
                    assert path.read_text()==SAFE
                    # Never mask a real incorrect outcome as environment Pending.
                    status=out['functional_verification']['status']
                    if status in {'PASSED','FAILED'}:
                        assert status==('FAILED' if failure else 'PASSED'),out
                        assert out['overall_status']==('SECURITY_VERIFIED_FUNCTION_FAILED' if failure else 'SECURITY_AND_FUNCTIONALLY_VERIFIED')
                    repeat=await call('run_functional_verification',planned['handoff']['arguments'])
                    if status in {'PASSED','FAILED'}: assert repeat['functional_verification']['reused']
                    assert not (root/'target').exists()
    return dict(case='B' if failure else 'A',mode=mode,transport='ACTUAL_MCP_STDIO',
                observed_mode=info['remediation']['mode'],interaction=decision['interaction'],
                prepare_task_fix=True,verify_task_fix=True,resolved_families=closed['resolved_families'],
                prepare_functional_verification=True,run_functional_verification=True,
                security_verification='SCANNER_VERIFIED_RESOLVED',functional_result=out,
                functional_acceptance='PASS' if status in {'PASSED','FAILED'} else 'PENDING_ENVIRONMENT_PREREQUISITES',
                plan=planned['plan'],duration_ms=round((time.monotonic()-start)*1000),
                host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',desktop_trial='PENDING',
                source_persisted=False,network_authorized=False,package_download=False,
                runtime_source_edit=False,baseline='UNKNOWN',ground_truth='UNREVIEWED')


async def run_all(command):
    return {'A':await run(command),'B':await run(command,True),'confirmed':await run(command,False,'ask_before_fix')}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--require-functional-pass',action='store_true')
    args=parser.parse_args()
    command=[str(Path(args.runtime).resolve())] if args.runtime else [sys.executable,'-m','security_runtime.cli']
    record=asyncio.run(run_all(command))
    data=json.dumps(record,indent=2,ensure_ascii=False)+'\n'
    if args.output: args.output.write_text(data,encoding='utf-8')
    print(data)
    if args.require_functional_pass and any(v['functional_acceptance']!='PASS' for v in record.values()):
        raise SystemExit(2)


if __name__=='__main__': main()

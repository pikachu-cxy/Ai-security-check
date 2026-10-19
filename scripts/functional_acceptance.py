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
from codex_hook_fixture import invocation_claims
if __package__:
    from .tls_impact_fixture import confirm_tls_fixture
else:
    from tls_impact_fixture import confirm_tls_fixture

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


def execute_host_plan(plan, root, sandbox):
    """Synthetic Host execution: sandbox mount directories never touch source."""
    from security_runtime.functional_execution import Unavailable
    report = dict(plan_digest=plan['plan_digest'], network_access='DENIED',
                  project_code_reviewed=True, steps=[])
    assert plan['temporary_projection'] is True
    for step in plan['steps']:
        projection = Path(step['working_directory']).resolve(strict=True)
        assert not projection.samefile(root) and not projection.is_relative_to(root.resolve())
        observation = dict(command_id=step['command_id'], execution_status='NOT_AVAILABLE',
                           exit_code=None, duration_ms=0)
        if sandbox.availability() is None:
            class HostStep:
                provider = step['provider']
                def argv(self): return step['argv']
            try:
                measured = sandbox.run(projection, HostStep(), timeout=step['timeout_seconds'])
                observation.update(execution_status='TIMEOUT' if measured['reason']=='TIMEOUT' else
                    'OUTPUT_LIMIT' if measured['reason'] else 'COMPLETED',
                    exit_code=measured['exit_code'], duration_ms=measured['duration_ms'])
                if any(x in measured['output'].lower() for x in
                       (b'pluginresolutionexception', b'dependencyresolutionexception')):
                    observation['stderr_summary'] = 'PluginResolutionException: offline mode'
            except Unavailable:
                pass
        report['steps'].append(observation)
        if observation['execution_status'] != 'COMPLETED' or observation['exit_code'] != 0:
            break
    return report


async def run(command,failure=False,mode='ask_before_fix'):
    requested_mode=mode
    mode='ask_before_fix' if mode=='smart_auto' else mode
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
        (state/'remediation.json').write_text(json.dumps({'remediation':{'mode':requested_mode}}))
        env=dict(os.environ,SECURITY_RUNTIME_WORKSPACE=str(root),SECURITY_RUNTIME_STATE_DIR=str(state),
                 SECURITY_RUNTIME_OFFLINE='1',SECURITY_RUNTIME_MCP_SELF_TEST='1',PYTHONUTF8='1')
        params=StdioServerParameters(command=command[0],args=[*command[1:],'mcp'],env=env,cwd=root)
        with tempfile.TemporaryFile(mode='w+',encoding='utf-8') as errors:
            async with stdio_client(params,errlog=errors) as (read,write):
                async with ClientSession(read,write,read_timeout_seconds=timedelta(seconds=180)) as client:
                    await client.initialize()
                    async def call(name,args):
                        response=await client.call_tool(name,invocation_claims(name, args))
                        assert not response.isError,name
                        data=response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result',data)
                    info=await call('get_runtime_info',{})
                    functional_available=info['features'].get('functional_verification')=='v0.1'
                    exposed={tool.name for tool in (await client.list_tools()).tools}
                    functional_tools={'prepare_functional_verification','run_functional_verification'}
                    assert (functional_tools <= exposed if functional_available else not functional_tools & exposed)
                    assert info['remediation']['mode']==mode
                    assert info['remediation']['configuration_status']=='VALID'
                    assert str(state) not in json.dumps(info)
                    claims=dict(event='PostToolUse',workspace_path=str(root),session_id='functional-maven',tool_name='apply_patch')
                    baseline=await call('handle_hook_event',claims)
                    assert baseline['status']=='BASELINE_ESTABLISHED' and baseline['new_families']==0
                    await asyncio.sleep(1.1); path.write_text(UNSAFE)
                    hook=await call('handle_hook_event',claims)
                    assert hook['new_families']==1,hook
                    pending=hook['remediation']
                    assert pending['action']=='CONFIRM_REQUIRED'
                    assert 'prepare' not in pending and 'agent_fix_ticket' not in pending
                    assert path.read_text()==UNSAFE
                    decision=await confirm_tls_fixture(call,
                        dict(pending['confirmation']['arguments'],approve=True),path,UNSAFE)
                    assert decision['status']=='AUTHORIZED'
                    assert decision['authorization_kind']=='USER_CONFIRMED'
                    assert decision['approval_trust']=='UNTRUSTED_HOST_REPORT'
                    assert 'already approved' in decision['guidance']
                    inline=False
                    grant=decision['prepare']['arguments']
                    if functional_available:
                        rejected=await call('prepare_functional_verification',grant)
                        assert rejected['overall_status']=='SECURITY_NOT_VERIFIED'
                    if not inline:
                        prepared=await call('prepare_task_fix',grant)
                        assert prepared['status']=='READY_FOR_HOST_FIX'
                    await asyncio.sleep(1.1); path.write_text(SAFE)  # simulated Host; Runtime never source-edits
                    closed=await call('handle_hook_event',claims)
                    assert closed['resolved_families']==1
                    checked=await call('verify_task_fix',grant)
                    assert checked['verification_status']=='SCANNER_VERIFIED_RESOLVED'
                    if not functional_available:
                        assert 'functional_verification_offer' not in checked
                        assert path.read_text()==SAFE and not (root/'target').exists()
                        return dict(case='B' if failure else 'A',mode=requested_mode,effective_mode=mode,
                            transport='ACTUAL_MCP_STDIO',observed_mode=info['remediation']['mode'],
                            interaction=decision['interaction'],prepare_task_fix=not inline,
                            inline_prepared=inline,verify_task_fix=True,resolved_families=closed['resolved_families'],
                            prepare_functional_verification=False,run_functional_verification=False,
                            security_verification='SCANNER_VERIFIED_RESOLVED',
                            functional_acceptance='SKIPPED_HIDDEN_PERSONAL_FEATURE',
                            functional_result={'status':'NOT_RUN','reason':'HIDDEN_PERSONAL_FEATURE'},
                            plan=None,duration_ms=round((time.monotonic()-start)*1000),
                            host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',desktop_trial='PENDING',
                            source_persisted=False,network_authorized=False,package_download=False,
                            runtime_source_edit=False,baseline='UNKNOWN',ground_truth='UNREVIEWED')
                    planned=await call('prepare_functional_verification',grant)
                    if planned.get('status') == 'FUNCTIONAL_VERIFICATION_READY':
                        # Execute only through the existing enforced sandbox,
                        # from this synthetic host driver, never inside Runtime.
                        from security_runtime.functional_execution import LocalSandbox
                        assert planned['plan']['runtime_executes_commands'] is False
                        assert planned['handoff']['execution_result_required'] is True
                        report = execute_host_plan(planned['plan'], root, LocalSandbox())
                        out=await call('run_functional_verification',
                            dict(planned['handoff']['arguments'], execution_result=report))
                        run_called=True
                    else:
                        assert planned['functional_verification']['status']=='NOT_AVAILABLE',planned
                        out=planned
                        run_called=False
                    assert out['security_verification']['status']=='SCANNER_VERIFIED_RESOLVED'
                    assert path.read_text()==SAFE
                    status=out['functional_verification']['status']
                    if status in {'PASSED','FAILED'}:
                        assert status==('FAILED' if failure else 'PASSED'),out
                        assert out['overall_status']==('SECURITY_VERIFIED_FUNCTION_FAILED' if failure else 'SECURITY_AND_FUNCTIONALLY_VERIFIED')
                        repeat=await call('run_functional_verification',planned['handoff']['arguments'])
                        assert repeat['functional_verification']['reused']
                    else:
                        assert status=='NOT_AVAILABLE',out
                        assert out['overall_status']=='SECURITY_VERIFIED_FUNCTION_UNKNOWN'
                    assert not out.get('functional_ref') and not out.get('handoff')
                    assert not (root/'target').exists()
    return dict(case='B' if failure else 'A',mode=requested_mode,effective_mode=mode,transport='ACTUAL_MCP_STDIO',
                observed_mode=info['remediation']['mode'],interaction=decision['interaction'],
                prepare_task_fix=not inline,inline_prepared=inline,verify_task_fix=True,resolved_families=closed['resolved_families'],
                prepare_functional_verification=True,run_functional_verification=run_called,
                security_verification='SCANNER_VERIFIED_RESOLVED',functional_result=out,
                functional_acceptance='PASS' if status in {'PASSED','FAILED'} else 'PENDING_ENVIRONMENT_PREREQUISITES',
                plan=planned.get('plan'),duration_ms=round((time.monotonic()-start)*1000),
                host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',desktop_trial='PENDING',
                source_persisted=False,network_authorized=False,package_download=False,
                runtime_source_edit=False,baseline='UNKNOWN',ground_truth='UNREVIEWED')


async def run_all(command):
    return {'A':await run(command),'B':await run(command,True),'legacy_alias':await run(command,False,'smart_auto')}


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
    # Machine stdout must also work on redirected English Windows consoles.
    # The saved human-readable receipt remains UTF-8 with Chinese intact.
    print(json.dumps(record,indent=2,ensure_ascii=True))
    if args.require_functional_pass and any(v['functional_acceptance']!='PASS' for v in record.values()):
        raise SystemExit(2)


if __name__=='__main__': main()

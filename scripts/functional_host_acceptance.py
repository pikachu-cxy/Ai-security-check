"""Actual offline MCP/scanner/JDK evidence. Host edits/execution are simulated."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from codex_hook_fixture import invocation_claims

SAFE = '''package demo;
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
public class TlsService {
 void request(String url) throws Exception {
  HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
  connection.setConnectTimeout(1000);
 }
}
'''
TARGET = 'src/main/java/demo/TlsService.java'


async def case(broken):
    with tempfile.TemporaryDirectory(prefix='runtime-functional-host-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'project'
        root.mkdir()
        subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
        path = root / TARGET
        path.parent.mkdir(parents=True)
        safe = SAFE.replace('setConnectTimeout(1000)', 'setConnectTimeout(MISSING_TIMEOUT)') if broken else SAFE
        unsafe = safe.replace('  connection.setConnectTimeout',
                              '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout')
        path.write_text(safe)
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_STATE_DIR=str(parent / 'state'), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=sys.executable, args=['-m', 'security_runtime.cli', 'mcp'],
                                      env=env, cwd=root)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    calls = []
                    async def call(name, arguments):
                        response = await client.call_tool(name, invocation_claims(name, arguments))
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        data = data.get('result', data)
                        calls.append(dict(tool=name, status=data.get('status'),
                                          overall_status=data.get('overall_status')))
                        return data
                    claims = dict(event='PostToolUse', workspace_path=str(root),
                                  session_id='functional-host-acceptance', tool_name='apply_patch')
                    assert (await call('handle_hook_event', claims))['status'] == 'BASELINE_ESTABLISHED'
                    await asyncio.sleep(1.1)
                    path.write_text(unsafe)
                    detected = await call('handle_hook_event', claims)
                    assert detected['remediation']['action'] == 'AUTO_FIX', detected
                    arguments = dict(detected['remediation']['prepare']['arguments'])
                    assert (await call('prepare_task_fix', arguments))['status'] == 'READY_FOR_HOST_FIX'
                    await asyncio.sleep(1.1)
                    path.write_text(safe)
                    closed = await call('handle_hook_event', claims)
                    assert closed['remediation']['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
                    planned = await call('prepare_functional_verification', arguments)
                    assert planned['status'] == 'FUNCTIONAL_VERIFICATION_READY', planned
                    plan = planned['plan']
                    assert plan['target_files'] == [TARGET] and len(plan['steps']) == 1
                    step = plan['steps'][0]
                    assert step['provider'] == 'javac' and step['argv'][-1] == TARGET
                    command_env = dict(os.environ, **step['environment'])
                    for name in step['unset_environment']:
                        command_env.pop(name, None)
                    began = time.monotonic()
                    # Host driver, outside Runtime. No shell interpolation/download.
                    proc = subprocess.run(step['argv'], cwd=step['working_directory'], env=command_env,
                                          shell=False, capture_output=True, timeout=step['timeout_seconds'])
                    duration = round((time.monotonic() - began) * 1000)
                    assert (proc.returncode != 0) == broken
                    report = dict(plan_digest=plan['plan_digest'], network_access='DENIED',
                                  project_code_reviewed=False, steps=[dict(command_id=step['command_id'],
                                  execution_status='COMPLETED', exit_code=proc.returncode, duration_ms=duration,
                                  stdout_summary='', stderr_summary='Compiler reported unresolved symbol' if broken else '')])
                    handoff = dict(planned['handoff']['arguments'])
                    assert handoff['functional_ref'] == planned['functional_ref']
                    handoff['execution_result'] = report
                    final = await call('run_functional_verification', handoff)
                    assert final['status'] == ('FUNCTIONAL_FAILED' if broken else 'FUNCTIONAL_VERIFIED'), final
                    verified = await call('verify_task_fix', arguments)
                    assert verified['verification_status'] == 'SCANNER_VERIFIED_RESOLVED', verified
                    assert verified['functional_verification']['status'] == ('FAILED' if broken else 'PASSED')
                    assert verified['overall_status'] == ('SECURITY_VERIFIED_FUNCTION_FAILED' if broken else
                                                         'SECURITY_AND_FUNCTIONALLY_VERIFIED')
                    assert not list(root.rglob('*.class')) and path.read_text() == safe
                    assert not Path(step['argv'][step['argv'].index('-d') + 1]).exists()
                    return dict(case='B_COMPILE_FAILED' if broken else 'A_COMPILE_PASSED',
                        mcp_calls=calls, javac_exit_code=proc.returncode, compile_duration_ms=duration,
                        security_status=verified['security_verification']['status'],
                        functional_status=verified['functional_verification']['status'],
                        overall_status=verified['overall_status'], remediation_stage=verified['remediation_stage'],
                        coverage=verified['functional_verification']['coverage'],
                        original_refs_exact=True, source_unchanged_after_compile=True,
                        class_files_in_source=False, temporary_output_removed=True)


async def run(inspect_workspace=None):
    start = time.monotonic()
    javac = shutil.which('javac')
    assert javac, 'Existing javac required; never install it automatically'
    version = subprocess.run([javac, '-version'], capture_output=True, text=True, check=True, timeout=10)
    inspected = None
    if inspect_workspace:
        from security_runtime.functional_verifiers import FunctionalVerifierRegistry
        root = inspect_workspace.resolve()
        steps = FunctionalVerifierRegistry().detect(root, target_files=(TARGET,))
        inspected = dict(workspace=str(root), target=TARGET, providers=[s.provider for s in steps],
                         tool_available=all(s.executable for s in steps), read_only=True,
                         credential_or_reference_used=False, actual_desktop_execution=False)
    outcomes = [await case(False), await case(True)]
    return dict(status='PASS', transport='ACTUAL_LOCAL_MCP_STDIO',
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE',
                compiler_version=(version.stdout or version.stderr).strip(), cases=outcomes,
                inspected_workspace=inspected, runtime_command_execution=False,
                host_execution='SIMULATED_NATIVE_HOST_DRIVER', actual_desktop='PENDING',
                raw_references_persisted=False, runtime_model=False, network=False,
                target_original_workspace_build=False, disposable_fixture_host_compile=True,
                duration_seconds=round(time.monotonic() - start, 2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--inspect-workspace', type=Path)
    arguments = parser.parse_args()
    data = asyncio.run(run(arguments.inspect_workspace))
    if arguments.output:
        arguments.output.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(json.dumps(data, indent=2))

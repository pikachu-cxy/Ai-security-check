"""Actual local SDK/scanner acceptance; simulated host edits, NOT Codex dispatch."""
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

SAFE = '''import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
class UnsafeTlsService {
 void request(String url) throws Exception {
  HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
  connection.setConnectTimeout(1000);
 }
}
'''
UNSAFE = SAFE.replace('  connection.setConnectTimeout',
                      '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout')


async def run(command):
    from security_runtime._version import __version__
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='runtime-remediation-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'project'; root.mkdir()
        for args in [('init',), ('config','user.name','Synthetic Fixture'),
                     ('config','user.email','fixture@example.invalid')]:
            subprocess.run(['git','-C',str(root),*args], check=True, capture_output=True)
        (root / 'README.md').write_text('Disposable local acceptance.\n')
        subprocess.run(['git','-C',str(root),'add','.'], check=True, capture_output=True)
        subprocess.run(['git','-C',str(root),'commit','-m','fixture'], check=True, capture_output=True)
        path = root / 'UnsafeTlsService.java'; path.write_text(SAFE)
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_STATE_DIR=str(parent / 'state'), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=command[0], args=command[1:] + ['mcp'], env=env, cwd=root)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = {t.name:t for t in (await client.list_tools()).tools}
                    async def call(name, arguments):
                        response = await client.call_tool(name, arguments)
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data), response
                    claims = dict(event='PostToolUse', workspace_path=str(root),
                                  session_id='local-sdk-remediation', tool_name='apply_patch')
                    baseline, _ = await call('handle_hook_event', claims)
                    assert baseline['status'] == 'BASELINE_ESTABLISHED'
                    assert baseline['new_families'] == 0
                    # Simulate host reading/editing time; retain the existing
                    # 1s Hook cooldown rather than bypassing its debounce.
                    await asyncio.sleep(1.1)
                    path.write_text(UNSAFE)
                    new, response = await call('handle_hook_event', claims)
                    assert new['new_families'] == 1 and new['remediation']['action'] == 'AUTO_FIX', new
                    assert new['decision'] == json.loads(response.content[0].text)['decision'] == 'block'
                    arguments = new['remediation']['prepare']['arguments']
                    packet, _ = await call('prepare_task_fix', arguments)
                    assert packet['status'] == 'READY_FOR_HOST_FIX'
                    assert packet['remediation_authorization']['action'] == 'AUTO_FIX'
                    assert not any(packet['execution'].values())
                    await asyncio.sleep(1.1)
                    # This driver plays the host editor. Runtime never edits.
                    path.write_text(SAFE)
                    closed, _ = await call('handle_hook_event', claims)
                    assert closed['resolved_families'] == 1, closed
                    assert closed['remediation']['verification']['verification_status'] == 'SCANNER_VERIFIED_RESOLVED', closed
                    assert 'decision' not in closed
                    verified, _ = await call('verify_task_fix', arguments)
                    assert verified['verification_status'] == 'SCANNER_VERIFIED_RESOLVED', verified
                    assert verified['runtime_observed_execution']['engine_process_observed']
                    await asyncio.sleep(1.1)
                    (root / 'Other.java').write_text('class Other {}\n')
                    later, _ = await call('handle_hook_event', claims)
                    assert later['remediation']['action'] == 'NONE' and 'decision' not in later
                    assert path.read_text() == SAFE
                    # Metadata export only; bounded fix evidence is not saved.
                    proof = dict(baseline_status=baseline['status'], new_families=new['new_families'],
                                 action=new['remediation']['action'], attempt_count=new['remediation']['attempt_count'],
                                 hook_feedback=new['decision'], prepare_status=packet['status'],
                                 resolved_families=closed['resolved_families'],
                                 automatic_verification=closed['remediation']['verification'],
                                 explicit_verification=verified['verification_status'],
                                 observed_execution=verified['runtime_observed_execution'],
                                 unrelated_edit_action=later['remediation']['action'])
            errors.seek(0)
            assert '0x80131506' not in errors.read()
    return dict(runtime_version=__version__, transport='ACTUAL_LOCAL_MCP_STDIO',
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE', host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',
                codex_native_dispatch='PENDING', same_turn_codex_model_continuation='PENDING',
                runtime_model_invoked=False, runtime_source_edit=False, target_build=False,
                scanner_network=False, ground_truth='UNREVIEWED', command_hook_runner_used=False,
                duration_ms=round((time.monotonic()-started)*1000), proof=proof,
                schemas={name:tools[name].inputSchema for name in ('handle_hook_event','prepare_task_fix','verify_task_fix')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', help='Optional built standalone executable')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    command = [args.runtime] if args.runtime else [sys.executable, '-m', 'security_runtime.cli']
    record = asyncio.run(run(command))
    if args.output:
        args.output.write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record, indent=2))

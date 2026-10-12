"""Real ordinary MCP + real offline engines. No Hook handler is invoked."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def accept(executable, engine_root, output):
    output.mkdir(parents=True, exist_ok=True)
    calls = []
    with tempfile.TemporaryDirectory(prefix='closeout-mcp-') as temporary:
        root = Path(temporary)
        subprocess.run(['git', 'init', str(root)], capture_output=True, check=True)
        path = root / 'fixture.ts'
        path.write_text('// Public fake credential, never issued.\n// Explanation retained.\n' +
                        'export const demoToken = "ghp_' + '0123456789abcdefghijklmnopqrstuvXYZabc' + '";\n', encoding='utf-8')
        (root / 'partial.vue').write_text('<template><div>Public fixture</div></template>\n', encoding='utf-8')
        env = {k: os.environ[k] for k in ('SystemRoot', 'PATH', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP',
                                         'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH') if k in os.environ}
        env.update(SECURITY_RUNTIME_DATA_DIR=str(engine_root.resolve()),
                   SECURITY_RUNTIME_STATE_DIR=str((output / 'state').resolve()),
                   SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        semgrep = Path(os.environ['LOCALAPPDATA']) / 'Programs/Python/Python312/Scripts/semgrep.exe'
        if semgrep.is_file():
            env['SECURITY_RUNTIME_SEMGREP_PATH'] = str(semgrep)
            env['PATH'] = str(semgrep.parent) + os.pathsep + env.get('PATH', '')
        params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
        independent = None

        async def session_run(stage, ref=None):
            nonlocal independent
            with (output / ('stderr-' + stage + '.txt')).open('w', encoding='utf-8') as stderr:
                async with stdio_client(params, errlog=stderr) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        async def call(name, arguments):
                            assert name not in {'handle_hook_event', 'handle_readiness_event', 'handle_stop_event'}
                            started = time.perf_counter()
                            response = await client.call_tool(name, arguments)
                            assert not response.isError, name
                            calls.append({'stage': stage, 'tool': name, 'elapsed_ms': round((time.perf_counter()-started)*1000, 3)})
                            data = response.structuredContent or json.loads(response.content[0].text)
                            return data.get('result', data)
                        tools = {t.name for t in (await client.list_tools()).tools}
                        assert {'prepare_closeout_check', 'run_closeout_check', 'get_closeout_status'} <= tools
                        if stage == 'initial':
                            info = await call('get_runtime_info', {})
                            scan = await call('scan_project', {'workspace_path': str(root), 'summary': False})
                            secrets = [f for f in scan['findings'] if f['category'] == 'secret']
                            assert {f['technical_details']['rule_id'] for f in secrets} >= {'github-pat', 'generic-api-key'}
                            tasks = await call('get_security_summary', {'workspace_path': str(root), 'details': True})
                            selected = next(t for t in tasks['tasks'] if t['topic'] == 'secret' and
                                            t['members'][0]['rule_id'] == 'github-pat')
                            path.write_text('// Public fake credential, never issued.\n// Explanation retained.\n', encoding='utf-8')
                            independent = await call('verify_task_fix', {'workspace_path': str(root), 'task_ref': selected['task_ref']})
                            assert independent['status'] == 'SCANNER_VERIFIED_RESOLVED'
                            one_closed = await call('get_security_summary', {'workspace_path': str(root), 'scan_id': scan['scan_id'], 'details': True})
                            assert sum(t['current_closure'] == 'CONFIRMED_CLOSED' for t in one_closed['tasks'] if t['topic'] == 'secret') == 1
                            job = await call('prepare_closeout_check', {'workspace_path': str(root),
                                'files': ['fixture.ts', 'partial.vue'], 'source_scan_id': scan['scan_id']})
                            duplicate = await call('prepare_closeout_check', {'workspace_path': str(root),
                                'files': ['fixture.ts', 'partial.vue'], 'source_scan_id': scan['scan_id']})
                            assert duplicate['closeout_ref'] == job['closeout_ref']
                            result = await call('run_closeout_check', {'workspace_path': str(root), 'closeout_ref': job['closeout_ref']})
                            assert result['status'] == 'COMPLETED', result.get('reason')
                            assert result['receipt']['credential_closure_complete'], result
                            assert result['coverage'] != 'FULL'  # Vue code remains partially supported.
                            historical = await call('get_security_summary', {'workspace_path': str(root),
                                'scan_id': scan['scan_id'], 'details': True})
                            assert len(historical['current_credential_closure']) == 2
                            assert all(t['current_closure'] == 'CONFIRMED_CLOSED' for t in historical['tasks'] if t['topic'] == 'secret')
                            return info, job['closeout_ref'], result
                        status = await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref})
                        reused = await call('run_closeout_check', {'workspace_path': str(root), 'closeout_ref': ref})
                        assert status['status'] == 'COMPLETED' and status['current_version'] and reused['reused']
                        path.write_text('// A newer content version\n', encoding='utf-8')
                        stale = await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref})
                        assert stale['current_version'] is False
                        return stale

        info, ref, checked = await session_run('initial')
        stale = await session_run('reconnected', ref)
        report = {'transport': 'REAL_FROZEN_MCP_STDIO', 'build_identity': info['build_identity'],
            'runtime_executable': info['runtime_executable'], 'closeout_ref': ref,
            'source': 'MANUAL_CLOSEOUT', 'calls': calls, 'result': checked,
            'independent_recheck': independent,
            'reconnect_and_idempotency': 'PASSED', 'old_receipt_invalid_after_edit': not stale['current_version'],
            'manual_hook_handlers_called': False, 'real_desktop_auto_closeout': '尚未通过',
            'synchronous_hook_ms': None, 'hook_scheduled_closeout_ms': None, 'user_prompt_latency': '未测得'}
        (output / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({'build': info['build_identity']['build_id'], 'status': checked['status'],
            'coverage': checked['coverage'], 'credential_rules': len(checked['receipt']['risk_verification']),
            'timing_ms': checked['receipt']['timing_ms'], 'desktop_auto': '尚未通过'}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--engine-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(accept(args.executable, args.engine_root, args.output))

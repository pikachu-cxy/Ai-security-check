"""Native default development workflow on disposable, never executed sources."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


async def check(executable, output):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    with tempfile.TemporaryDirectory(prefix='observed-development-acceptance-') as temporary:
        root = Path(temporary)
        project = root / 'project'
        project.mkdir()
        subprocess.run(['git', 'init', '-q', str(project)], check=True, capture_output=True)
        source = project / 'sample.py'
        source.write_text('VALUE = 1\n', encoding='utf-8')
        # A non-observed file must never enter the fixed scan input.
        (project / 'unobserved.py').write_text('def unused(value):\n    return eval(value)\n', encoding='utf-8')
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(project),
                   SECURITY_RUNTIME_STATE_DIR=str(root / 'state'), SECURITY_RUNTIME_OFFLINE='1')
        env.pop('SECURITY_RUNTIME_GLOBAL', None)
        env.pop('SECURITY_RUNTIME_HOST', None)
        hooks = []
        for host in ('codex', 'cursor'):
            for event in ('session-start', 'file-changed', 'agent-stop'):
                before = source.read_bytes()
                process = subprocess.run([str(executable), 'hook', event, '--path', str(project),
                    '--host', host, '--session-id', 'synthetic-default', '--json'], env=env,
                    capture_output=True, text=True, encoding='utf-8', timeout=90)
                assert process.returncode == 0, (host, event, process.stdout, process.stderr)
                data = json.loads(process.stdout)
                assert source.read_bytes() == before
                assert not data.get('baseline_available', False), data
                assert not data.get('execution', {}).get('scanner_run', data.get('scanner_run', False)), data
                if event == 'session-start':
                    assert data['status'] == 'CONNECTED', data
                elif event == 'file-changed':
                    assert data.get('development_check_ref'), data
                else:
                    assert data['status'] == 'SESSION_FINALIZED', data
                hooks.append({'host': host, 'event': event, 'result': data})
        params = StdioServerParameters(command=str(executable), args=['mcp'], cwd=project, env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await asyncio.wait_for(client.initialize(), 90)
                async def call(name, arguments):
                    response = await asyncio.wait_for(client.call_tool(name, arguments), 90)
                    assert not response.isError, (name, response)
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                started = await call('begin_development_check', {'task_key': 'synthetic-release-default', 'workspace_path': str(project)})
                ref = started['check_ref']
                arguments = {'check_ref': ref, 'workspace_path': str(project)}
                source.write_text('VALUE = 2\n', encoding='utf-8')
                recorded = await call('record_development_changes', dict(arguments, paths=['sample.py']))
                assert not recorded['scanner_run'] and not recorded['baseline_created'], recorded
                digest = hashlib.sha256(source.read_bytes()).hexdigest()
                saved = await call('complete_development_check', arguments)
                for _ in range(30):
                    if saved['status'] not in {'QUEUED', 'RUNNING', 'DIRTY'}:
                        break
                    saved = await call('wait_development_check', arguments)
                assert saved['result_available'] and saved['scan_status'] == 'COMPLETED', saved
                assert saved['scanned_seq'] == saved['dirty_seq'], saved
                assert saved['scope']['paths'] == ['sample.py'] and not saved['scope']['full_project'], saved
                risks = await call('get_development_risks', arguments)
                assert risks['total'] == 0, risks
                await call('submit_development_review', dict(arguments, expected_seq=saved['dirty_seq'], observations=[]))
                reread = await call('get_development_check', arguments)
                assert reread['host_review_completed'] and reread['scan_id'] == saved['scan_id'], reread
                assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
        output.write_text(json.dumps({'hooks': hooks, 'observed_check': reread,
            'unobserved_source_scanned': False, 'source_modified_by_runtime': False},
            ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        print('Native Codex/Cursor hooks record edits without baselines; MCP scans only the recorded file and persists review.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(check(args.executable.resolve(), args.output))

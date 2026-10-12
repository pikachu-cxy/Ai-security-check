"""Ordinary frozen MCP calls only. Never invoke or replay a host Hook handler."""
import argparse
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def accept(executable, engine_root, output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ai-security-secret-mcp-') as temporary:
        root = Path(temporary)
        path = root / 'src' / 'secret-fixture.ts'
        path.parent.mkdir()
        fake = 'ghp_' + '0123456789abcdefghijklmnopqrstuvXYZabc'
        path.write_text('// Public fake fixture only.\n// Never issued.\nexport const demoToken = "' + fake + '";\n', encoding='utf-8')
        env = {key: os.environ[key] for key in ('SystemRoot', 'PATH', 'LOCALAPPDATA', 'APPDATA', 'TEMP',
            'TMP', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH') if key in os.environ}
        env.update(SECURITY_RUNTIME_DATA_DIR=str(engine_root.resolve()),
            SECURITY_RUNTIME_STATE_DIR=str((output / 'state').resolve()),
            SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_OFFLINE='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
        calls = []
        with (output / 'mcp-stderr.txt').open('w', encoding='utf-8') as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()

                    async def call(name, arguments):
                        assert name in {'get_runtime_info', 'scan_project', 'get_security_summary',
                                        'prepare_task_fix', 'verify_task_fix'}
                        started = time.perf_counter()
                        response = await client.call_tool(name, arguments)
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        calls.append({'tool': name, 'elapsed_ms': round((time.perf_counter() - started) * 1000, 2)})
                        return data.get('result', data)

                    info = await call('get_runtime_info', {})
                    assert info['version'] == '0.3.2'
                    initial = await call('scan_project', {'workspace_path': str(root), 'summary': False})
                    summary = await call('get_security_summary', {'workspace_path': str(root), 'details': True})
                    task = next(t for t in summary['tasks'] if t.get('topic') == 'secret')
                    arguments = {'workspace_path': str(root), 'task_ref': task['task_ref']}
                    prepared = await call('prepare_task_fix', arguments)
                    assert prepared['status'] == 'READY_FOR_HOST_FIX', prepared['status']
                    unchanged = await call('verify_task_fix', arguments)
                    assert unchanged['status'] == 'STILL_PRESENT', unchanged['status']
                    path.write_text('// Public fake fixture only.\n// Fixture removed; explanation retained.\n', encoding='utf-8')
                    cleaned = await call('verify_task_fix', arguments)
                    assert cleaned['status'] == 'SCANNER_VERIFIED_RESOLVED', cleaned['status']
                    assert '已确认关闭' in cleaned['user_feedback']['message']
                    final = await call('scan_project', {'workspace_path': str(root), 'summary': False})
                    assert not final['findings'] and final['recommendation'] == 'NO_FINDINGS'
        result = {'transport': 'REAL_FROZEN_MCP_STDIO', 'runtime_version': info['version'],
            'build_identity': info['build_identity'], 'runtime_executable': info['runtime_executable'],
            'secret_feature': info['features'].get('secret_rule_file_recheck'), 'ordinary_tool_calls': calls,
            'initial_candidate_count': len(initial['findings']), 'prepare_status': prepared['status'],
            'unchanged_status': unchanged['status'], 'cleaned_status': cleaned['status'],
            'cleaned_user_feedback': cleaned['user_feedback'], 'final_recommendation': final['recommendation'],
            'manual_hook_handlers_called': False, 'real_desktop_hook_acceptance': '尚未通过；待用户安装后测试'}
        (output / 'results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--engine-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(accept(args.executable, args.engine_root, args.output))

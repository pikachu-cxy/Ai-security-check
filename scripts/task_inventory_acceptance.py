"""Verify automatic task selection through native MCP, with no caller file scope."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from security_runtime.hook_state import no_links


async def accept(executable, engine_root, output, workspace=None):
    output = output.absolute()
    no_links(output)
    if output.exists():
        raise ValueError('Use a fresh receipt directory')
    output.mkdir(parents=True)
    if workspace is None:
        root = output / 'project'
        root.mkdir()
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        (root / '.gitignore').write_text('.test-tmp*/\n', encoding='utf-8')
        (root / 'main.py').write_text('initial_value = 1\n', encoding='utf-8')
        temporary = root / '.test-tmp-old'
        temporary.mkdir()
        for number in range(1100):
            (temporary / f'old{number:04d}.py').write_text('cached_value = 2\n', encoding='utf-8')
        related = 'main.py'
        probe_directory = root
    else:
        root = workspace.resolve(strict=True)
        related = 'src/security_runtime/task_security.py'
        probe_directory = root / 'src/security_runtime'
        if not probe_directory.is_dir():
            raise ValueError('Expected Runtime source workspace')
    root = root.resolve(strict=True)
    no_links(probe_directory.absolute())
    env = {k: os.environ[k] for k in ('SystemRoot', 'PATH', 'LOCALAPPDATA', 'APPDATA',
           'TEMP', 'TMP', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH') if k in os.environ}
    env.update(SECURITY_RUNTIME_DATA_DIR=str(engine_root.resolve()),
               SECURITY_RUNTIME_STATE_DIR=str(output / 'state'), SECURITY_RUNTIME_WORKSPACE=str(root),
               SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
    tag = uuid.uuid4().hex[:12]
    probes = [probe_directory / f'inventory_probe_{tag}_{number}.py' for number in (1, 2)]
    assert not any(path.exists() for path in probes)
    expected = sorted(path.relative_to(root).as_posix() for path in probes)
    created, timings = [], []
    params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
    receipt = None
    try:
        with (output / 'stderr.txt').open('w', encoding='utf-8') as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    async def call(name, **arguments):
                        started = time.perf_counter()
                        response = await client.call_tool(name, arguments)
                        timings.append({'tool': name, 'milliseconds': round((time.perf_counter()-started)*1000, 2)})
                        if response.isError:
                            raise AssertionError((name, response.content))
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data)
                    info = await call('get_runtime_info')
                    started = await call('begin_security_task', task_key='automatic-inventory-'+tag,
                                         workspace_path=str(root))
                    assert started['status'] == 'ACTIVE' and not started['limitations'], started
                    ref = started['task_ref']
                    for number, path in enumerate(probes, 1):
                        content = f'probe_value = {number}\n'
                        with path.open('x', encoding='utf-8', newline='\n') as stream:
                            stream.write(content)
                        created.append((path, content))
                    result = await call('finish_security_task', task_ref=ref, workspace_path=str(root))
                    assert result['status'] == 'READY', result
                    assert sorted(c['path'] for c in result['changes']) == expected, result['changes']
                    assert result['static']['scope_files'] == expected, result['static']
                    assert all('.test-tmp' not in p for p in result['static']['actual_files'])
                    assert result['static']['finding_count'] == 0
                    assert {'semgrep', 'gitleaks'} <= {r['scanner'] for r in result['static']['scanner_runs'] if r['status']=='SUCCESS'}
                    again = await call('finish_security_task', task_ref=ref, workspace_path=str(root))
                    assert again['static']['scan_id'] == result['static']['scan_id'] and not again['scanner_run']
                    packet = await call('prepare_task_security_review', task_ref=ref, workspace_path=str(root))
                    assert set(d['path'] for d in packet['diffs']) == set(expected)
                    assert not any('availability' in d for d in packet['diffs'])
                    session = packet['review_session']
                    for name in [expected[0], related]:
                        await call('read_task_review_context', task_ref=ref, review_session=session,
                                   file_path=name, start_line=1, end_line=40, workspace_path=str(root))
                    submitted = await call('submit_task_security_review', task_ref=ref, review_session=session,
                        findings=[], coverage='PARTIAL', limitations=['接口验收模拟提交，不代表真实宿主AI分析。'], workspace_path=str(root))
                    assert submitted['status'] == 'COMPLETE'
                    readback = await call('get_task_security_review', task_ref=ref, workspace_path=str(root))
                    assert readback['current_version'] is True
                    receipt = {'contract': 'automatic-task-inventory-acceptance-v1', 'workspace': str(root),
                        'build_id': info['build_identity']['build_id'], 'baseline_files': started['baseline_file_count'],
                        'changes': result['changes'], 'static': result['static'], 'diff_preimages_available': True,
                        'same_result_reused': True, 'context_read': True, 'timings': timings,
                        'host_review_is_fixture': True, 'desktop_dispatch_observed': False,
                        'caller_supplied_file_scope': False, 'global_configuration_modified': False}
    finally:
        for path, content in created:
            # Delete only exact owned probes; no recursive deletion or restoration.
            if path.resolve().is_relative_to(root) and path.read_text(encoding='utf-8') == content:
                path.unlink()
    assert receipt is not None
    receipt['owned_probes_removed_after_receipt'] = True
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'receipt': str(output / 'receipt.json'), 'build_id': receipt['build_id'],
                      'baseline_files': receipt['baseline_files'], 'changes': receipt['changes'],
                      'scanner_runs': receipt['static']['scanner_runs'], 'timings': timings}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--engine-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workspace', type=Path)
    args = parser.parse_args()
    asyncio.run(accept(args.executable, args.engine_root, args.output, args.workspace))

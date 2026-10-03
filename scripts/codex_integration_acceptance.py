"""Disposable actual CLI/MCP/scanner acceptance; synthetic host, not Desktop proof.

Works against source, clean installed wheel, or standalone. Never downloads, builds
the target, executes user configuration commands, or touches real Codex settings.
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
import tomllib

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from remediation_acceptance import SAFE, UNSAFE


async def accept(command):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='codex-product-') as temporary:
        parent = Path(temporary).resolve(); root = parent / '项目 with spaces'; root.mkdir()
        state = parent / 'private state'
        env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(state), SECURITY_RUNTIME_OFFLINE='1',
                   PYTHONUTF8='1', PIP_NO_INDEX='1')
        env.pop('SECURITY_RUNTIME_WORKSPACE', None)
        for argv in [('init',), ('config', 'user.name', 'Fixture'), ('config', 'user.email', 'fixture@example.invalid')]:
            subprocess.run(['git', '-C', str(root), *argv], check=True, capture_output=True)
        (root / 'README.md').write_text('Disposable integration fixture.\n', encoding='utf-8')
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), 'commit', '-m', 'fixture'], check=True, capture_output=True)
        folder = root / '.codex'; folder.mkdir()
        original = b'# retain comments\nmodel="fixture"\n[mcp_servers.unrelated]\ncommand="never-execute-this"\n'
        config = folder / 'config.toml'; config.write_bytes(original)
        hooks = folder / 'hooks.json'; unrelated_hook = {'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'never-execute-this'}]}]}}
        hooks.write_text(json.dumps(unrelated_hook), encoding='utf-8')

        def cli(argv):
            response = subprocess.run([*command, *argv, '--path', str(root), '--json'], cwd=parent,
                                      env=env, capture_output=True, timeout=90)
            assert response.returncode == 0, 'CLI lifecycle failed (raw output withheld)'
            return json.loads(response.stdout)
        assert cli(['integration', 'status', 'codex'])['overall'] == 'NOT_INSTALLED'
        installed = cli(['setup', 'codex']); assert installed['operation'] == 'CONFIGURED'
        first = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (config, hooks)}
        assert cli(['setup', 'codex'])['operation'] == 'ALREADY_CONFIGURED'
        assert first == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in first}
        assert cli(['integration', 'repair', 'codex'])['operation'] == 'ALREADY_CONFIGURED'
        assert first == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in first}
        entry = tomllib.loads(config.read_text(encoding='utf-8'))['mcp_servers']['ai_security_runtime']
        assert entry['command'] == command[0] and entry['required'] is True
        assert entry['env']['SECURITY_RUNTIME_WORKSPACE'] == str(root)
        source = root / 'UnsafeTlsService.java'
        params = StdioServerParameters(command=entry['command'], args=entry['args'], cwd=entry['cwd'], env={**env, **entry['env']})
        called = []
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=180)) as client:
                    await client.initialize()
                    async def call(name, claims):
                        called.append(name)
                        response = await client.call_tool(name, claims)
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data)
                    # No prior get_runtime_info/tool warmup in this fresh process.
                    ready = await call('handle_readiness_event', dict(event='SessionStart', workspace_path=str(root), session_id='new-host-session'))
                    assert ready['status'] == 'READY' and not any(ready['execution'].values()), ready
                    assert not (state / 'scans.db').exists()
                    assert not source.exists()
                    source.write_text(SAFE, encoding='utf-8')  # simulated first ordinary host edit
                    claims = dict(event='PostToolUse', workspace_path=str(root), session_id='new-host-session', tool_name='apply_patch')
                    baseline = await call('handle_hook_event', claims)
                    assert baseline['status'] == 'BASELINE_ESTABLISHED' and baseline['scanner_run'] and baseline['new_families'] == 0, baseline
                    await asyncio.sleep(1.1)
                    source.write_text(UNSAFE, encoding='utf-8')
                    finding = await call('handle_hook_event', claims)
                    decision = finding['remediation']
                    assert finding['new_families'] == 1 and decision['action'] == 'AUTO_FIX', finding
                    original_refs = decision['prepare']['arguments']
                    packet = await call('prepare_task_fix', original_refs)
                    assert packet['status'] == 'READY_FOR_HOST_FIX' and not any(packet['execution'].values())
                    await asyncio.sleep(1.1)
                    source.write_text(SAFE, encoding='utf-8')  # simulated host authorized edit
                    closed = await call('handle_hook_event', claims)
                    receipt = closed['remediation']['security_verification']
                    assert closed['resolved_families'] == 1 and receipt['status'] == 'SCANNER_VERIFIED_RESOLVED'
                    assert receipt['phase'] == 'CLOSED' and receipt['task_ref'] == original_refs['task_ref']
                    assert receipt['grant_id'] == decision['grant_id'] and not receipt['explicit_verification_required']
                    functional = await call('prepare_functional_verification', original_refs)
                    assert functional['functional_verification']['status'] == 'NOT_AVAILABLE'
                    assert functional['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
                    assert not functional.get('functional_ref') and not functional.get('handoff')
                    assert 'verify_task_fix' not in called and 'run_functional_verification' not in called
                    assert 'get_runtime_info' not in called
        status = cli(['integration', 'status', 'codex'])
        assert status['overall'] == 'READY' and status['live_connection'] == 'UNKNOWN'
        assert cli(['integration', 'remove', 'codex'])['operation'] == 'REMOVED'
        assert config.read_bytes() == original
        assert json.loads(hooks.read_bytes()) == unrelated_hook
        assert source.read_text(encoding='utf-8') == SAFE and (state / 'scans.db').exists()
        assert cli(['setup', 'codex'])['operation'] == 'CONFIGURED'
        assert cli(['integration', 'status', 'codex'])['readiness']['status'] == 'READINESS_NOT_OBSERVED'
        assert cli(['integration', 'remove', 'codex'])['operation'] == 'REMOVED'
        return {'status': 'PASS', 'duration_seconds': round(time.monotonic() - started, 2),
                'host_dispatch': 'SYNTHETIC_SDK_NOT_DESKTOP', 'actual_desktop_cold_start': 'PENDING_ACTUAL_DESKTOP',
                'runtime_kind': installed['runtime']['kind'], 'workspace_unicode_and_spaces': 'PASS',
                'lifecycle': 'SETUP_STATUS_IDEMPOTENT_REPAIR_REMOVE_REINSTALL_PASS',
                'first_edit': baseline['status'], 'scanner_run': baseline['scanner_run'], 'readiness': ready['readiness'],
                'new_families': finding['new_families'], 'resolved_families': closed['resolved_families'],
                'security_verification': receipt['status'], 'explicit_verify_called': False,
                'functional': functional['functional_verification']['status'], 'functional_run_called': False,
                'warmup_called': False, 'target_build': False, 'network': False, 'model': False,
                'source_edit': 'SIMULATED_HOST_ONLY', 'ground_truth': 'NOT_PERFORMED',
                'calls': called}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    command = [str(args.runtime.resolve())] if args.runtime else [sys.executable, '-I', '-m', 'security_runtime.cli']
    result = asyncio.run(accept(command))
    rendered = json.dumps(result, ensure_ascii=True, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered)


if __name__ == '__main__':
    main()

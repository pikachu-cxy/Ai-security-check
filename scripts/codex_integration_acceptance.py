"""Disposable actual CLI/MCP/scanner acceptance; synthetic host, not Desktop proof.

Works against source, clean installed wheel, or standalone. Never downloads, builds
the target, executes user configuration commands, or touches real Codex settings.
"""
import argparse
import asyncio
from datetime import timedelta
import hashlib
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
from codex_hook_fixture import invocation_claims


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
        assert installed['baseline']['status'] == 'READY', installed
        seed = state / 'codex-integrations' / hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest() / 'baseline-seed.json'
        assert seed.is_file() and not (state / 'scans.db').exists()
        seed_before = seed.read_bytes(), seed.stat().st_mtime_ns
        first = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (config, hooks)}
        assert cli(['setup', 'codex'])['operation'] == 'ALREADY_CONFIGURED'
        assert first == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in first}
        assert cli(['integration', 'repair', 'codex'])['operation'] == 'ALREADY_CONFIGURED'
        assert first == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in first}
        assert seed_before == (seed.read_bytes(), seed.stat().st_mtime_ns)
        entry = tomllib.loads(config.read_text(encoding='utf-8'))['mcp_servers']['ai_security_runtime']
        assert entry['command'] == command[0] and entry['required'] is True
        assert entry['env']['SECURITY_RUNTIME_WORKSPACE'] == str(root)
        generated = json.loads(hooks.read_bytes())
        owned_stop = generated['hooks']['Stop'][1]['hooks'][0]
        assert owned_stop['type'] == 'mcp_tool' and owned_stop['tool'] == 'handle_stop_event'
        assert owned_stop['input']['stop_hook_active'] == '${stop_hook_active}'
        source = root / 'UnsafeTlsService.java'
        params = StdioServerParameters(command=entry['command'], args=entry['args'], cwd=entry['cwd'], env={**env, **entry['env']})
        called = []
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=180)) as client:
                    await client.initialize()
                    async def call(name, claims):
                        called.append(name)
                        response = await client.call_tool(name, invocation_claims(name, claims))
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data)
                    # No prior get_runtime_info/tool warmup in this fresh process.
                    ready = await call('handle_readiness_event', dict(event='SessionStart', workspace_path=str(root), session_id='new-host-session'))
                    assert ready['status'] == 'READY' and not any(ready['execution'].values()), ready
                    assert not (state / 'scans.db').exists()
                    assert not source.exists()
                    stop_claims = dict(event='Stop', workspace_path=str(root), session_id='new-host-session', stop_hook_active=False)
                    quiet = await call('handle_stop_event', stop_claims)
                    assert quiet['status'] == 'ALLOW_STOP' and not any(quiet['execution'].values())
                    source.write_text(SAFE, encoding='utf-8')  # simulated first ordinary host edit
                    claims = dict(event='PostToolUse', workspace_path=str(root), session_id='new-host-session', tool_name='apply_patch')
                    # Deliberately no Hook for this safe edit: exact Desktop
                    # attribution failure fixture, not a pre-warmed baseline.
                    source.write_text(UNSAFE, encoding='utf-8')
                    finding = await call('handle_hook_event', claims)
                    assert finding['baseline_available'] and finding['baseline_source'] == 'SETUP_SEED'
                    assert finding['status'] != 'BASELINE_ESTABLISHED' and finding['scanner_run']
                    decision = finding['remediation']
                    assert finding['new_families'] == 1 and decision['action'] == 'AUTO_FIX', finding
                    assert finding['continue'] is False and 'decision' not in finding
                    assert finding['stopReason'].endswith(decision['guidance'])
                    assert 'Do not retry or repeat it.' in finding['stopReason']
                    assert 'not the original insecure edit' in finding['stopReason']
                    assert 'prepare_task_fix' in finding['systemMessage']
                    original_refs = decision['prepare']['arguments']
                    # Force the observed missing-prepare state. This SDK driver
                    # consumes the Stop handoff; it is not model continuation.
                    guarded = await call('handle_stop_event', stop_claims)
                    assert guarded['decision'] == 'block' and guarded['host_continuation_attempt_count'] == 1
                    assert 'continue' not in guarded and guarded['reason']
                    assert not any(guarded['execution'].values())
                    resumed = json.loads(guarded['reason'][guarded['reason'].index('{'):])
                    assert resumed == decision['prepare']
                    packet = await call('prepare_task_fix', original_refs)
                    assert packet['status'] == 'READY_FOR_HOST_FIX' and not any(packet['execution'].values())
                    prepared_stop = await call('handle_stop_event', {**stop_claims, 'stop_hook_active': True})
                    assert prepared_stop['status'] == 'ALLOW_STOP' and 'decision' not in prepared_stop
                    await asyncio.sleep(1.1)
                    source.write_text(SAFE, encoding='utf-8')  # simulated host authorized edit
                    closed = await call('handle_hook_event', claims)
                    receipt = closed['remediation']['security_verification']
                    assert closed['resolved_families'] == 1 and receipt['status'] == 'SCANNER_VERIFIED_RESOLVED'
                    assert receipt['phase'] == 'CLOSED' and receipt['task_ref'] == original_refs['task_ref']
                    assert receipt['grant_id'] == decision['grant_id'] and not receipt['explicit_verification_required']
                    closed_stop = await call('handle_stop_event', {**stop_claims, 'stop_hook_active': True})
                    assert closed_stop['status'] == 'ALLOW_STOP' and 'decision' not in closed_stop
                    functional = await call('prepare_functional_verification', original_refs)
                    if functional.get('status') == 'FUNCTIONAL_VERIFICATION_READY':
                        # This integration acceptance deliberately does not build
                        # targets. New host plans are declined via their exact
                        # report contract, so Runtime can clean its temp output.
                        first = functional['plan']['steps'][0]
                        functional = await call('run_functional_verification', {
                            **functional['handoff']['arguments'],
                            'execution_result': {
                                'plan_digest': functional['plan']['plan_digest'],
                                'network_access': 'DENIED', 'project_code_reviewed': False,
                                'steps': [{'command_id': first['command_id'],
                                           'execution_status': 'NOT_AVAILABLE',
                                           'exit_code': None, 'duration_ms': 0}]}})
                    assert functional['functional_verification']['status'] == 'NOT_AVAILABLE'
                    assert functional['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
                    assert not functional.get('functional_ref') and not functional.get('handoff')
                    assert 'verify_task_fix' not in called
                    assert 'get_runtime_info' not in called
        status = cli(['integration', 'status', 'codex'])
        assert status['overall'] == 'READY' and status['live_connection'] == 'UNKNOWN'
        assert cli(['integration', 'remove', 'codex'])['operation'] == 'REMOVED'
        assert not seed.exists()
        assert config.read_bytes() == original
        assert json.loads(hooks.read_bytes()) == unrelated_hook
        assert source.read_text(encoding='utf-8') == SAFE and (state / 'scans.db').exists()
        source.write_text(UNSAFE, encoding='utf-8')  # now pre-existing, not new AI attribution
        assert cli(['setup', 'codex'])['baseline']['status'] == 'READY'
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=180)) as client:
                    await client.initialize()
                    response = await client.call_tool('handle_hook_event', invocation_claims('handle_hook_event', {**claims, 'session_id': 'preexisting-fresh-session'}))
                    assert not response.isError
                    data = response.structuredContent or json.loads(response.content[0].text)
                    existing = data.get('result', data)
                    assert existing['baseline_source'] == 'SETUP_SEED'
                    assert existing['new_families'] == 0 and existing['persisting_families'] == 1, existing
                    assert existing['remediation']['action'] == 'NONE'
                    assert not {'decision', 'continue', 'stopReason'} & existing.keys()
        assert cli(['integration', 'status', 'codex'])['readiness']['status'] == 'READINESS_NOT_OBSERVED'
        assert cli(['integration', 'remove', 'codex'])['operation'] == 'REMOVED'
        return {'status': 'PASS', 'duration_seconds': round(time.monotonic() - started, 2),
                'host_dispatch': 'SYNTHETIC_SDK_NOT_DESKTOP', 'actual_desktop_stop_continuation': 'PENDING_ACTUAL_DESKTOP',
                'runtime_kind': installed['runtime']['kind'], 'workspace_unicode_and_spaces': 'PASS',
                'lifecycle': 'SETUP_STATUS_IDEMPOTENT_REPAIR_REMOVE_REINSTALL_PASS',
                'baseline_seed': installed['baseline'], 'missing_first_safe_hook': 'PASS',
                'first_edit': 'SKIPPED_UNOBSERVED_SAFE_EDIT', 'first_effective_hook': finding['status'],
                'baseline_source': finding['baseline_source'], 'untracked_new_file': 'PASS',
                'preexisting_persisting': existing['persisting_families'], 'preexisting_auto_fix': False,
                'scanner_run': finding['scanner_run'], 'readiness': ready['readiness'],
                'new_families': finding['new_families'], 'resolved_families': closed['resolved_families'],
                'security_verification': receipt['status'], 'explicit_verify_called': False,
                'auto_fix_issued': True, 'posttool_natural_continuation': 'NOT_TESTED_DRIVER_FORCED_FALLBACK',
                'posttool_feedback': 'CONTINUE_FALSE_NON_REJECT_FEEDBACK',
                'stop_continuation_invoked': True, 'stop_continuation_count': 1,
                'prepare_task_fix_called': True, 'secure_edit_applied': 'SIMULATED_HOST_ONLY',
                'explicit_verify_deduped': True, 'functional_prepare_called': True,
                'functional': functional['functional_verification']['status'],
                'functional_run_called': 'run_functional_verification' in called,
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

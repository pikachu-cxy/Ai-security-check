"""Disposable CODEX_HOME + installed wheel + real stdio MCP/scanner trial.

No Desktop/model/trust manipulation. Host source edits are fixture operations;
opaque refs remain in memory and are never serialized into the report.
"""
import argparse
import asyncio
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import time
from contextlib import closing

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from remediation_episode_acceptance import SAFE, UNSAFE
from codex_hook_fixture import invocation_claims
from remediation_acceptance import approve_reported_risk


def command(argv, cwd, env):
    p = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       encoding='utf-8', errors='replace', timeout=180)
    if p.returncode:
        raise RuntimeError(f'Acceptance command failed: {argv[1:3]} / {p.returncode}: {p.stderr[-1500:]}')
    return p.stdout


async def trial(args):
    start = time.perf_counter()
    report = {'actual_desktop': 'NOT_RUN_USER_SCHEDULED', 'trust_ui': 'PENDING_ACTUAL_DESKTOP',
              'network': False, 'model': False, 'target_build': False, 'active_runtime_replaced': False,
              'raw_references_persisted': False, 'temporary_codex_home': True,
              'wheel_sha256': hashlib.sha256(Path(args.wheel).read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='p07-global-') as temporary:
        parent = Path(temporary).resolve(); home = parent / 'codex-home'; home.mkdir()
        venv = parent / 'venv'
        command([sys.executable, '-m', 'venv', '--system-site-packages', str(venv)], parent, os.environ)
        python = venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        env = {**os.environ, 'CODEX_HOME': str(home), 'SECURITY_RUNTIME_STATE_DIR': str(parent / 'state'),
               'SECURITY_RUNTIME_OFFLINE': '1', 'SECURITY_RUNTIME_MCP_SELF_TEST': '1', 'PYTHONUTF8': '1', 'PIP_NO_INDEX': '1'}
        env.pop('PYTHONPATH', None); env.pop('SECURITY_RUNTIME_WORKSPACE', None); env.pop('SECURITY_RUNTIME_GLOBAL', None)
        # The shared third-party dependency environment may contain an older
        # Runtime with the same version. Always install this wheel inside the
        # disposable venv, without uninstalling anything in the base environment.
        command([str(python), '-m', 'pip', 'install', '--ignore-installed', '--no-deps', '--no-index', str(Path(args.wheel).resolve())], parent, env)
        origin = Path(json.loads(command([str(python), '-I', '-c',
            "import importlib.util,json; print(json.dumps(importlib.util.find_spec('security_runtime.cli').origin))"], parent, env)))
        assert origin.resolve().is_relative_to(venv.resolve())
        report['runtime_module_origin'] = 'TEMPORARY_VENV_SITE_PACKAGES'
        cli = [str(python), '-I', '-m', 'security_runtime.cli']
        roots = []; targets = []
        for name in ('project-a', 'project-b', 'legacy'):
            root = parent / name; root.mkdir(); roots.append(root)
            command(['git', 'init', '-q', str(root)], parent, env)
            target = root / 'src/main/java/demo/CodeModeTlsService.java'; target.parent.mkdir(parents=True)
            target.write_bytes(SAFE.encode()); targets.append(target)
            command(['git', '-C', str(root), 'add', '.'], parent, env)
            command(['git', '-C', str(root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'safe'], parent, env)
        # Existing project installation belongs to this isolated Runtime state.
        legacy = json.loads(command([*cli, 'setup', 'codex', '--scope', 'project', '--path', str(roots[2]), '--json'], roots[2], env))
        assert legacy['overall'] == 'CONFIGURED'
        user = b'# user preserved\nmodel = "fixture"\n[mcp_servers.user]\ncommand = "user"\n'
        (home / 'config.toml').write_bytes(user)
        user_hook = {'type': 'command', 'command': 'fixture-user-hook'}
        (home / 'hooks.json').write_text(json.dumps({'hooks': {'Stop': [{'hooks': [user_hook]}]}}))
        installed = json.loads(command([*cli, 'setup', '--json'], roots[0], env))
        assert installed['overall'] == 'CONFIGURED' and installed['scope'] == 'GLOBAL'
        snapshots = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (home / 'config.toml', home / 'hooks.json')}
        repeat = json.loads(command([*cli, 'setup', '--json'], roots[1], env))
        assert repeat['operation'] == 'ALREADY_CONFIGURED'
        assert snapshots == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in snapshots}
        migrated = json.loads(command([*cli, 'repair', '--path', str(roots[2]), '--json'], roots[2], env))
        assert migrated['migration']['removed_layers'] == 1
        for action in ('status', 'doctor'):
            data = json.loads(command([*cli, action, '--json'], roots[0], env))
            assert data['scope'] == 'GLOBAL' and data['overall'] == 'CONFIGURED'
        assert all(not (root / '.codex').exists() for root in roots[:2])
        report.update(clean_installed_launcher=True, fresh_setup='PASS', repeated_setup='PASS',
                      legacy_migration='PASS', user_preservation='PASS', cli_status_doctor='PASS')
        if args.codex:
            # Public CLI only; does not approve hooks, connect a model or touch
            # the user's original CODEX_HOME/internal trust DB.
            entries = json.loads(command([args.codex, 'mcp', 'list', '--json'], roots[0], env))
            got = json.loads(command([args.codex, 'mcp', 'get', 'ai_security_runtime', '--json'], roots[1], env))
            assert any(e['name'] == 'ai_security_runtime' for e in entries)
            assert got['name'] == 'ai_security_runtime'
            report['local_codex_global_config_discovery'] = 'PASS'
            report['codex_cli_version'] = command([args.codex, '--version'], parent, env).strip()
        import tomllib
        server_config = tomllib.loads((home / 'config.toml').read_text())['mcp_servers']['ai_security_runtime']
        params = StdioServerParameters(command=server_config['command'], args=server_config['args'],
            env={**env, **server_config['env']}, cwd=roots[0])
        episodes = []; previous_a = None
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    names = {t.name for t in (await client.list_tools()).tools}
                    assert {'handle_hook_event', 'handle_readiness_event', 'handle_stop_event', 'prepare_task_fix'} <= names
                    async def call(name, arguments):
                        r = await client.call_tool(name, invocation_claims(name, arguments))
                        assert not r.isError, name
                        data = r.structuredContent or json.loads(r.content[0].text)
                        return data.get('result', data)
                    async def bootstrap(root, session):
                        claims = {'event': 'SessionStart', 'workspace_path': str(root / 'src'), 'session_id': session}
                        first = await call('handle_readiness_event', claims)
                        assert first['status'] == 'INITIALIZING'
                        deadline = time.monotonic() + 90
                        while time.monotonic() < deadline:
                            current = await call('handle_readiness_event', claims)
                            if current['status'] != 'INITIALIZING':
                                assert current['status'] == 'READY', current
                                return
                            # Polling an actual background baseline, not fake
                            # scanner time or a performance benchmark.
                            await asyncio.sleep(.05)
                        raise RuntimeError('BOOTSTRAP_DID_NOT_CONVERGE')
                    for root, session in zip(roots[:2], ('session-a', 'session-b')):
                        await bootstrap(root, session)
                        if root == roots[0]:
                            missing = await call('get_security_summary', {})
                            assert missing['reason_code'] == 'WORKSPACE_CLAIM_REQUIRED'
                            report['single_admitted_workspace_missing_claim'] = 'REJECTED'
                    baseline_databases = list((parent / 'state/global-workspaces').glob('*/scans.db'))
                    assert len(baseline_databases) == 2
                    for database in baseline_databases:
                        with closing(sqlite3.connect(database)) as connection:
                            assert connection.execute('SELECT count(*) FROM scans').fetchone()[0] == 0
                            assert connection.execute('SELECT count(*) FROM findings').fetchone()[0] == 0
                    report['initial_baseline_projection_only'] = 'PASS'
                    for index, number in ((0, 1), (1, 1), (0, 2)):
                        root = roots[index]; target = targets[index]; session = ('session-a', 'session-b')[index]
                        claims = {'event': 'PostToolUse', 'workspace_path': str(root / 'src'), 'session_id': session, 'tool_name': 'apply_patch'}
                        target.write_bytes(UNSAFE.encode())
                        hook = await call('handle_hook_event', claims)
                        grant = await approve_reported_risk(call, hook['remediation'], target)
                        ticket = grant['agent_fix_ticket']
                        assert grant['action'] == 'AUTO_FIX' and ticket['mode'] == 'INLINE_PREPARED'
                        assert grant['episode_number'] == number
                        assert ticket['task_ref'] == grant['prepare']['arguments']['task_ref']
                        assert ticket['remediation_ref'] == grant['prepare']['arguments']['remediation_ref']
                        if index == 0 and number == 1:
                            foreign = await call('prepare_task_fix', {'workspace_path': str(roots[1]),
                                'task_ref': ticket['task_ref'], 'remediation_ref': ticket['remediation_ref']})
                            assert foreign.get('status') != 'READY_FOR_HOST_FIX'
                            report['cross_workspace_opaque_refs'] = 'REJECTED'
                        if index == 0 and previous_a:
                            assert ticket['episode_id'] != previous_a['episode_id']
                        # Simulated Host applies only the fixture's signed target
                        # edit; no Runtime product source-writing tool is added.
                        assert target.read_bytes() == UNSAFE.encode()
                        target.write_bytes(SAFE.encode())
                        closed = await call('handle_hook_event', claims)
                        receipt = closed['remediation']['security_verification']
                        assert receipt['status'] == 'SCANNER_VERIFIED_RESOLVED' and receipt['phase'] == 'CLOSED'
                        assert receipt['task_ref'] == ticket['task_ref']
                        assert closed['remediation']['next_action'] == 'RETURN_TO_HOST'
                        stopped = await call('handle_stop_event', {'event': 'Stop', 'workspace_path': str(root / 'src'),
                            'session_id': session, 'stop_hook_active': False})
                        assert stopped['status'] == 'ALLOW_STOP'
                        episodes.append({'workspace': index + 1, 'episode_number': number,
                            'status': receipt['status'], 'phase': receipt['phase'],
                            'prepare_calls': 0, 'reference_integrity': 'ORIGINAL_VALUES_UNCHANGED',
                            'real_scanner_proof': True, 'functional_verification': 'NOT_REQUESTED',
                            'stop_status': stopped['status'],
                            'initial_scanner_invocations': {n: p['counts']['process_invocations']
                                for n, p in hook['scanner_diagnostics']['providers'].items()}})
                        if index == 0: previous_a = ticket
                    ambiguity = await call('get_security_summary', {})
                    assert ambiguity['reason_code'] == 'WORKSPACE_CLAIM_REQUIRED'
                    report['shared_connection_ambiguous_request'] = 'REJECTED'
        report['episodes'] = episodes
        assert all(not (r / '.codex').exists() for r in roots[:2])
        healthy = json.loads(command([*cli, 'repair', '--json'], roots[0], env))
        assert healthy['operation'] == 'ALREADY_CONFIGURED'
        removed = json.loads(command([*cli, 'uninstall', '--json'], roots[0], env))
        assert removed['overall'] == 'NOT_INSTALLED'
        assert (home / 'config.toml').read_bytes() == user
        assert json.loads((home / 'hooks.json').read_text()) == {'hooks': {'Stop': [{'hooks': [user_hook]}]}}
        report['uninstall_owned_only'] = 'PASS'
        report['temporary_cleanup'] = 'ON_EXIT'
    report.update(status='PASS', duration_seconds=round(time.perf_counter() - start, 2))
    Path(args.output).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--wheel', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--codex')
    asyncio.run(trial(parser.parse_args()))

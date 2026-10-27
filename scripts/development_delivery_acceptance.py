"""Isolated real stdio MCP/scanner delivery check; never changes user settings.

No fixture execution/download/model/desktop timing. Synthetic host events test
the protocol, not actual native desktop Hook invocation or report submission.
"""
import argparse
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from security_runtime.closeout_state import readonly_uri


def unpack(response):
    if response.isError:
        raise AssertionError('MCP rejected the isolated fixture request')
    return response.structuredContent or json.loads(response.content[0].text)


async def verify(parent):
    root, home, private = parent/'project', parent/'home', parent/'private'
    (root/'src').mkdir(parents=True)
    (root/'src/app.js').write_text('export function compute(expression) { return new Function(expression)(); }\n')
    subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True, timeout=30)
    env = dict(os.environ, CODEX_HOME=str(home), SECURITY_RUNTIME_STATE_DIR=str(private),
        SECURITY_RUNTIME_SKILLS_DIR=str(parent/'skills'), SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_WORKSPACE='', SECURITY_RUNTIME_GLOBAL='0', SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS='1')
    for name in ('SECURITY_RUNTIME_CODEX_HOME', 'SECURITY_RUNTIME_INTEGRATION'):
        env.pop(name, None)
    setup = subprocess.run([sys.executable, '-m', 'security_runtime.cli', 'setup', 'codex',
        '--dev', '--path', str(root), '--json'], env=env, cwd=parent, capture_output=True, timeout=120)
    if setup.returncode or json.loads(setup.stdout)['mcp']['status'] != 'CONFIGURED':
        raise AssertionError('Isolated setup failed')
    entry = tomllib.loads((home/'config.toml').read_text())['mcp_servers']['ai_security_runtime']
    params = StdioServerParameters(command=entry['command'], args=entry['args'], env={**env, **entry['env']})
    common = dict(workspace_path=str(root))
    session = 'isolated-delivery-session'
    original = None
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=180)) as client:
            await client.initialize()
            async def call(name, **arguments):
                return unpack(await client.call_tool(name, {**common, **arguments}))
            ready = await call('handle_readiness_event', event='SessionStart', session_id=session)
            token = ready['task_session_ref']
            info = unpack(await client.call_tool('get_runtime_info', dict(view='summary')))
            assert info['features']['development_check_delivery'].startswith('development-result-delivery-v1;')
            row = await call('begin_development_check', task_key='real-stdio-delivery', session_ref=token)
            ref = row['check_ref']
            await call('handle_hook_event', event='PostToolUse', session_id=session, turn_id='fixture-turn',
                tool_use_id='fixture-edit', tool_name='apply_patch',
                tool_input={'command':'*** Begin Patch\n*** Update File: src/app.js\n@@\n-a\n+b\n*** End Patch'})
            first = await call('complete_development_check', check_ref=ref, session_ref=token)
            timed_out = first['status'] in {'QUEUED', 'RUNNING'}
            result = first
            waits = 0
            while result['status'] in {'QUEUED', 'RUNNING'} and waits < 90:
                result = await call('wait_development_check', check_ref=ref, session_ref=token)
                waits += 1
            assert result['status'] in {'RESULTS_READY', 'PARTIAL'}
            assert result['scanned_seq'] == result['dirty_seq'] == 1
            assert result['scope']['paths'] == ['src/app.js'] and not result['scope']['full_project']
            assert result['static_result']['finding_count'] > 0
            listings = await call('get_development_deliveries', session_ref=token)
            assert listings['total'] == 1 and not listings['automatic_host_ack']
            original = await call('get_development_result', check_ref=ref, scanned_seq=1, session_ref=token)
            assert original['delivery']['delivery'] == 'PENDING'
            assert original['static_result']['scan_id'] == result['scan_id']
            assert (await call('wait_development_check', check_ref=ref, session_ref=token))['scan_id'] == result['scan_id']
    # A fresh MCP process must recover delivery with the same verified native owner.
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=180)) as client:
            await client.initialize()
            ready_response = await client.call_tool('handle_readiness_event', dict(
                **common, event='SessionStart', session_id=session))
            ready = unpack(ready_response)
            assert ref in ready_response.content[0].text
            routed = dict(**common, session_ref=ready['task_session_ref'])
            restored = unpack(await client.call_tool('get_development_result', dict(
                **routed, check_ref=ref, scanned_seq=1)))
            assert restored == original
            other = unpack(await client.call_tool('handle_readiness_event', dict(
                **common, event='SessionStart', session_id='isolated-other-session')))
            hidden = unpack(await client.call_tool('get_development_deliveries', dict(
                **common, session_ref=other['task_session_ref'])))
            assert hidden['total'] == 0
    scans = []
    for path in private.rglob('scans.db'):
        with sqlite3.connect(readonly_uri(path), uri=True) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='scans'").fetchone():
                scans.extend(db.execute('SELECT id FROM scans').fetchall())
    assert len(scans) == 1
    return dict(contract='development-delivery-stdio-acceptance-v1', passed=True,
        build_id=info['build_identity']['build_id'], initial_wait_timed_out=timed_out,
        wait_calls=waits, scans=len(scans), observed_files=1,
        cases=['single_submission', 'scoped_real_scan', 'saved_risk_result', 'no_rescan_on_wait',
               'pending_not_auto_acked', 'new_process_original_version', 'reconnect_context', 'other_owner_hidden'],
        limitations=['Synthetic events; not native desktop or AI report delivery.',
                     'No model, fixture execution or downloads; no full-chat speed claim.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # A retiring detached worker can still release Windows lock directories.
    # Keep that cleanup outcome separate from protocol verification, never let
    # cleanup erase the actual acceptance report or mask an assertion failure.
    with tempfile.TemporaryDirectory(prefix='development-delivery-mcp-', ignore_cleanup_errors=True) as directory:
        report = asyncio.run(verify(Path(directory).resolve()))
    report['temporary_cleanup'] = 'COMPLETE' if not Path(directory).exists() else 'PENDING_WINDOWS_RETIREMENT'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

"""Verify a real managed checkout through a separate experimental MCP process.

Reads the current installation's configuration without changing it. Task state
and receipts are isolated under the fresh output directory. No source edit,
scanner, model, installer or configuration repair is invoked by this smoke test.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys


def payload(result):
    value = result.structuredContent or json.loads(result.content[0].text)
    return value.get('result', value)


def config_hashes(home):
    return {name: hashlib.sha256((home/name).read_bytes()).hexdigest()
            if (home/name).is_file() else None for name in ('config.toml', 'hooks.json')}


def serve(state):
    from security_runtime.global_integration import GlobalCodexIntegration
    from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
    # The installed configuration is observed; this experiment never edits it.
    integration = GlobalCodexIntegration()
    pool = GlobalWorkspaces(base=state, integration=integration)
    try:
        create_global_server(workspaces=pool, include_batch_review=True).run(transport='stdio')
    finally:
        pool.close()


async def verify(workspace, output):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from security_runtime.global_integration import GlobalCodexIntegration
    from security_runtime.global_workspace import resolve_workspace

    integration = GlobalCodexIntegration()
    home = integration.home
    before = config_hashes(home)
    original_gitfile = (workspace/'.git').read_bytes()
    resolved = resolve_workspace(workspace, codex_home=home)
    health = integration.configuration_status()['overall']
    if resolved != workspace or health != 'CONFIGURED':
        raise RuntimeError('Experimental admission or installed configuration is unavailable')
    parameters = StdioServerParameters(command=sys.executable, args=['-P', str(Path(__file__).resolve()),
        '--serve', '--output', str(output)], cwd=output,
        env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1]/'src'),
             'PYTHONSAFEPATH': '1', 'SECURITY_RUNTIME_OFFLINE': '1'})
    with (output/'mcp-stderr.log').open('w', encoding='utf-8') as errors:
        async with stdio_client(parameters, errlog=errors) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                await asyncio.wait_for(client.initialize(), timeout=15)
                listed = await asyncio.wait_for(client.list_tools(), timeout=10)
                tools = {tool.name for tool in listed.tools}
                assert {'begin_security_task', 'finish_security_task', 'prepare_security_batch'} <= tools
                begin = payload(await asyncio.wait_for(client.call_tool('begin_security_task',
                    dict(workspace_path=str(workspace), task_key='managed-worktree-admission-smoke')), timeout=30))
                if begin.get('status') != 'ACTIVE':
                    raise RuntimeError('Managed worktree task did not start: '+str(begin.get('reason_code')))
                finish = payload(await asyncio.wait_for(client.call_tool('finish_security_task',
                    dict(workspace_path=str(workspace), task_ref=begin['task_ref'])), timeout=30))
                rejected = payload(await asyncio.wait_for(client.call_tool('begin_security_task',
                    dict(workspace_path=str(home), task_key='host-state-negative-control')), timeout=10))
    checks = dict(
        managed_worktree_task_active=begin['status'] == 'ACTIVE',
        task_baseline_established=begin.get('baseline_file_count', 0) > 0,
        unchanged_task_finished=finish.get('status') == 'NO_CHANGES',
        no_static_scan=begin.get('scanner_run') is False and finish.get('scanner_run') is False,
        codex_state_still_rejected=rejected.get('reason_code') == 'WORKSPACE_OUTSIDE_ALLOWED_ROOT',
        rejection_stage_preserved=rejected.get('workspace_binding_stage') == 'RESOLVING_ROOT',
        global_configuration_unchanged=before == config_hashes(home),
        managed_gitfile_unchanged=original_gitfile == (workspace/'.git').read_bytes(),
    )
    receipt = dict(contract='managed-worktree-admission-smoke-v1', passed=all(checks.values()),
        checks=checks, workspace=str(workspace), experimental_source=str(Path(__file__).resolve().parents[1]),
        installed_configuration=health, baseline_file_count=begin.get('baseline_file_count'),
        rejected_directory_message='Host state directory remains outside the project boundary.',
        model_calls=0, static_scans=0, note='Separate NO_CHANGES smoke task; not a review of preceding development edits.')
    (output/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--serve', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        serve(args.output.resolve()/'workspace-state')
        return 0
    if args.workspace is None:
        parser.error('--workspace is required')
    args.output.mkdir(parents=True, exist_ok=False)
    result = asyncio.run(asyncio.wait_for(verify(args.workspace.resolve(), args.output.resolve()), timeout=90))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

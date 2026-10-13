"""Real frozen install -> detached online preparation -> saved closeout MCP.

Isolated caches/config only. Never calls Hook handlers or counts as desktop proof.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from security_runtime.delivery import package_metadata
from security_runtime.trial import TrialProfile, isolated_environment
from install_flow_acceptance import execute


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


async def accept(bundle, output, tools, old_db):
    output = output.resolve()
    output.mkdir(exist_ok=False)
    profile = output/'profile'
    TrialProfile(profile).create()
    original = {p.name: sha(p) for p in old_db.iterdir() if p.is_file()}
    # Fresh isolated profile with no DB: the user's cache may already be fresh.
    # Never alter its metadata or clear it to manufacture a download.
    env = dict(isolated_environment(profile), SECURITY_RUNTIME_OFFLINE='0',
        SECURITY_RUNTIME_SEMGREP_PATH=str(Path(os.environ['LOCALAPPDATA'])/'Programs/Python/Python312/Scripts/semgrep.exe'),
        SECURITY_RUNTIME_GITLEAKS_PATH=str(tools/'tools/gitleaks/8.30.0/gitleaks.exe'),
        SECURITY_RUNTIME_TRIVY_PATH=str(tools/'tools/trivy/0.74.0/trivy.exe'))
    root = profile/'workspace'
    subprocess.run(['git', 'init', '-q', str(root)], capture_output=True, check=True)
    path = root/'fixture.ts'
    path.write_text('// Original file before background preparation\nexport const value = 1;\n')
    subprocess.run(['git', '-C', str(root), 'add', '.'], capture_output=True, check=True)
    metadata = package_metadata(bundle)
    installed, install = execute([str(bundle/'security-check.exe'), 'install', 'codex',
        '--root', str(profile/'program'), '--json'], profile, env)
    (output/'install.json').write_text(json.dumps({'receipt': installed, 'execution': install}, ensure_ascii=False, indent=2), encoding='utf-8')
    assert install['exit_code'] == 0 and installed['installation']['local_files_ready']
    assert not installed['installation']['scan_ready']
    assert installed['background_preparation']['status'] in {'QUEUED', 'PREPARING'}
    launcher = Path(installed['delivery']['launcher'])
    owned = [profile/'codex-home/config.toml', profile/'codex-home/hooks.json', profile/'skills/ai-security-review/SKILL.md']
    unchanged = {str(p): (sha(p), p.stat().st_mtime_ns) for p in owned}
    repeated, repeat = execute([str(launcher), 'install', 'codex', '--json'], profile, env)
    (output/'repeat.json').write_text(json.dumps({'receipt': repeated, 'execution': repeat}, ensure_ascii=False, indent=2), encoding='utf-8')
    assert repeated['background_preparation']['job_id'] == installed['background_preparation']['job_id']
    assert repeated['background_preparation']['reused']
    # Use the actual global routing path; resumed MCP must reopen this workspace's
    # original store and hooks, rather than invent a second database.
    mcp_env = dict(env, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_MCP_SELF_TEST='1')
    params = StdioServerParameters(command=str(launcher), args=['mcp'], env=mcp_env, cwd=root)
    frames, calls, job = [], [], None
    started = time.monotonic()
    with (output/'mcp-stderr.txt').open('w', encoding='utf-8') as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                async def call(name, args):
                    assert name not in {'handle_hook_event', 'handle_readiness_event', 'handle_stop_event'}
                    began = time.monotonic()
                    response = await client.call_tool(name, args)
                    assert not response.isError, name
                    calls.append({'tool': name, 'elapsed_seconds': round(time.monotonic()-began, 3)})
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                info = await call('get_runtime_info', {})
                assert info['build_identity']['build_id'] == metadata['build_id']
                quick = await call('scan_diff', {'workspace_path': str(root), 'mode': 'quick'})
                assert quick['background_preparation']['background_registered']
                ref = quick['background_preparation']['closeout_ref']
                before = await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref})
                assert before['status'] == 'PENDING' and before['attempts'] == 0
                # Real native filesystem edit while the true download is running.
                # It is not a simulated Hook event and is reported separately.
                path.write_text('// Latest file while background download runs\nexport const value = 2;\n')
                assert (await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref}))['current_version'] is False
                deadline = time.monotonic()+1900
                while time.monotonic() < deadline:
                    status = await call('get_scan_preparation_status', {})
                    frame = {k: status.get(k) for k in ('status', 'ready', 'stage', 'progress', 'estimate', 'updated_at')}
                    if not frames or frame != frames[-1]:
                        frames.append(frame)
                        (output/'progress.json').write_text(json.dumps(frames, ensure_ascii=False, indent=2), encoding='utf-8')
                    if status['status'] not in {'QUEUED', 'PREPARING', 'RESUMING'}:
                        break
                    await asyncio.sleep(2)
                assert status['status'] == 'READY' and status['receipt']['ready'], status
                job = await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref})
                # No manual run_closeout_check or prepare-scanners in this script.
                assert job['status'] == 'COMPLETED' and job['current_version'], job
                assert job['generation'] > before['generation']
                assert job['receipt']['execution_origin'] == 'BACKGROUND_PREPARATION_MCP'
                assert job['receipt']['source'] == 'MANUAL_QUICK_PREPARATION_PENDING'
                path.write_text('// A new edit after background closeout\nexport const value = 3;\n')
                invalidated = await call('get_closeout_status', {'workspace_path': str(root), 'closeout_ref': ref})
                assert not invalidated['current_version']
    final_cache = {p.name: sha(p) for p in old_db.iterdir() if p.is_file()}
    assert original == final_cache
    assert unchanged == {str(p): (sha(p), p.stat().st_mtime_ns) for p in owned}
    result = dict(status='PASS', build_id=metadata['build_id'], source_commit=metadata['source_commit'],
        source_dirty=metadata['source_dirty'], transport='REAL_FROZEN_GLOBAL_MCP_AND_DETACHED_WORKER',
        install=install, installation_receipt=installed, repeat=repeat, repeated_receipt=repeated,
        preparation=status, final_closeout=job, original_closeout=before, latest_edit_invalidates_receipt=True,
        calls=calls, progress_frames=len(frames), eta_observed=any(f.get('estimate') for f in frames),
        total_after_install_seconds=round(time.monotonic()-started, 3), original_cache_preserved=True,
        owned_configuration_preserved=True, global_installation_modified=False,
        manual_prepare_or_closeout_run=False, manual_hook_handler_called=False,
        synchronous_hook='尚未通过', hook_scheduled_closeout='尚未通过',
        desktop_automatic_hook='尚未通过', user_prompt_latency='未测得')
    (output/'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'build_id', 'eta_observed', 'progress_frames', 'total_after_install_seconds')}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('bundle', 'output', 'tools', 'old-db'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(accept(args.bundle.resolve(), args.output, args.tools.resolve(), args.old_db.resolve()))

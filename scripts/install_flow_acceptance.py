"""Real frozen install/MCP and optional public-data probe in an isolated profile."""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import threading
import time

from security_runtime.delivery import package_metadata
from security_runtime.install_readiness import validate_readiness_receipt
from security_runtime.toolchain import VERSIONS, sha256_file
from security_runtime.trial import TrialProfile, isolated_environment


def execute(command, root, env, timeout=150):
    started = time.monotonic()
    feedback = []
    captured = []
    with subprocess.Popen(command, cwd=root / 'workspace', env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        def observe():
            while line := process.stderr.readline(8192):
                if len(feedback) < 1000:
                    feedback.append({'elapsed_seconds': round(time.monotonic() - started, 3),
                        'message': line.decode('utf-8', errors='replace').strip()})
        thread = threading.Thread(target=observe, daemon=True)
        reader = threading.Thread(target=lambda: captured.append(process.stdout.read(256_001)), daemon=True)
        thread.start()
        reader.start()
        try:
            process.wait(timeout=timeout)
        except BaseException:
            # Use the system process-tree utility, never kill unrelated MCPs.
            import os
            subprocess.run([str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/taskkill.exe'),
                '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=5)
            process.wait(timeout=5)
            raise
        finally:
            thread.join(timeout=3)
            reader.join(timeout=3)
        assert not thread.is_alive() and not reader.is_alive() and captured
        stdout = captured[0]
        assert len(stdout) <= 256_000
        data = json.loads(stdout)
    return data, {'exit_code': process.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
        'stderr_feedback': feedback, 'user_prompt_latency': '未测得'}


async def mcp_identity(executable, env):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    async with stdio_client(StdioServerParameters(command=str(executable), args=['mcp'], env=env)) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            info = (await session.call_tool('get_runtime_info', {})).structuredContent
            guide = (await session.call_tool('get_professional_guidance', {})).structuredContent
            assert guide['status'] == 'READY'
            assert hashlib.sha256(guide['content'].encode()).hexdigest() == guide['content_sha256']
            return {'tools': len(tools.tools), 'runtime_info': info, 'guidance_verified': True}


def main(bundle, output, tool_root=None, cached_db=None):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profile = output / 'profile with spaces 中文'
    TrialProfile(profile).create()
    env = isolated_environment(profile)
    metadata = package_metadata(bundle)
    program = profile / 'program'
    config = profile / 'codex-home/config.toml'
    original = b'# isolated retained user preference\nmodel="fixture-user-model"\n'
    config.write_bytes(original)
    first, install = execute([str(bundle / 'security-check.exe'), 'install', 'codex',
        '--root', str(program), '--json'], profile, env)
    assert install['exit_code'] == 0 and first['installation']['local_files_ready']
    assert not first['installation']['scan_ready'] and first['installation']['status'] == 'INSTALLED'
    assert first['execution']['network_query'] is False
    assert 'CHECK_SCAN_CACHE' not in ''.join(item['message'] for item in install['stderr_feedback'])
    assert install['stderr_feedback'][0]['elapsed_seconds'] < 5
    assert config.read_bytes().startswith(original)
    launcher = Path(first['delivery']['launcher'])
    owned = [config, profile / 'codex-home/hooks.json', profile / 'skills/ai-security-review/SKILL.md']
    before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in owned}
    repeat, repeated = execute([str(launcher), 'install', 'codex', '--json'], profile, env)
    assert repeated['exit_code'] == 0 and repeat['installation']['local_files_ready']
    assert before == {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in owned}
    status, inspected = execute([str(launcher), 'prepare-scanners', '--status', '--json'], profile, env)
    assert inspected['exit_code'] == 2 and not status['ready'] and status['network_allowed'] is False
    assert validate_readiness_receipt(status)
    mcp = asyncio.run(asyncio.wait_for(mcp_identity(launcher,
        dict(env, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_INTEGRATION='codex')), timeout=60))
    assert mcp['runtime_info']['build_id'] == metadata['build_id']
    result = dict(status='PASS', build_id=metadata['build_id'], source_commit=metadata['source_commit'],
        install=install, repeated_install=repeated, status_check=inspected, mcp=mcp,
        real_global_installation_modified=False, desktop_automatic_hook='尚未通过；本脚本没有宿主 Hook 事件')
    if tool_root is not None and cached_db is not None:
        cache = profile / 'engines/cache/trivy'
        shutil.copytree(cached_db, cache / 'db')
        old = {p.name: sha256_file(p) for p in (cache / 'db').iterdir() if p.is_file()}
        binaries = dict(semgrep=tool_root / f'engines/semgrep/{VERSIONS["semgrep"]}/runtime/Scripts/semgrep.exe',
            gitleaks=tool_root / f'tools/gitleaks/{VERSIONS["gitleaks"]}/gitleaks.exe',
            trivy=tool_root / f'tools/trivy/{VERSIONS["trivy"]}/trivy.exe')
        if not binaries['semgrep'].is_file():
            binaries['semgrep'] = tool_root.parent / 'Programs/Python/Python312/Scripts/semgrep.exe'
        assert all(p.is_file() for p in binaries.values())
        online = dict(env, SECURITY_RUNTIME_OFFLINE='0',
            **{f'SECURITY_RUNTIME_{name.upper()}_PATH': str(path) for name, path in binaries.items()})
        checked, check = execute([str(launcher), 'prepare-scanners', '--status', '--json'], profile, online)
        assert all(c['ready'] for c in checked['tools'].values())
        assert checked['vulnerability_db']['cached_usable'] and not checked['ready']
        prepared, probe = execute([str(launcher), 'prepare-scanners', '--timeout', '20', '--json'], profile, online, timeout=40)
        assert validate_readiness_receipt(prepared) and prepared['preparation']['attempts'] <= 1
        assert probe['elapsed_seconds'] < 35
        assert any('下载进度' in item['message'] for item in probe['stderr_feedback'])
        after = {p.name: sha256_file(p) for p in (cache / 'db').iterdir() if p.is_file()}
        if not prepared['ready']:
            assert probe['exit_code'] == 2 and prepared['vulnerability_db']['cached_usable']
            assert after == old
        else:
            assert probe['exit_code'] == 0 and prepared['vulnerability_db']['freshness'] == 'FRESH'
        assert before == {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in owned}
        result['public_data_probe'] = dict(receipt=prepared, execution=probe,
            isolated_cached_database_preserved=after == old, full_online_preparation_passed=prepared['ready'])
    (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'build_id', 'source_commit', 'real_global_installation_modified')}, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tool-root', type=Path)
    parser.add_argument('--cached-db', type=Path)
    args = parser.parse_args()
    if bool(args.tool_root) != bool(args.cached_db):
        parser.error('--tool-root and --cached-db must be supplied together')
    main(args.bundle.resolve(), args.output, args.tool_root, args.cached_db)

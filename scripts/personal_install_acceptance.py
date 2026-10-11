"""Exercise a real local Windows bundle without touching the real global installation."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import tomllib
import shutil

from security_runtime.delivery import package_metadata, EXE, encode
from security_runtime.delta_delivery import make_update
from security_runtime.hook_state import atomic_bytes, no_links
from security_runtime.trial import TrialProfile, isolated_environment


def receipt(command, root, env):
    # Observe feedback while the real EXE is running, not merely after exit.
    started = time.monotonic()
    feedback, stdout = [], []
    with subprocess.Popen(command, cwd=root / 'workspace', env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        def read_feedback():
            while line := process.stderr.readline(8192):
                if len(feedback) < 1000:
                    feedback.append((time.monotonic() - started, line.decode('utf-8', errors='replace').strip()))
        def read_stdout():
            stdout.append(process.stdout.read(256_001))
        readers = [threading.Thread(target=read_feedback), threading.Thread(target=read_stdout)]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=180)
        except BaseException:
            process.kill()
            process.wait(timeout=10)
            raise
        finally:
            for reader in readers:
                reader.join(timeout=10)
        assert all(not reader.is_alive() for reader in readers)
        assert stdout and len(stdout[0]) <= 256_000, 'bounded receipt exceeded'
        data = json.loads(stdout[0])
        assert process.returncode == 0, (process.returncode, data.get('diagnostics'), feedback[-4:])
    progress = [(elapsed, line) for elapsed, line in feedback if line.startswith('[安装]')]
    assert progress and progress[0][0] < 5, 'immediate progress missing'
    assert '开始安装' in progress[0][1]
    assert any('本地安装完成' in line for _, line in progress)
    assert not any('安装未完成' in line for _, line in progress)
    assert '%' not in ''.join(line for _, line in progress)
    return data, {'first_feedback_seconds': round(progress[0][0], 3),
                  'total_seconds': round(time.monotonic() - started, 3),
                  'progress_lines': len(progress), 'json_stdout_clean': True,
                  'completion_feedback': True}


async def mcp_contract(launcher, env):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    parameters = StdioServerParameters(command=str(launcher), args=['mcp'], env=env)
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = {t.name: t for t in (await session.list_tools()).tools}
            assert 'get_professional_guidance' in tools
            assert 'workspace_path' not in tools['get_professional_guidance'].inputSchema.get('properties', {})
            response = await session.call_tool('get_professional_guidance', {})
            guide = response.structuredContent
            assert guide['status'] == 'READY' and guide['source'] == 'BUNDLED'
            assert hashlib.sha256(guide['content'].encode()).hexdigest() == guide['content_sha256']
            assert not any(guide['execution'].values())
            info = (await session.call_tool('get_runtime_info', {})).structuredContent
            assert info['integration_scope'] == 'GLOBAL'
            assert info['professional_guidance']['remote_fetch_implemented'] is False
            return {'tool_advertised': True, 'source': guide['source'], 'version': guide['version'],
                'content_sha256': guide['content_sha256'], 'state_modified': False, 'network_query': False}


def main(bundle, output):
    metadata = package_metadata(bundle)
    with tempfile.TemporaryDirectory(prefix='runtime-personal-install-') as temporary:
        root = Path(temporary).resolve() / 'profile with spaces 中文'
        TrialProfile(root).create()
        env = isolated_environment(root)
        program = root / 'program with spaces'
        config = root / 'codex-home/config.toml'
        original = b'# retained settings\nmodel="fixture-user-model"\n'
        atomic_bytes(config, original)
        skill = root / 'skills/ai-security-review'
        first, first_progress = receipt([str(bundle / EXE), 'install', 'codex', '--root', str(program), '--json'], root, env)
        assert first['installation']['local_files_ready'] and first['skill']['status'] == 'INSTALLED'
        launcher = Path(first['delivery']['launcher'])
        assert launcher == program / 'launcher' / EXE
        assert config.read_bytes().startswith(original)
        server = tomllib.loads(config.read_text())['mcp_servers']['ai_security_runtime']
        assert server['command'] == str(launcher)
        assert (skill / 'references/deep-audit.md').is_file()
        assert not (root / 'workspace/.codex').exists()
        assert not first['installation']['risk_fix_authorized']
        note = skill / 'notes.md'
        atomic_bytes(note, b'user attached note')
        paths = [config, root / 'codex-home/hooks.json', skill / 'SKILL.md', skill / 'references/deep-audit.md']
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        repeated, repeated_progress = receipt([str(launcher), 'install', 'codex', '--json'], root, env)
        assert repeated['installation']['local_files_ready']
        assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        assert note.read_bytes() == b'user attached note'
        mcp_env = dict(env, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='', SECURITY_RUNTIME_INTEGRATION='codex')
        guide = asyncio.run(asyncio.wait_for(mcp_contract(launcher, mcp_env), timeout=60))
        assert not (root / 'state/global-workspaces').exists()
        # A real differential upgrade, including an in-use previous process.
        candidate = root / 'next bundle'
        shutil.copytree(bundle, candidate)
        changed = candidate / 'WINDOWS_EXPERIENCE.md'
        changed.write_bytes(changed.read_bytes() + b'\nIsolated delta acceptance fixture.\n')
        value = json.loads((candidate / 'version.json').read_bytes())
        value.pop('build_id')
        value['files']['WINDOWS_EXPERIENCE.md'] = hashlib.sha256(changed.read_bytes()).hexdigest()
        value['build_id'] = hashlib.sha256(encode(value)).hexdigest()
        (candidate / 'version.json').write_bytes(encode(value))
        update = root / 'update.zip'
        delta = make_update(bundle, candidate, update)
        upgraded, upgrade_progress = receipt([str(launcher), 'install', 'codex', '--update', str(update), '--json'], root, env)
        assert upgraded['delivery']['active_build'] == value['build_id']
        assert upgraded['downloads']['product'] == 'LOCAL_DELTA'
        assert metadata['build_id'] in upgraded['cleanup']['deferred_builds']
        # A real reconnect, not a second install, must retry completed-install GC.
        asyncio.run(asyncio.wait_for(mcp_contract(launcher,
            dict(mcp_env, SECURITY_RUNTIME_MCP_SELF_TEST='0')), timeout=60))
        assert not (program / 'versions' / metadata['build_id']).exists()
        completed, _ = receipt([str(launcher), 'install', 'codex', '--json'], root, env)
        assert completed['installation']['local_files_ready']
        assert not (program / 'versions' / metadata['build_id']).exists()
        assert len(list((program / 'versions').iterdir())) == 1
        # Neither modified bytes nor extra files may execute through the launcher.
        active = program / 'versions' / value['build_id'] / 'bundle'
        original_bytes = (active / 'LICENSE').read_bytes()
        (active / 'LICENSE').write_bytes(original_bytes + b'tamper')
        refused = subprocess.run([str(launcher), 'runtime-info', '--json'], env=env, capture_output=True, timeout=30)
        assert refused.returncode == 2 and not refused.stdout
        (active / 'LICENSE').write_bytes(original_bytes)
        foreign = active / 'foreign.txt'
        foreign.write_bytes(b'foreign')
        refused = subprocess.run([str(launcher), 'runtime-info', '--json'], env=env, capture_output=True, timeout=30)
        assert refused.returncode == 2 and not refused.stdout
        foreign.unlink()
        wrong_base = subprocess.run([str(launcher), 'install', 'codex', '--update', str(update), '--json'],
            env=env, capture_output=True, timeout=30)
        assert wrong_base.returncode == 2
        assert json.loads(wrong_base.stdout)['diagnostics'] == ['DELTA_BASE_MISMATCH']
        result = {'status': 'PASS', 'package_build_id': metadata['build_id'],
            'personal_install_contract': first['installation']['contract'],
            'first_install_skill': 'INSTALLED', 'repeat_install': 'IDEMPOTENT',
            'global_command': 'FIXED_VALIDATED_LAUNCHER', 'professional_guidance': guide,
            'installation_progress': {'first_install': first_progress, 'repeat_install': repeated_progress},
            'delta_upgrade': {'status': 'PASS', **delta, 'progress': upgrade_progress,
                'in_use_slot_deferred_then_removed': True, 'wrong_base_rejected': True},
            'reconnect_cleanup': 'PASS_REAL_NON_SELF_TEST_MCP',
            'native_launcher': {'bytes': launcher.stat().st_size,
                'runtime_not_duplicated': (launcher.parent / 'launcher.json').is_file(),
                'modified_bytes_rejected': True, 'extra_files_rejected': True,
                'spaces_unicode_long_paths': True},
            'user_content_preserved': True, 'project_config_written': False,
            'real_global_installation_modified': False, 'risk_fix_authorized': False,
            'scanner_run': False, 'target_build': False, 'source_upload': False,
            'desktop': 'PENDING_HOST_RESTART_DISCOVERY_AND_TRUST', 'public_download_installer': 'NOT_PUBLISHED'}
    no_links(output)
    atomic_bytes(output, json.dumps(result, ensure_ascii=False, indent=2).encode())
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.bundle.absolute(), args.output.absolute())

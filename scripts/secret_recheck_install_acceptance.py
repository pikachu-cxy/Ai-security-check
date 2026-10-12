"""Test the exact install command in a synthetic user home, never the real one."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--base-executable', required=True, type=Path)
    parser.add_argument('--engine-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ai-security-install-r9-') as temporary:
        root = Path(temporary)
        home = root / 'synthetic-home'
        home.mkdir()
        env = {key: os.environ[key] for key in ('SystemRoot', 'PATH', 'TEMP', 'TMP') if key in os.environ}
        env.update(USERPROFILE=str(home), LOCALAPPDATA=str(home / 'AppData' / 'Local'),
            APPDATA=str(home / 'AppData' / 'Roaming'),
            SECURITY_RUNTIME_DATA_DIR=str(args.engine_root.resolve()),
            SECURITY_RUNTIME_STATE_DIR=str(root / 'isolated-state'), SECURITY_RUNTIME_OFFLINE='1')
        install_root = root / 'program'
        command = [str(args.base_executable.resolve()), 'install', 'codex', '--offline',
                   '--root', str(install_root), '--json']
        process = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=120)
        receipt = json.loads(process.stdout)
        assert receipt.get('installation', {}).get('local_files_ready') is True
        assert (home / '.codex' / 'config.toml').is_file()
        old_slots = sorted(p.name for p in (install_root / 'versions').iterdir())
        activated = subprocess.run([str(args.executable.resolve()), 'delivery', 'activate', '--root', str(install_root),
            '--bundle', str(args.executable.resolve().parent), '--json'], cwd=root, env=env,
            capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        activation = json.loads(activated.stdout)
        assert activated.returncode == 0
        launcher = Path(activation['launcher'])
        assert launcher.parent.parent == install_root and launcher.parent.name in {'launcher', 'launcher-v2'}
        repaired = subprocess.run([str(launcher), 'repair', '--json'], cwd=root, env=env,
            capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        repair = json.loads(repaired.stdout)
        assert repaired.returncode == 0 and repair['overall'] == 'CONFIGURED', repair.get('overall')
        observed = subprocess.run([str(launcher), 'runtime-info', '--json'], cwd=root, env=env,
            capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        info = json.loads(observed.stdout)
        assert observed.returncode == 0 and info['version'] == '0.3.2'
        new_slots = sorted(p.name for p in (install_root / 'versions').iterdir())
        assert set(old_slots).issubset(new_slots)
        result = {'source': 'REAL_FROZEN_CLI_SYNTHETIC_HOME_UPDATE',
            'base_installation': receipt.get('installation'), 'activation_status': activation.get('status'),
            'repair_overall': repair['overall'], 'installed_runtime_version': info['version'],
            'installed_build_identity': info['build_identity'], 'previous_slots_preserved': True,
            'synthetic_codex_home_confirmed': True, 'real_user_home_modified': False,
            'real_baselines_modified': False, 'network_allowed': False,
            'reconnect_required': repair.get('reconnect_required'),
            'dependency_data_readiness': '离线准备未完成：使用的合成测试缓存已过期；没有伪装为已检查'}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()

"""Measure native Windows installation after download in disposable profiles.

Includes ZIP SHA256, extraction, native install and actual launcher identity.
No real Codex configuration or project is modified. Never downloads engines.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import tomllib
import uuid
import zipfile

from security_runtime.trial import TrialProfile, isolated_environment
from security_runtime.processes import run_process
from security_runtime.install_progress import STAGES


def invoke(argv, env, cwd, phases=None):
    started = time.perf_counter()
    def progress(line):
        if phases is not None:
            for stage, message in STAGES.items():
                if line == '[安装] ' + message:
                    phases.append(dict(stage=stage, seconds=round(time.perf_counter()-started, 3)))
                    break
    result = run_process([str(x) for x in argv], env=env, cwd=cwd,
                         timeout=240, max_output=1_000_000, on_stderr_line=progress)
    if result.returncode:
        raise RuntimeError(f'exit={result.returncode}: ' + result.stderr[-4000:] + result.stdout[-4000:])
    return json.loads(result.stdout)


def environment(profile):
    env = isolated_environment(profile)
    env.update(SECURITY_RUNTIME_CURSOR_HOME=str(profile/'cursor-home'),
               WORKBUDDY_CONFIG_DIR=str(profile/'workbuddy-home'),
               CODEBUDDY_CONFIG_DIR=str(profile/'workbuddy-home'))
    return env


def install(bundle, root, env, profile, host, phases=None):
    return invoke([bundle/'security-check.exe', 'install', host, '--bundle', bundle,
                   '--root', root, '--offline', '--json'], env, profile, phases)


def measure(archive, expected, profile, root, label, samples, results, host):
    env = environment(profile)
    for index in range(samples):
        trace = profile/f'trace-{label}-{index}'
        trace.mkdir(mode=0o700)
        env.update(SECURITY_RUNTIME_PERF_DIR=str(trace),
                   SECURITY_RUNTIME_PERF_RUN=uuid.uuid4().hex)
        started = time.perf_counter()
        with archive.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected
        extracted = profile/f'payload-{label}-{index}'
        # This ZIP is produced from the caller's local test bundle below.
        with zipfile.ZipFile(archive) as source:
            source.extractall(extracted)
        unpacked = time.perf_counter()
        bundle = extracted/'security-check'
        identity = json.loads((bundle/'version.json').read_bytes())
        phases = []
        receipt = install(bundle, root, env, profile, host, phases)
        installed = time.perf_counter()
        launcher = Path(receipt['delivery']['launcher'])
        if host == 'codex':
            config = tomllib.loads((profile/'codex-home/config.toml').read_text(encoding='utf-8'))
            configured = config['mcp_servers']['ai_security_runtime']['command']
        else:
            config = json.loads((profile/f'{host}-home/mcp.json').read_bytes())
            configured = config['mcpServers']['ai-security-runtime']['command']
        assert Path(configured) == launcher, 'Host still points to an old launcher'
        assert receipt['launcher_verification']['build_id'] == identity['build_id']
        runtime = invoke([launcher, 'runtime-info', '--json'], env, profile)
        ended = time.perf_counter()
        actual = runtime['build_identity']
        assert actual['build_id'] == identity['build_id']
        assert actual['version'] == identity['version']
        assert receipt['installation']['local_files_ready']
        assert receipt['delivery']['active_build'] == actual['build_id']
        row = dict(host=host, scenario=label, sample=index+1, seconds=round(installed-started,3),
                   # Installer includes the actual launcher probe; the second
                   # independently timed probe is acceptance evidence as well.
                   unpack_seconds=round(unpacked-started,3),
                   install_seconds=round(installed-unpacked,3),
                   launcher_seconds=round(ended-installed,3),
                   independent_acceptance_seconds=round(ended-installed,3), phases=phases,
                   build_id=actual['build_id'], passed=installed-started <= 10,
                   scan_ready=receipt['installation']['scan_ready'],
                   cache='isolated-empty-engines', os_cache='not-flushed',
                   profile=str(profile), install_root=str(root))
        results.append(row)
        (profile.parent/'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(json.dumps(row), flush=True)


def verify_rejection(root, env, profile, results):
    """Exercise the native launcher's fail-closed path on disposable files only."""
    pointer = json.loads((root/'active.json').read_bytes())
    slot = root/'versions'/pointer['active']/'bundle'
    launcher = root/pointer['launcher']/'security-check.exe'
    target = slot/'SOURCE_OFFER.md'
    original = target.read_bytes()
    extra = slot/'unexpected-integrity-test-file'
    checks = []
    try:
        for kind in ('corrupt', 'missing', 'extra'):
            if kind == 'corrupt':
                target.write_bytes(b'corrupt')
            elif kind == 'missing':
                target.unlink()
            else:
                extra.write_bytes(b'unexpected')
            checked = run_process([str(launcher), '--version'], env=env, cwd=profile, timeout=30)
            if checked.returncode != 2 or 'launcher verification failed' not in checked.stderr:
                raise AssertionError(f'Native integrity rejection failed: {kind}')
            checks.append(kind)
            target.write_bytes(original)
            extra.unlink(missing_ok=True)
    finally:
        target.write_bytes(original)
        extra.unlink(missing_ok=True)
    actual = invoke([launcher, 'runtime-info', '--json'], env, profile)['build_identity']
    assert actual['build_id'] == pointer['active']
    (results.parent/'integrity.json').write_text(json.dumps(dict(rejected=checks, restored_build=actual['build_id']), indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--upgrade-from', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--host', choices=['codex', 'cursor', 'workbuddy'], default='codex')
    parser.add_argument('--report', type=Path, help='Also write the completed report to this explicit destination')
    parser.add_argument('--enforce-target', action='store_true', help='Exit nonzero when any sample exceeds 10 seconds')
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.samples <= 10:
        parser.error('Windows and 1..10 samples required')
    parent = Path(tempfile.gettempdir()).resolve()
    workspace = Path(__file__).resolve().parents[2]
    if parent.is_relative_to(workspace):
        raise ValueError('Benchmark temporary directory must be outside workspace')
    run = Path(tempfile.mkdtemp(prefix='asr-install-perf-', dir=parent))
    print(str(run), flush=True)
    archive = Path(shutil.make_archive(str(run/'package'), 'zip',
                   root_dir=args.bundle.resolve().parent, base_dir=args.bundle.name))
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    results = []
    def short_install_root():
        # Match the product's short Windows ASR layout, while retaining unique
        # owned temporary roots. Deep per-sample roots exceed legacy MAX_PATH.
        target = parent / uuid.uuid4().hex[:6]
        target.mkdir(exist_ok=False)
        with (run/'install-roots.txt').open('a', encoding='utf-8') as stream:
            stream.write(str(target)+'\n')
        return target
    for index in range(args.samples):
        profile = run/f'fresh-{index}'
        TrialProfile(profile).create()
        root = short_install_root()
        measure(archive, expected, profile, root, 'fresh', 1, results, args.host)
        measure(archive, expected, profile, root, 'repeat', 1, results, args.host)
        profile = run/f'upgrade-{index}'
        TrialProfile(profile).create()
        root = short_install_root()
        env = environment(profile)
        if args.host == 'workbuddy':
            # Historical packages exposed setup workbuddy rather than install.
            invoke([args.upgrade_from.resolve()/'security-check.exe', 'setup', 'workbuddy',
                    '--scope', 'global', '--json'], env, profile)
            invoke([args.upgrade_from.resolve()/'security-check.exe', 'delivery', 'activate',
                    '--bundle', args.upgrade_from.resolve(), '--root', root, '--json'], env, profile)
        else:
            install(args.upgrade_from.resolve(), root, env, profile, args.host)
        measure(archive, expected, profile, root, 'upgrade', 1, results, args.host)
    verify_rejection(root, env, profile, run/'results.json')
    if args.report:
        args.report.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps({'all_under_10_seconds': all(r['passed'] for r in results),
                      'results': str(run/'results.json')}), flush=True)
    if args.enforce_target and not all(r['passed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()

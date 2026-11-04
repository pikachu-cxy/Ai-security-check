"""Run an explicitly selected command and collect opt-in timing outside the repo.

This runner does not choose installation targets, clear caches, or start scans.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
import uuid

PHASES = {'install.'+s for s in ('bootstrap', 'python_prepare', 'python_download',
    'python_verify', 'python_extract', 'python_probe', 'product_download',
    'archive_verify', 'managed_setup', 'cleanup', 'payload_verify', 'venv',
    'offline_dependencies', 'launcher_preflight', 'archive_members', 'archive_extract', 'native_setup')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True, choices=['install-fresh', 'install-cached',
        'install-upgrade', 'install-offline', 'scan-first', 'scan-repeat', 'mcp', 'smoke'])
    parser.add_argument('--cache', required=True, choices=['empty', 'warm', 'unknown'])
    parser.add_argument('--build', required=True, help='Verified build/commit label; no private paths')
    parser.add_argument('--timeout', type=float, default=1800)
    parser.add_argument('--disabled', action='store_true', help='Control run without internal tracing')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 0 < args.timeout <= 7200:
        parser.error('Provide a command after -- and timeout in (0, 7200]')
    root = Path(tempfile.mkdtemp(prefix='asr-performance-')).resolve()
    os.chmod(root, 0o700)
    run = uuid.uuid4().hex
    environment = dict(os.environ)
    environment.pop('SECURITY_RUNTIME_PERF_DIR', None)
    environment.pop('SECURITY_RUNTIME_PERF_RUN', None)
    if not args.disabled:
        environment.update(SECURITY_RUNTIME_PERF_DIR=str(root), SECURITY_RUNTIME_PERF_RUN=run)
    started = time.perf_counter_ns()
    points = []
    # stderr stays visible; only exact fixed markers are retained, never raw output.
    def relay(stream):
        for line in iter(lambda: stream.readline(65536), b''):
            phase = line.decode('ascii', errors='replace').strip().removeprefix('@@ASR_PERF ')
            if line.startswith(b'@@ASR_PERF ') and phase in PHASES:
                points.append({'phase': phase, 'elapsed_ms': (time.perf_counter_ns()-started)/1e6})
            else:
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
    timed_out = False
    process = reader = None
    launch_failed = interrupted = False
    code = 127
    try:
        process = subprocess.Popen(command, env=environment, stderr=subprocess.PIPE)
        reader = threading.Thread(target=relay, args=(process.stderr,), daemon=True)
        reader.start()
        code = process.wait(timeout=args.timeout)
    except OSError:
        launch_failed = True
    except subprocess.TimeoutExpired:
        # Do not kill detached product workers or infer that they completed.
        timed_out = True
        process.kill()
        code = process.wait()
    except KeyboardInterrupt:
        interrupted = True
        if process is not None:
            process.kill()
            process.wait()
        code = 130
    ended = time.perf_counter_ns()
    if reader is not None:
        reader.join(timeout=2)
    manifest = dict(contract='performance-run-v1', run=run, scenario=args.scenario,
        cache_declared=args.cache, build=args.build, platform=platform.system(),
        machine=platform.machine(), python=platform.python_version(),
        instrumentation=not args.disabled, command_wall_ms=(ended-started)/1e6,
        exit_code=code, timed_out=timed_out, launch_failed=launch_failed, interrupted=interrupted,
        stderr_complete=reader is None or not reader.is_alive(),
        shell_boundaries=points, background_completion='NOT_INFERRED',
        host_model_ms=None, transport_ms=None)
    (root/'run.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('\nTiming directory: '+str(root), file=sys.stderr)
    return 124 if timed_out else code


if __name__ == '__main__':
    raise SystemExit(main())

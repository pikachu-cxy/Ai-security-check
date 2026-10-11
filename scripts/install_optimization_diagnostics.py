"""Isolated native launcher diagnostics, never the live user profile."""
from pathlib import Path
import json
import subprocess
from security_runtime.trial import TrialProfile, isolated_environment

root = Path('artifacts/install-optimization-diagnostic-01').absolute()
TrialProfile(root).create()
env = isolated_environment(root)
bundle = Path('dist/install-optimized-20261011/security-check').absolute()
program = root / 'program with spaces'
installed = subprocess.run([str(bundle / 'security-check.exe'), 'install', 'codex',
    '--root', str(program), '--json'], env=env, capture_output=True, timeout=150)
data = json.loads(installed.stdout)
print(json.dumps({'diagnostics': data.get('diagnostics'), 'runtime': data.get('runtime'),
    'feedback': installed.stderr.decode('utf-8', errors='replace')}, ensure_ascii=True))
launcher = Path(data['delivery']['launcher'])
for executable in (launcher, Path(data['delivery']['root']) / 'versions' / data['delivery']['active_build'] / 'bundle/security-check.exe'):
    result = subprocess.run([str(executable), 'runtime-info', '--json'], env=env,
        capture_output=True, timeout=30)
    print(json.dumps({'command_type': executable.parent.name, 'code': result.returncode,
        'stdout_bytes': len(result.stdout), 'stderr': result.stderr.decode('utf-8', errors='replace'),
        'json_valid': bool(result.stdout.startswith(b'{'))}, ensure_ascii=True))

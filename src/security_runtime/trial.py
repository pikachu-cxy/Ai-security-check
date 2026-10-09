"""Explicit, local trial profiles. No real user configuration is modified."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .hook_state import atomic_bytes, no_links

CONTRACT = 'runtime-trial-v1'
TRIAL_OPTIONS = {
    'runtime-info': {'--json'},
    'review-skill': {'--skills-dir', '--json'},
    'setup': {'--path', '--json', '--verbose', '--scope', '--dev'},
    'status': {'--path', '--json', '--dev'},
    'doctor': {'--path', '--json', '--verbose', '--global', '--project'},
    'repair': {'--path', '--json', '--dev'},
    'upgrade': {'--path', '--skills-dir', '--plan', '--output', '--approve-user-managed', '--dev', '--probe', '--json'},
    'delivery': {'--root', '--bundle', '--json'},
    'summary': {'--path', '--scan', '--details', '--json'},
}


def isolated_environment(root, inherited=None):
    root = Path(root).absolute()
    no_links(root)
    env = {k: v for k, v in (os.environ if inherited is None else inherited).items()
           if not k.upper().startswith(('SECURITY_RUNTIME_', 'SEMGREP_', 'GITLEAKS_', 'TRIVY_', 'OSV_'))
           and k.upper() not in {'CODEX_HOME', 'PYTHONPATH', 'PYTHONHOME'}}
    env.update(SECURITY_RUNTIME_STATE_DIR=str(root / 'state'), CODEX_HOME=str(root / 'codex-home'),
               SECURITY_RUNTIME_CODEX_HOME=str(root / 'codex-home'),
               SECURITY_RUNTIME_SKILLS_DIR=str(root / 'skills'),
               SECURITY_RUNTIME_TRIAL_ROOT=str(root), SECURITY_RUNTIME_TRIAL_MODE='1',
               SECURITY_RUNTIME_DATA_DIR=str(root / 'engines'), SECURITY_RUNTIME_OFFLINE='1',
               SECURITY_RUNTIME_TRIVY_CACHE_DIR=str(root / 'engines/cache/trivy'))
    return env


class TrialProfile:
    def __init__(self, root):
        raw = Path(root)
        if not raw.is_absolute() or '..' in raw.parts:
            raise ValueError('TRIAL_ABSOLUTE_ROOT_REQUIRED')
        self.root = raw.absolute()
        no_links(self.root)
        if self.root in {Path.home(), Path(self.root.anchor)}:
            raise ValueError('TRIAL_ROOT_REJECTED')

    def create(self):
        # Never reinterpret an existing unrelated folder as a trial environment.
        self.root.mkdir(parents=True, exist_ok=False)
        atomic_bytes(self.root / 'trial.json', json.dumps({'contract': CONTRACT, 'root': str(self.root)}).encode())
        for name in ('state', 'codex-home', 'skills', 'workspace'):
            (self.root / name).mkdir()
        atomic_bytes(self.root / 'workspace/pyproject.toml', b'[project]\nname="runtime-trial-fixture"\nversion="0.0.0"\n')
        atomic_bytes(self.root / 'workspace/safe.py', b'print("isolated fixture")\n')
        return self.status()

    def status(self):
        path = self.root / 'trial.json'
        no_links(path)
        if path.stat().st_size > 4096:
            raise ValueError('TRIAL_MARKER_INVALID')
        if json.loads(path.read_bytes()) != {'contract': CONTRACT, 'root': str(self.root)}:
            raise ValueError('TRIAL_MARKER_INVALID')
        return {'status': 'ISOLATED_PROFILE', 'root': str(self.root), 'environment': isolated_environment(self.root, {}),
                'workspace': str(self.root / 'workspace'), 'desktop': 'PENDING_HOST_SEPARATE_PROFILE_SUPPORT',
                'network': 'NOT_AUTHORIZED_BY_PROFILE', 'engines': 'NOT_INSTALLED_BY_PROFILE'}

    def run(self, argv, *, executable=None):
        import subprocess
        import sys
        self.status()
        if not argv or argv[0] not in TRIAL_OPTIONS:
            raise ValueError('TRIAL_ACTION_NOT_ALLOWED')
        argv = list(argv)
        # argparse accepts abbreviated long options by default. Reject them
        # before checking target flags so --skills-d/--p cannot escape the
        # profile boundary. Trial setup is deliberately Codex-only; never
        # auto-detect another editor's real user configuration.
        allowed = TRIAL_OPTIONS[argv[0]] | {'--help', '-h'}
        if any(arg.startswith('-') and arg.split('=', 1)[0] not in allowed for arg in argv[1:]):
            raise ValueError('TRIAL_ARGUMENT_INVALID')
        if argv[0] == 'setup':
            if any(arg in {'cursor', 'workbuddy'} for arg in argv[1:]):
                raise ValueError('TRIAL_INTEGRATION_NOT_ALLOWED')
            if 'codex' not in argv[1:]:
                argv.insert(1, 'codex')
        # Profile commands may only target synthetic workspace/configuration.
        for flag in ('--path', '--skills-dir', '--root', '--plan', '--output'):
            for i, arg in enumerate(argv):
                if arg == flag or arg.startswith(flag + '='):
                    if arg == flag and i + 1 >= len(argv):
                        raise ValueError('TRIAL_ARGUMENT_INVALID')
                    value = arg.split('=', 1)[1] if '=' in arg else argv[i + 1]
                    target = Path(value).absolute()
                    no_links(target)
                    if not Path(value).is_absolute() or '..' in Path(value).parts or not target.is_relative_to(self.root):
                        raise ValueError('TRIAL_TARGET_OUTSIDE_PROFILE')
                    if flag == '--plan':
                        if target.stat().st_size > 1_000_000:
                            raise ValueError('TRIAL_PLAN_INVALID')
                        plan = json.loads(target.read_bytes())
                        if not isinstance(plan, dict) or not isinstance(plan.get('steps'), list):
                            raise ValueError('TRIAL_PLAN_INVALID')
                        if not all(isinstance(step, dict) for step in plan['steps']):
                            raise ValueError('TRIAL_PLAN_INVALID')
                        for location in [plan.get('workspace'), plan.get('home'), plan.get('skill_root'),
                                         *[step.get('layer') for step in plan.get('steps', [])]]:
                            if location is not None:
                                path = Path(location)
                                no_links(path)
                                if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(self.root):
                                    raise ValueError('TRIAL_TARGET_OUTSIDE_PROFILE')
        command = ([str(executable)] if executable is not None else [sys.executable]
                   if getattr(sys, 'frozen', False) else [sys.executable, '-I', '-m', 'security_runtime.cli'])
        return subprocess.run([*command, *argv], cwd=self.root / 'workspace', env=isolated_environment(self.root),
                              stdin=subprocess.DEVNULL, timeout=120, check=False).returncode

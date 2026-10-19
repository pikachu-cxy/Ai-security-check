"""Bounded synthetic engine execution probes, never project scan evidence."""
from pathlib import Path
import json

from .diagnostics import DiagnosticError, ErrorDiagnostic, classify_network_error
from .engine_environment import engine_environment
from .processes import run_process


def probe_semgrep(executable, environment):
    """Exercise the native core before a Windows version probe is called ready."""
    with engine_environment('semgrep', environment) as child:
        directory = Path(child['TEMP'])
        (directory / 'probe.py').write_text('runtime_engine_probe()\n', encoding='utf-8')
        (directory / 'probe.yml').write_text(
            'rules:\n- id: runtime-engine-probe\n  languages: [python]\n'
            '  severity: INFO\n  message: Engine execution probe.\n'
            '  pattern: runtime_engine_probe()\n', encoding='utf-8')
        args = [str(executable), 'scan', '--config', 'probe.yml', '--json',
            '--metrics', 'off', '--disable-version-check', '--no-git-ignore',
            '--no-rewrite-rule-ids', 'probe.py']
        result = run_process(args, cwd=str(directory), env=child, timeout=8,
            max_output=64_000, capture_start_failure=True)
        if result.return_code != 0:
            raise DiagnosticError(classify_network_error(stderr=result.stderr,
                return_code=result.return_code, fallback='ENGINE_EXECUTION_PROBE_FAILED'))
        try:
            data = json.loads(result.stdout)
            matches = data['results']
            valid = (not data.get('errors') and isinstance(matches, list)
                and len(matches) == 1 and matches[0]['check_id'] == 'runtime-engine-probe'
                and matches[0]['path'] == 'probe.py' and matches[0]['start']['line'] == 1)
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise DiagnosticError(ErrorDiagnostic('ENGINE_EXECUTION_PROBE_FAILED',
                'The engine version is available, but its synthetic scan did not verify execution.',
                'Inspect the local engine environment; retain the installed component.'))

"""Real offline scanners on disposable Python text; never import the target."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
from security_runtime.toolchain import ToolManager
from security_runtime.remediation import RemediationService
from security_runtime.remediation_policy import RemediationConfig
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.task_fix import TaskFixService


def run():
    os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    fixtures = Path(__file__).resolve().parents[1]/'tests/rule_program'
    risk = (fixtures/'python-sql-injection-risk.py').read_text(encoding='utf-8')
    safe = (fixtures/'python-sql-injection-safe.py').read_text(encoding='utf-8').replace('def safe(', 'def vulnerable(')
    with tempfile.TemporaryDirectory(prefix='python-consent-audit-') as temporary:
        folder = Path(temporary); root = folder/'project'; root.mkdir()
        target = root/'app.py'; target.write_text(safe, encoding='utf-8')
        for args in (['init'], ['config','user.name','Fixture'], ['config','user.email','fixture@example.invalid'],
                     ['add','.'], ['commit','-m','safe fixture']):
            subprocess.run(['git','-C',str(root),*args], check=True, capture_output=True)
        state = folder/'state'; store = SQLiteStore(state/'scans.db')
        hooks = HookStateStore(state/'hooks'); manager = ToolManager()
        registry = ScannerRegistry([SemgrepAdapter(manager), GitleaksAdapter(manager)],
                                   tool_manager=manager, fallback_adapters=[])
        coordinator = HookCoordinator(SecurityRuntime(registry, store), hooks, cooldown_ms=0)
        remediation = RemediationService(store, registry=registry, hooks=hooks,
            directory=state/'remediation', config=RemediationConfig(state/'policy.json'))
        baseline = coordinator.handle('SESSION_START', root, 'codex', 'fixture')
        assert baseline['status'] == 'BASELINE_ESTABLISHED', baseline['status']
        target.write_text(risk, encoding='utf-8'); before = target.read_bytes()
        detected = coordinator.handle('FILE_CHANGED', root, 'codex', 'fixture')
        offer = remediation.on_hook(detected, root, 'fixture', host='codex')
        assert detected['delta']['new'] == 1, detected['delta']
        assert offer['action'] != 'AUTO_FIX' and not remediation.authorized
        assert target.read_bytes() == before
        summary = SecuritySummaryService(store).get(root, details=True)
        task = next(t for t in summary['tasks'] if t['topic'] == 'code')
        fix = TaskFixService(store, registry)
        packet = fix.prepare(task['task_ref'], root, bound_workspace=root)
        assert packet['status'] == 'READY_FOR_HOST_FIX' and not any(packet['execution'].values())
        assert packet['authorization_requirements']['user_consent_required'] is True
        assert packet['authorization_requirements']['preparation_is_not_user_consent'] is True
        assert packet['authorization_requirements']['explicit_selected_task_fix_intent_required'] is True
        assert target.read_bytes() == before
        still = fix.verify(task['task_ref'], root, bound_workspace=root)
        assert still['status'] == 'STILL_PRESENT', still['status']
        target.write_text('\n'*10+risk, encoding='utf-8')
        moved = fix.verify(task['task_ref'], root, bound_workspace=root)
        assert moved['status'] == 'STILL_PRESENT', moved['status']
        # This is a trusted fixture-driver choice, NOT inferred production consent.
        explicit_selected_task_fix_intent = True
        assert explicit_selected_task_fix_intent
        target.write_text('\n'*10+safe, encoding='utf-8')  # simulated approved Host edit
        checked = fix.verify(task['task_ref'], root, bound_workspace=root)
        assert checked['status'] == 'SCANNER_VERIFIED_RESOLVED', checked['status']
        assert checked['runtime_observed_execution']['scanner_recheck']
        assert not checked['runtime_observed_execution']['patch_applied']
        hook = coordinator.handle('FILE_CHANGED', root, 'codex', 'fixture')
        assert hook['delta']['resolved'] == 1, hook['delta']
        return {'fixture':'DISPOSABLE_PYTHON_SQL_TEXT', 'rule_pack_version':'1.3.0',
            'origin_scanners':[{r['scanner']:r['version']} for r in detected['scanner_runs']],
            'detection':'PASS', 'no_unconfirmed_runtime_edit':'PASS',
            'consent_boundary':'HOST_EXPLICIT_SELECTED_TASK_INTENT; NOT_CRYPTOGRAPHIC_USER_ATTESTATION',
            'before_fix':still['status'], 'line_moved':moved['status'],
            'origin_scanner_retest':checked['status'], 'hook_resolved_families':hook['delta']['resolved'],
            'executed_target_code':False, 'target_build':False, 'network_query':False,
            'desktop_natural_language_trial':'PENDING', 'production_exploitability':'NOT_ESTABLISHED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))

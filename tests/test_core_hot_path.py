"""Core stops at security proof; timing observes, never authorizes."""
import json
import time
import pytest
from test_hook_runtime import repo, FakeRuntime
from test_remediation import setup, prepare, args, FIXED
from test_remediation_episodes import resolve, recur, record
from test_codex_mcp_hook import binding
from security_runtime.codex_mcp_hook import handle_codex_hook
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.hook_timing import ExecutionTrigger, PHASES
from security_runtime.host_guidance import HOST_INSTRUCTIONS, runtime_info
from security_runtime.functional_verification import FunctionalVerificationService
from security_runtime.functional_verifiers import FunctionalVerifierRegistry
from security_runtime.codex_integration import check_capabilities, REQUIRED_TOOLS


def forbid_deep(monkeypatch):
    def forbidden(*a, **kw): pytest.fail('Core entered optional Deep Verification')
    for name in ('prepare', 'run', 'finalize'):
        monkeypatch.setattr(FunctionalVerificationService, name, forbidden)
    monkeypatch.setattr(FunctionalVerifierRegistry, 'detect', forbidden)
    from security_runtime.functional_execution import LocalSandbox
    monkeypatch.setattr(LocalSandbox, 'run', forbidden)


def test_safe_edit_has_observed_timing_no_deep(repo, tmp_path, monkeypatch):
    forbid_deep(monkeypatch)
    runtime = FakeRuntime()
    repo.joinpath('Safe.java').write_text('class Safe {}')
    core = HookCoordinator(runtime, HookStateStore(tmp_path/'hooks'), cooldown_ms=0)
    out = handle_codex_hook('PostToolUse', str(repo), 's', 'Write', binding=binding(repo), coordinator=core)
    assert out['new_families'] == 0
    assert set(out['timing_ms']) == set(PHASES)
    assert out['timing_ms']['hook_total'] >= out['timing_ms']['scanner'] >= 0
    assert out['timing_ms']['auto_remediation'] is None
    assert out['execution_context']['trigger'] == 'HOOK'
    assert not out['execution']['target_build'] and not out['execution']['ai_called']


def test_new_auto_fix_rescan_recurrence_never_enters_deep(setup, monkeypatch):
    forbid_deep(monkeypatch)
    assert setup[-1]['remediation']['action'] == 'AUTO_FIX'
    packet = prepare(setup)
    assert packet['timing_ms']['remediation_preparation'] >= 0
    assert 'prepare_functional_verification' not in packet['host_protocol']['instructions']
    assert 'END the Core remediation' in packet['host_protocol']['instructions']
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    start = time.perf_counter()
    out = setup[4]()
    duration = (time.perf_counter()-start)*1000
    assert out['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert out['remediation']['next_action'] == 'RETURN_TO_HOST'
    assert record(setup)['phase'] == 'CLOSED'
    measured = out['timing_ms']
    assert 0 <= measured['hook_total'] <= duration+5
    for phase in PHASES:
        assert measured[phase] is not None and measured[phase] >= 0
    assert measured['remediation_preparation'] == packet['timing_ms']['remediation_preparation']
    assert 'functional' not in out['remediation'].get('next_action', '').lower()
    fresh = recur(setup)
    assert fresh['remediation']['action'] == 'AUTO_FIX'
    assert fresh['remediation']['episode_number'] == 2
    assert fresh['remediation']['attempt_count'] == 1
    assert fresh['timing_ms']['auto_remediation'] is None
    assert fresh['timing_ms']['remediation_preparation'] is None


def test_security_failure_cannot_claim_resolved(setup, monkeypatch):
    forbid_deep(monkeypatch)
    prepare(setup)
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = []
    def failed(*a, **kw): raise OSError('private source secret')
    setup[2].scan = failed
    out = setup[4]()
    assert out['remediation']['action'] == 'ESCALATE'
    assert out['remediation']['reason_code'] == 'VERIFICATION_INCONCLUSIVE'
    assert record(setup)['phase'] != 'CLOSED'
    assert 'private source secret' not in json.dumps(out)


def test_no_change_does_not_reuse_old_measured_scan_time(setup):
    out = setup[4]()
    assert out['status'] == 'NO_CHANGE'
    assert out['timing_ms']['scanner'] is None
    assert out['timing_ms']['security_rescan'] is None


def test_timing_persistence_contains_no_source_or_new_authority(setup):
    resolve(setup)
    data = setup[3].state.path(setup[0], 'codex', 'session').read_text()
    assert 'timing_ms' not in data and 'ready_at' not in data
    assert 'setHostnameVerifier' not in data
    assert set(t.value for t in ExecutionTrigger) == {'HOOK','MANUAL','STOP','PR','CI','SCHEDULED'}


def test_missing_deep_capability_is_not_a_core_readiness_failure():
    info = runtime_info()
    info['features'].pop('functional_verification')
    info['features'].pop('functional_host_execution')
    assert check_capabilities(info, REQUIRED_TOOLS)['status'] == 'OK'
    assert 'Only a separate explicit Deep Verification request' in HOST_INSTRUCTIONS


def test_core_mcp_verify_does_not_finalize_optional_deep(setup, monkeypatch):
    root, runtime, _, service, _, _ = setup
    resolve(setup)
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(root))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(service.store.path.parent))
    import security_runtime.remediation as module
    monkeypatch.setattr(module, 'RemediationService', lambda *a, **kw: service)
    forbid_deep(monkeypatch)
    from security_runtime.mcp_server import create_server
    server = create_server(runtime)
    values = args(setup)
    checked = server._tool_manager.get_tool('verify_task_fix').fn(**values, workspace_path=str(root))
    assert checked['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert checked['next_action'] == 'RETURN_TO_HOST'
    assert 'functional_status' not in checked
    # An explicit manual Deep request keeps the existing API finalization path.
    monkeypatch.setattr(FunctionalVerificationService, 'prepare', lambda *a, **kw:
                        {'security_verification': {'status': 'SCANNER_VERIFIED_RESOLVED'}})
    monkeypatch.setattr(FunctionalVerificationService, 'finalize', lambda self, r, t, p, checked:
                        dict(checked, explicitly_requested_deep=True))
    server._tool_manager.get_tool('prepare_functional_verification').fn(**values, workspace_path=str(root))
    assert server._tool_manager.get_tool('verify_task_fix').fn(**values, workspace_path=str(root))['explicitly_requested_deep']

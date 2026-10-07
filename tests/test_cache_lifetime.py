"""Preparation lifetime, batched Secret coverage and monotonic cycle contracts."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_hook_runtime import repo
from test_remediation import setup, prepare, args, FIXED
from test_remediation_episodes import resolve, recur
from test_scanner_hot_path import engine, probe, context
from security_runtime.scanner_cache import lifetime
from security_runtime.scanner_observation import observation
from security_runtime.scanners import SemgrepAdapter, GitleaksAdapter
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus
from security_runtime.processes import ProcessResult
from security_runtime.models import ScanContext, ScanMode, RunStatus
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_timing import RemediationCycles


def test_three_requests_then_manager_recreation_keeps_process_cache(probe):
    manager, path, calls, _ = probe
    first = lifetime()
    flags = []
    for _ in range(3):
        with observation('same-workspace') as observed:
            manager._version('gitleaks', path)
        flags.append(observed['cache']['version_probe'])
    rebuilt = ToolManager(manager.root)
    with observation('same-workspace') as observed:
        rebuilt._version('gitleaks', path)
    assert flags == ['MISS', 'HIT', 'HIT']
    assert observed['cache']['version_probe'] == 'HIT' and len(calls) == 1
    assert lifetime() == first


def test_rebuilt_registry_plan_is_fresh_without_losing_static_config(engine):
    root, _, _, adapter, _, _ = engine
    plan = adapter.plan_rules(None, context(root))
    plan.confirmed_rules.add('old-proof')
    rebuilt = SemgrepAdapter(adapter.tool_manager, rule_packs=adapter.rule_packs)
    current = rebuilt.plan_rules(None, context(root))
    assert current.planning_diagnostics['rule_pack_cache'] == 'HIT'
    assert current.planning_diagnostics['rule_plan_cache'] == 'HIT'
    assert not current.confirmed_rules and not current.scanned_files


def test_registry_rebuild_different_workspace_cannot_use_previous_proof(engine, tmp_path):
    root, _, _, adapter, _, _ = engine
    adapter.plan_rules(None, context(root))
    other = tmp_path/'other'; other.mkdir(); (other/'A.java').write_text('class A {}')
    rebuilt = SemgrepAdapter(adapter.tool_manager, rule_packs=adapter.rule_packs)
    plan = rebuilt.plan_rules(None, context(other))
    assert plan.planning_diagnostics['rule_pack_cache'] == 'MISS'
    assert plan.planning_diagnostics['rule_plan_cache'] == 'MISS'
    assert not plan.confirmed_rules


def test_parallel_engine_probes_and_later_single_engine_recheck_keep_own_bucket(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    manager = ToolManager(tmp_path/'tools')
    barrier = threading.Barrier(2); seen = {}; probes = []
    def key(tool, path):
        seen[tool] = seen.get(tool, 0)+1
        if seen[tool] == 1: barrier.wait(timeout=5)
        return tool, 'stable-contract-identity'
    monkeypatch.setattr(manager, '_probe_identity', key)
    def version(tool, path):
        probes.append(tool)
        return manager.versions[tool]
    monkeypatch.setattr(manager, '_probe_version', version)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(manager._version, tool, tmp_path/tool) for tool in ('gitleaks','trivy')]
        assert [job.result() for job in jobs] == [manager.versions[tool] for tool in ('gitleaks','trivy')]
    for tool in ('gitleaks','trivy'):
        with observation('scope') as data: manager._version(tool, tmp_path/tool)
        assert data['cache']['version_probe'] == 'HIT'
    assert sorted(probes) == ['gitleaks','trivy']


def test_real_python_process_restart_changes_identity_and_starts_cold(tmp_path):
    engine = tmp_path/'gitleaks'; engine.write_bytes(b'contract-only-version-fixture')
    script = tmp_path/'probe.py'
    script.write_text('''import json, sys
from pathlib import Path
from security_runtime.toolchain import ToolManager
from security_runtime.scanner_cache import lifetime
from security_runtime.scanner_observation import observation
manager=ToolManager(Path(sys.argv[1]).parent/'tools')
manager._probe_version=lambda *args: '8.30.0'
flags=[]
for _ in range(2):
 with observation('restart-fixture') as data:
  manager._version('gitleaks',Path(sys.argv[1]))
 flags.append(data['cache']['version_probe'])
print(json.dumps(dict(lifetime=lifetime(),flags=flags)))
''', encoding='utf-8')
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src'), PYTHONUTF8='1')
    results = [json.loads(subprocess.check_output([sys.executable, str(script), str(engine)], env=env)) for _ in range(2)]
    assert all(data['flags'] == ['MISS', 'HIT'] for data in results)
    assert results[0]['lifetime']['runtime_instance_id'] != results[1]['lifetime']['runtime_instance_id']


def test_hook_factory_recreation_retains_process_diagnostic(monkeypatch):
    from security_runtime.mcp_server import create_server
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    ids = []
    for _ in range(2):
        server = create_server()
        response = server._tool_manager.get_tool('handle_hook_event').fn(
            event='PostToolUse', workspace_path='unbound', session_id='unit', tool_name='Write',
            turn_id='fixture-turn', tool_use_id='fixture-call')
        assert response.structuredContent['status'] == 'INCONCLUSIVE'
        ids.append(response.structuredContent['runtime_instance_id'])
    assert ids[0] == ids[1] == lifetime()['runtime_instance_id']


@pytest.fixture
def secret_engine(tmp_path, monkeypatch):
    root = tmp_path/'project'; root.mkdir()
    files = ('src/A.java', 'notes/one.txt', 'README.md')
    for name in files:
        file = root/name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text('private synthetic fixture\n')
    (root/'unrelated.txt').write_text('must never enter scoped mirror')
    adapter = GitleaksAdapter()
    monkeypatch.setattr(adapter.tool_manager, 'ensure', lambda *a, **kw:
                        ResolvedTool('gitleaks', '8.30.0', 'gitleaks', None, ToolStatus.READY))
    calls = []; mode = {'value': 'success'}
    def execute(argv, cwd, timeout):
        target = Path(argv[2]); calls.append((target, tuple(sorted(
            p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file())) if target.is_dir() else (target.name,)))
        report = Path(argv[argv.index('--report-path')+1])
        if mode['value'] == 'failure':
            return ProcessResult(2, '', '', 1)
        if mode['value'] == 'missing':
            return ProcessResult(0, '', '', 1)
        report.write_text(json.dumps([{'File': str(target/'src/A.java') if target.is_dir() else str(target),
                                      'RuleID': 'synthetic-secret', 'StartLine': 1, 'Secret': 'private-raw-canary'}]))
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    return root, files, adapter, calls, mode


def test_single_file_duplicates_are_scanned_once(secret_engine):
    root, files, adapter, calls, _ = secret_engine
    found, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, (files[0], files[0])), FindingNormalizer(root))
    assert run.status == RunStatus.SUCCESS and len(calls) == 1
    assert run.scanner_diagnostics['invocations'] == [{'type': 'SECRET_SCAN', 'target_count': 1}]
    assert found[0].file_path == files[0]


def test_batch_has_exact_complete_scope_relative_paths_redaction_and_cleanup(secret_engine):
    root, files, adapter, calls, _ = secret_engine
    original = {name: (root/name).read_bytes() for name in files}
    found, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, files), FindingNormalizer(root))
    assert run.status == RunStatus.SUCCESS and len(calls) == 1
    assert calls[0][1] == tuple(sorted(files))
    assert not calls[0][0].exists()
    assert run.scanner_diagnostics['invocation_count'] == 1
    assert run.scanner_diagnostics['scope']['target_files'] == len(files)
    assert run.scanner_diagnostics['invocations'] == [{'type': 'SECRET_SCAN', 'target_count': 3}]
    assert found[0].file_path == 'src/A.java' and found[0].evidence == '[REDACTED_SECRET]'
    assert 'private-raw-canary' not in json.dumps(run.scanner_diagnostics)
    assert all((root/name).read_bytes() == value for name, value in original.items())


@pytest.mark.parametrize('mode', ['failure', 'missing'])
def test_failed_batch_is_not_a_success_and_next_scan_is_fresh(secret_engine, mode):
    root, files, adapter, calls, state = secret_engine
    state['value'] = mode
    _, failed = adapter.scan(ScanContext(str(root), ScanMode.QUICK, files), FindingNormalizer(root))
    assert failed.status == RunStatus.FAILED and not calls[-1][0].exists()
    state['value'] = 'success'
    _, fresh = adapter.scan(ScanContext(str(root), ScanMode.QUICK, files), FindingNormalizer(root))
    assert fresh.status == RunStatus.SUCCESS and len(calls) == 2


def test_batch_rejects_workspace_escape(secret_engine):
    root, _, adapter, calls, _ = secret_engine
    _, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, ('../outside.txt',)), FindingNormalizer(root))
    assert run.status == RunStatus.FAILED and calls == []


def test_cycle_endpoints_do_not_add_phases_and_freeze_on_first_resolution(tmp_path):
    now = [100.0]; cycles = RemediationCycles(clock=lambda: now[0])
    cycles.start(tmp_path, 'episode-1', 95.0)
    assert cycles.result(tmp_path, 'episode-1')['remediation_cycle_measurement']['status'] == 'IN_PROGRESS'
    now[0] = 110.0
    first = cycles.result(tmp_path, 'episode-1', complete=True)
    assert first['remediation_cycle_wall_ms'] == 15000
    now[0] = 200.0
    assert cycles.result(tmp_path, 'episode-1', complete=True) == first
    cycles.start(tmp_path, 'episode-2', 199.0); now[0] = 205.0
    assert cycles.result(tmp_path, 'episode-2', complete=True)['remediation_cycle_wall_ms'] == 6000
    assert cycles.result(tmp_path/'foreign', 'episode-1', complete=True)['remediation_cycle_wall_ms'] is None


def test_cycle_invalid_start_reconnect_or_process_identity_is_unknown(tmp_path, monkeypatch):
    cycles = RemediationCycles(clock=lambda: 100.0)
    for started in (None, float('nan'), 101.0):
        cycles.start(tmp_path, 'unknown', started)
    assert cycles.result(tmp_path, 'unknown', complete=True)['remediation_cycle_measurement']['status'] == 'UNKNOWN'
    cycles.start(tmp_path, 'observed', 99.0)
    monkeypatch.setattr('security_runtime.scanner_cache._process', __import__(
        'security_runtime.scanner_cache', fromlist=['ProcessPreparations']).ProcessPreparations(2))
    assert cycles.result(tmp_path, 'observed', complete=True)['remediation_cycle_measurement']['status'] == 'UNKNOWN'
    assert RemediationCycles().result(tmp_path, 'observed', complete=True)['remediation_cycle_wall_ms'] is None


def test_cycle_budget_evicts_observation_without_inventing_success(tmp_path):
    cycles = RemediationCycles(clock=lambda: 100.0)
    for i in range(40): cycles.start(tmp_path, str(i), 99.0)
    assert len(cycles.entries) == 32
    assert cycles.result(tmp_path, '0', complete=True)['remediation_cycle_measurement']['status'] == 'UNKNOWN'


def test_invocation_metadata_bounded_without_losing_total_count():
    from security_runtime.scanner_observation import invocation, metadata
    with observation('scope') as data:
        invocation('VERSION_PROBE', 0)
        for _ in range(70): invocation('SAST_SCAN', 1)
    result = metadata(data)
    assert result['invocation_count'] == 70 and len(result['invocations']) == 64
    assert result['invocations_truncated']


def test_auto_fix_cycle_is_episode_bound_frozen_and_not_persisted(setup):
    root, runtime, provider, service, hook, grant = setup
    assert grant['remediation_cycle_measurement']['status'] == 'IN_PROGRESS'
    prepare(setup); root.joinpath('A.java').write_text(FIXED); runtime.findings = provider.findings = []
    closed = hook()
    assert closed['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert closed['remediation_cycle_measurement']['status'] == 'OBSERVED'
    assert closed['remediation_cycle_wall_ms'] >= closed['timing_ms']['hook_total']
    values = args(setup)
    verified = service.verify(values['remediation_ref'], values['task_ref'], root)
    assert verified['remediation_cycle_wall_ms'] == closed['remediation_cycle_wall_ms']
    fresh = recur(setup)
    assert fresh['remediation']['episode_id'] != grant['remediation']['episode_id']
    assert fresh['remediation_cycle_measurement']['status'] == 'IN_PROGRESS'
    assert fresh['remediation_cycle_wall_ms'] is None
    persisted = service.state.path(root, 'codex', 'session').read_text()
    assert 'remediation_cycle' not in persisted and 'runtime_instance_id' not in persisted


def test_reconnected_closed_remediation_preserves_security_but_cycle_unknown(setup):
    resolve(setup)
    from security_runtime.remediation import RemediationService
    service = setup[3]
    reconnected = RemediationService(service.store, registry=service.registry, hooks=service.hooks)
    values = args(setup)
    output = reconnected.verify(values['remediation_ref'], values['task_ref'], setup[0])
    assert output['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert output['remediation_cycle_measurement']['status'] == 'UNKNOWN'
    assert output['remediation_cycle_wall_ms'] is None

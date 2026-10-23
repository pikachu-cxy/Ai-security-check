"""Real private snapshots, native detector, cache, and evidence-bound attribution."""
import copy
import subprocess
from dataclasses import asdict

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.baseline_inputs import BaselineInputs
from security_runtime.tasks.risk_attribution import apply_assessments, unknown
from security_runtime.tasks.risk_reporting import ReportNotifications, describe, grouped_rows, report_ref

SAFE = 'export function calculate(expression) {\n  return parseArithmetic(expression);\n}\n'
RISK = 'export function calculate(expression) {\n  return new Function(`return (${expression});`)();\n}\n'


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    root = tmp_path/'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root/'app.js').write_text(RISK)
    engine = SecurityRuntime(ScannerRegistry([NativeFunctionScanner()], fallback_adapters=[]),
                             SQLiteStore(tmp_path/'scan.db'))
    service = TaskSecurityService(engine, HookStateStore(tmp_path/'hooks'), owner=session_owner('codex', 'a'))
    # Source-tree tests run while development continues; freeze only that build
    # identity. Actual source, native rules, signed stores and engines are real.
    from security_runtime.build_identity import build_identity
    build = build_identity()
    monkeypatch.setattr('security_runtime.scan_reuse.build_identity', lambda:build)
    monkeypatch.setattr('security_runtime.scan_freshness.build_identity', lambda:build)
    return service, root, engine


def begin(setup, name='task'):
    service, root, _ = setup
    return service.begin(root, name, check_policy=POLICY)['task_ref']


def finish(setup, ref):
    service, root, _ = setup
    response = service.finish(root, ref)
    assert response['status'] == 'READY'
    record = service.load(root, ref)
    assert record['static']['findings'], record['static']
    return record


def test_raw_original_is_private_and_survives_reconnect(setup):
    service, root, engine = setup
    ref = begin(setup)
    original = copy.deepcopy(service.load(root, ref))
    saved = original['before_scan_inputs']
    assert saved['status'] == 'AVAILABLE'
    inputs = BaselineInputs(service.hooks, root)
    private = inputs.open(saved['ref'])
    assert not private.is_relative_to(root)
    assert (private/'app.js').read_text() == RISK
    (root/'app.js').write_text(SAFE)
    restarted = TaskSecurityService(engine, service.hooks, owner=service._owner())
    assert restarted.begin(root, 'task', check_policy=POLICY)['task_ref'] == ref
    assert restarted.load(root, ref)['baseline'] == original['baseline']
    assert restarted.load(root, ref)['before_scan_inputs'] == saved
    assert (private/'app.js').read_text() == RISK


def test_existing_risk_moves_lines_without_becoming_new(setup):
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text('// unrelated comment\n'+RISK)
    record = finish(setup, ref)
    comparison = record['static']['risk_comparison']
    assert comparison['status'] == 'COMPARED', comparison
    attribution = record['static']['findings'][0]['risk_attribution']
    assert attribution['origin'] == 'EXISTING', attribution
    assert attribution['impact'] == 'REQUIRES_REVIEW'
    assert attribution['local_semantics_unchanged'] is True


def test_new_risk_requires_host_causal_review(setup):
    service, root, _ = setup
    (root/'app.js').write_text(SAFE)
    ref = begin(setup)
    (root/'app.js').write_text(RISK)
    record = finish(setup, ref)
    attribution = record['static']['findings'][0]['risk_attribution']
    assert attribution['presence'] == 'ABSENT_BEFORE', record['static']['risk_comparison']
    assert attribution['origin'] == 'UNKNOWN'
    assert attribution['candidate_origin'] == 'INTRODUCED'


def test_missing_before_input_never_recaptures(setup, monkeypatch):
    service, root, _ = setup
    ref = begin(setup)
    saved = service.load(root, ref)
    BaselineInputs(service.hooks, root).discard(saved['before_scan_inputs']['ref'])
    (root/'app.js').write_text('// later\n'+RISK)
    monkeypatch.setattr(BaselineInputs, 'writer', lambda *a:pytest.fail('must not rebuild baseline'))
    record = finish(setup, ref)
    assert record['static']['risk_comparison']['status'] == 'COMPARISON_UNAVAILABLE'
    assert record['static']['findings'][0]['risk_attribution']['origin'] == 'UNKNOWN'
    assert record['baseline'] == saved['baseline']


def test_exact_tasks_share_static_facts_but_not_baselines_or_ownership(setup):
    a, root, engine = setup
    b = TaskSecurityService(engine, a.hooks, owner=session_owner('cursor', 'b'))
    ar = begin(setup)
    br = b.begin(root, 'b', check_policy=POLICY)['task_ref']
    (root/'app.js').write_text('// both see this end version\n'+RISK)
    ra = finish(setup, ar)
    rb = finish((b, root, engine), br)
    assert rb['static']['reuse'].get('reused') is True, rb['static']
    assert rb['static']['risk_comparison']['before_cache_reused'] is True
    assert ra['task_ref'] != rb['task_ref']
    assert ra['task_owner'] != rb['task_owner']
    assert ra['before_scan_inputs']['ref'] != rb['before_scan_inputs']['ref']
    assert rb['static']['findings'][0]['risk_attribution']['authorship'] == 'UNPROVEN_SHARED_WORKSPACE'
    with pytest.raises(ValueError):
        b.finish(root, ar)


def test_old_masked_artifact_is_not_reused_as_original_evidence(setup):
    from security_runtime.scan_artifacts import ScanArtifacts
    service, root, engine = setup
    ref = begin(setup)
    (root/'app.js').write_text('// first end\n'+RISK)
    finish(setup, ref)
    artifacts = ScanArtifacts(service.hooks, root)
    rows = artifacts.rows()
    assert rows
    with artifacts.transaction() as db:
        for row in rows:
            row.pop('source_presentation')
            for finding in row['result']['findings']:
                finding['evidence'] = '[REDACTED_SECRET]'
            artifacts._put(db, row['key'], row)
    assert all(artifacts.lookup(row['key']) is None for row in rows)
    other = TaskSecurityService(engine, service.hooks, owner=session_owner('cursor', 'raw-next'))
    next_ref = other.begin(root, 'raw-next', check_policy=POLICY)['task_ref']
    (root/'app.js').write_text('// next end\n'+RISK)
    result = finish((other, root, engine), next_ref)
    assert result['static']['risk_comparison']['before_cache_reused'] is False
    assert result['static']['findings'][0]['risk_attribution']['origin'] == 'EXISTING'


def test_zero_current_findings_needs_no_before_scan(setup, monkeypatch):
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text(SAFE)
    monkeypatch.setattr(BaselineInputs, 'open', lambda *a:pytest.fail('zero findings need no before scan'))
    service.finish(root, ref)
    value = service.load(root, ref)['static']['risk_comparison']
    assert value['status'] == 'NO_CURRENT_FINDINGS'
    assert value['before_scan_run'] is False


def test_tampered_before_bytes_fail_closed(setup):
    service, root, _ = setup
    ref = begin(setup)
    saved = service.load(root, ref)
    inputs = BaselineInputs(service.hooks, root)
    path = inputs.open(saved['before_scan_inputs']['ref'])/'app.js'
    import os, stat
    os.chmod(path, stat.S_IWRITE|stat.S_IREAD)
    path.write_text(SAFE)
    (root/'app.js').write_text('// changed\n'+RISK)
    record = finish(setup, ref)
    assert record['static']['risk_comparison']['status'] == 'COMPARISON_UNAVAILABLE'


def test_changed_config_does_not_prove_introduction(setup):
    service, root, _ = setup
    ref = begin(setup)
    (root/'.semgrepignore').write_text('ignored.js\n')
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    assert record['static']['findings'][0]['risk_attribution']['origin'] == 'UNKNOWN'


def test_host_expansion_needs_before_and_changed_evidence(setup):
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    finding = record['static']['findings'][0]
    record['evidence'] = {'after':dict(path='app.js', location_version='CURRENT_TASK_END', start_line=1, end_line=4),
                          'before':dict(path='app.js', location_version='BEFORE_TASK', start_line=1, end_line=3)}
    assessment = dict(finding_id=finding['id'], origin='EXPANDED', impact='EXPANDED',
                      rationale='Fixture host claim of a new reachable caller; not a scanner proof.',
                      evidence_refs=['after'])
    with pytest.raises(ValueError, match='before evidence'):
        apply_assessments(record, [], [assessment])
    assessment['evidence_refs'].append('before')
    apply_assessments(record, [], [assessment])
    assert finding['risk_attribution']['origin'] == 'EXPANDED'
    assert finding['risk_attribution']['assessment'] == 'HOST_REASONING_NOT_SCANNER_PROOF'


def test_report_preparation_is_not_delivery_and_changed_risk_reopens(setup):
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    record['phase'] = 'COMPLETE'
    finding = record['static']['findings'][0]
    finding['risk_attribution']['impact'] = 'UNCHANGED'
    reports = ReportNotifications(service.hooks, root)
    assert report_ref(record) == describe(record)['report_ref']
    assert reports.prior(finding) is None
    with pytest.raises(ValueError):
        reports.acknowledge(record, session_owner('cursor', 'other'), [finding['id']], final_report_submitted=True)
    reports.acknowledge(record, service._owner(), [finding['id']], final_report_submitted=True)
    assert reports.prior(finding)['report_ref'] == report_ref(record)
    finding['risk_attribution']['origin'] = 'EXPANDED'
    assert reports.prior(finding) is None
    finding['risk_attribution']['origin'] = 'UNKNOWN'
    assert reports.prior(finding) is None


def test_host_static_same_issue_keeps_both_provenances(setup):
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    static = record['static']['findings'][0]
    record['review'] = dict(findings=[dict(id='host', same_issue_as=static['id'], title='host reasoning')])
    rows = grouped_rows(record)
    assert len(rows) == 1
    assert rows[0][1]['related_observations'][0]['id'] == 'host'
    assert describe(record)['raw_observation_count'] == 2
    assert describe(record)['distinct_issue_count'] == 1


def test_explicit_project_scan_reused_for_original_task_comparison(setup):
    service, root, engine = setup
    from security_runtime.scan_attempt import ScanAttemptExecution, ScanAttemptStore, source_binding
    service.hooks.key(root)
    attempts = ScanAttemptStore(service.hooks, root)
    with service.hooks.lock(root):
        lease = attempts.claim('MANUAL', 'project-check', source_binding({'test':'project'}))
    execution = ScanAttemptExecution(attempts, lease)
    project = engine.scan(root, mode='release', execution=execution)
    with service.hooks.lock(root):
        attempts.finish(lease, input_id=execution.input_id, scan_id=project.scan_id, outcome='COMPLETED')
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    comparison = record['static']['risk_comparison']
    assert comparison['before_cache_reused']
    assert comparison['original_project_artifact']
    assert record['static']['findings'][0]['risk_attribution']['origin'] == 'EXISTING'


def test_forced_project_scan_bypasses_artifact_and_ack_requires_submission(setup):
    service, root, engine = setup
    from security_runtime.explicit_scan import run_explicit_scan
    def scan(force=False):
        return run_explicit_scan(engine, root, mode='release', hooks=service.hooks, force_rescan=force)
    first = scan()
    reused = scan()
    assert reused.scanner_diagnostics['result_reuse']['reused'] is True
    forced = scan(True)
    assert not forced.scanner_diagnostics.get('result_reuse', {}).get('reused')
    reports = ReportNotifications(service.hooks, root)
    with pytest.raises(ValueError):
        reports.acknowledge_project(first, service._owner(), [first.findings[0].id], final_report_submitted=False)
    reports.acknowledge_project(first, service._owner(), [first.findings[0].id], final_report_submitted=True)
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    finding = record['static']['findings'][0]
    assert reports.prior(finding) is None  # Existence alone does not establish unchanged impact.
    finding['risk_attribution']['impact'] = 'UNCHANGED'
    assert reports.prior(finding)['scan_id'] == first.scan_id


def test_project_cache_does_not_bypass_changed_configuration(setup):
    service, root, engine = setup
    from security_runtime.explicit_scan import run_explicit_scan
    run_explicit_scan(engine, root, mode='release', hooks=service.hooks)
    ref = begin(setup)
    (root/'.semgrepignore').write_text('other.js\n')
    (root/'app.js').write_text('// comment\n'+RISK)
    record = finish(setup, ref)
    assert record['static']['risk_comparison']['status'] == 'COMPARISON_UNAVAILABLE'
    assert record['static']['findings'][0]['risk_attribution']['origin'] == 'UNKNOWN'


def test_attribution_submission_uses_real_current_review_evidence(setup):
    from task_review_helpers import review_all, evidence_id
    service, root, _ = setup
    (root/'app.js').write_text(SAFE)
    ref = begin(setup)
    (root/'app.js').write_text(RISK)
    record = finish(setup, ref)
    packet = service.prepare(root, ref)
    review_all(service, root, ref, packet)
    session = packet['review_session']
    current = evidence_id(service.read(root, ref, session, 'app.js', 1, 3))
    before = evidence_id(service.read(root, ref, session, 'app.js', 1, 3, source_version='BEFORE_TASK'))
    attribution = dict(finding_id=record['static']['findings'][0]['id'], origin='INTRODUCED',
        impact='UNKNOWN', rationale='The task replaces the parser with dynamic code execution.',
        evidence_refs=[current, 'te-forged'])
    with pytest.raises(ValueError, match='issued current review evidence'):
        service.submit(root, ref, session, [], 'REVIEWED', [], risk_attributions=[attribution])
    assert service.load(root, ref)['phase'] == 'REVIEWING'
    attribution['evidence_refs'] = [current, before]
    service.submit(root, ref, session, [], 'REVIEWED', [], risk_attributions=[attribution])
    saved = service.load(root, ref)['static']['findings'][0]['risk_attribution']
    assert saved['origin'] == 'INTRODUCED'
    assert saved['assessment'] == 'HOST_REASONING_NOT_SCANNER_PROOF'


def test_broken_optional_cache_preserves_fresh_scanner_findings(setup, monkeypatch):
    import sqlite3
    from security_runtime.scan_artifacts import ScanArtifacts
    service, root, _ = setup
    ref = begin(setup)
    (root/'app.js').write_text('// comment\n'+RISK)
    def broken(*args):
        raise sqlite3.DatabaseError('fixture unavailable cache')
    monkeypatch.setattr(ScanArtifacts, 'lookup', broken)
    monkeypatch.setattr(ScanArtifacts, 'original_project', broken)
    record = finish(setup, ref)
    assert record['static']['status'] != 'FAILED'
    assert record['static']['findings'][0]['risk_attribution']['origin'] == 'UNKNOWN'


def test_private_scanner_store_failure_preserves_sanitized_baseline(setup, monkeypatch):
    import sqlite3
    service, root, _ = setup
    def broken(*args):
        raise sqlite3.DatabaseError('fixture unavailable private inputs')
    monkeypatch.setattr(BaselineInputs, 'collect_expired', broken)
    ref = begin(setup)
    record = service.load(root, ref)
    assert record['before_scan_inputs']['status'] == 'UNAVAILABLE'
    assert record['baseline']['hashes']['app.js']

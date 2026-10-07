from pathlib import Path
import json
import pytest

from security_runtime.hook_timing import RemediationCycles

pytest_plugins = ('test_remediation',)


def test_auto_fix_recurrence_starts_a_new_episode_timing_observation(setup):
    from test_remediation import FIXED, prepare
    from test_remediation_episodes import recur

    first = setup[-1]
    prepare(setup)
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    closed = setup[4]()
    fresh = recur(setup)
    assert closed['remediation_cycle_measurement']['status'] == 'OBSERVED'
    assert fresh['remediation']['episode_id'] != first['remediation']['episode_id']
    assert fresh['remediation_cycle_measurement']['status'] == 'IN_PROGRESS'


def test_cycle_breakdown_partitions_wall_clock_and_classifies_boundaries(tmp_path):
    now = [122.0]
    cycles = RemediationCycles(clock=lambda: now[0])
    cycles.start(tmp_path, 'episode-1', 95.0, token_hash='grant',
                 scope=(str(Path(tmp_path).resolve()), 'codex', 'session'),
                 points={
                     'initial_scan_finished': 96.0,
                     'policy_finished': 99.0,
                     'auto_fix_authorized': 99.0,
                     'initial_hook_response_ready': 100.0,
                     'host_continuation_observed': 105.0,
                     'prepare_task_fix_started': 105.0,
                     'prepare_task_fix_finished': 107.0,
                     'fix_edit_hook_started': 115.0,
                     'host_edit_observed': 116.0,
                     'security_rescan_started': 117.0,
                     'security_rescan_finished': 120.0,
                     'episode_closed': 121.0,
                     'return_to_host': 122.0})
    result = cycles.result(tmp_path, 'episode-1', complete=True)
    breakdown = result['remediation_cycle_breakdown_ms']
    assert result['remediation_cycle_wall_ms'] == 27000.0
    assert breakdown['runtime_to_host_continuation_wait'] == 5000.0
    assert breakdown['prepare_fix'] == 2000.0
    assert breakdown['host_fix_window'] == 8000.0
    assert breakdown['post_edit_hook'] == 2000.0
    assert breakdown['security_rescan'] == 3000.0
    assert breakdown['unaccounted'] == 0.0
    assert sum(breakdown.values()) == result['remediation_cycle_wall_ms']
    assert result['remediation_cycle_boundary']['host_fix_window'].startswith('HOST_AGENT_AND_TRANSPORT_WINDOW')
    assert result['remediation_cycle_boundary']['security_rescan'].startswith('SCANNER_PROCESSING')


def test_missing_cycle_timepoints_are_unknown_not_invented(tmp_path):
    now = [110.0]
    cycles = RemediationCycles(clock=lambda: now[0])
    cycles.start(tmp_path, 'episode-1', 100.0, token_hash='grant')
    result = cycles.result(tmp_path, 'episode-1', complete=True)
    assert result['remediation_cycle_wall_ms'] == 10000.0
    assert result['remediation_cycle_timepoints_ms']['risk_hook_started'] == 0.0
    assert result['remediation_cycle_timepoints_ms']['return_to_host'] == 10000.0
    assert result['remediation_cycle_breakdown_ms']['initial_runtime'] is None
    assert result['remediation_cycle_breakdown_ms']['unaccounted'] == 10000.0


def test_restart_does_not_fabricate_cycle_timing(tmp_path):
    now = [110.0]
    original = RemediationCycles(clock=lambda: now[0])
    original.start(tmp_path, 'episode-1', 100.0, token_hash='grant')
    restarted = RemediationCycles(clock=lambda: now[0])
    result = restarted.result(tmp_path, 'episode-1', complete=True)
    assert result['remediation_cycle_wall_ms'] is None
    assert result['remediation_cycle_timepoints_ms'] is None
    assert result['remediation_cycle_breakdown_ms'] is None


def test_same_process_reconnect_and_workspace_cannot_borrow_observations(tmp_path):
    cycles = RemediationCycles(clock=lambda: 100.0)
    cycles.start(tmp_path, 'one', 90.0, token_hash='token')
    assert not cycles.mark_token('token', 'prepare_task_fix_started', root=tmp_path/'other')
    assert not cycles.mark_token(None, 'prepare_task_fix_started', root=tmp_path)
    assert cycles.result(tmp_path/'other', 'one')['remediation_cycle_timepoints_ms'] is None
    assert RemediationCycles(clock=lambda: 100.0).result(tmp_path, 'one')['remediation_cycle_measurement']['status'] == 'UNKNOWN'


def test_points_are_frozen_after_close_including_duplicate_verify(tmp_path):
    now = [100.0]
    cycles = RemediationCycles(clock=lambda: now[0])
    cycles.start(tmp_path, 'one', 90.0, token_hash='token')
    first = cycles.result(tmp_path, 'one', complete=True)
    now[0] = 200.0
    assert not cycles.mark(tmp_path, 'one', 'episode_closed')
    assert not cycles.mark_token('token', 'security_rescan_started', root=tmp_path)
    cycles.detail(tmp_path, 'one', 'initial_scanner', 1.0)
    assert cycles.result(tmp_path, 'one', complete=True) == first


def test_changed_runtime_instance_cannot_mark_token_or_return_old_points(tmp_path, monkeypatch):
    cycles = RemediationCycles(clock=lambda: 100.0)
    cycles.start(tmp_path, 'one', 90.0, token_hash='token')
    monkeypatch.setattr('security_runtime.scanner_cache._process', __import__(
        'security_runtime.scanner_cache', fromlist=['ProcessPreparations']).ProcessPreparations(2))
    assert not cycles.mark_token('token', 'prepare_task_fix_started', root=tmp_path)
    result = cycles.result(tmp_path, 'one', complete=True)
    assert result['remediation_cycle_wall_ms'] is None
    assert result['remediation_cycle_timepoints_ms'] is None


@pytest.mark.parametrize('bad', [True, float('nan'), float('inf'), 101.0, -1.0, 70.0])
def test_untrusted_or_discontinuous_clock_values_do_not_create_points(tmp_path, bad):
    cycles = RemediationCycles(clock=lambda: 100.0)
    cycles.start(tmp_path, 'one', 90.0)
    assert not cycles.mark(tmp_path, 'one', 'prepare_task_fix_started', bad)
    cycles.clock = lambda: bad
    if bad != 101.0:
        result = cycles.result(tmp_path, 'one', complete=True)
        assert result['remediation_cycle_measurement']['status'] == 'UNKNOWN'
        assert result['remediation_cycle_timepoints_ms'] is None


def test_overlapping_spans_are_unknown_instead_of_clamped_double_counting(tmp_path):
    cycles = RemediationCycles(clock=lambda: 110.0)
    cycles.start(tmp_path, 'one', 90.0, points={'initial_hook_response_ready': 105.0,
        'prepare_task_fix_started': 100.0, 'prepare_task_fix_finished': 106.0})
    result = cycles.result(tmp_path, 'one', complete=True)
    assert result['remediation_cycle_wall_ms'] == 20000.0
    assert result['remediation_cycle_breakdown_measurement']['status'] == 'UNKNOWN'
    assert result['remediation_cycle_breakdown_ms']['initial_runtime'] is None
    assert result['remediation_cycle_breakdown_ms']['unaccounted'] == 20000.0


def test_nested_scanner_and_policy_details_are_not_summed_into_partition(tmp_path):
    cycles = RemediationCycles(clock=lambda: 110.0)
    cycles.start(tmp_path, 'one', 100.0, points={'initial_hook_response_ready': 105.0},
                 detail={'initial_scanner': 3000.0, 'initial_finding_policy': 1000.0})
    result = cycles.result(tmp_path, 'one', complete=True)
    assert result['remediation_cycle_breakdown_ms']['initial_runtime'] == 5000.0
    assert result['remediation_cycle_breakdown_ms']['unaccounted'] == 5000.0
    assert result['remediation_cycle_detail_ms']['initial_scanner'] == 3000.0
    for name in ('host_fix_started', 'host_edit_completed', 'initial_hook_response_sent', 'host_received_advisory'):
        assert result['remediation_cycle_timepoints_ms'][name] is None
        assert not cycles.mark(tmp_path, 'one', name)


def test_retry_does_not_restart_episode_or_label_host_retry_as_finalization(tmp_path):
    now = [105.0]
    cycles = RemediationCycles(clock=lambda: now[0])
    cycles.start(tmp_path, 'one', 90.0, token_hash='old')
    cycles.mark(tmp_path, 'one', 'security_rescan_started', 100.0)
    cycles.mark(tmp_path, 'one', 'security_rescan_finished', 104.0)
    now[0] = 110.0
    cycles.start(tmp_path, 'one', 109.0, token_hash='new')
    assert not cycles.mark_token('old', 'prepare_task_fix_started', root=tmp_path)
    assert cycles.mark_token('new', 'prepare_task_fix_started', root=tmp_path)
    now[0] = 120.0
    cycles.mark(tmp_path, 'one', 'security_rescan_started')
    result = cycles.result(tmp_path, 'one', complete=True)
    assert result['remediation_cycle_wall_ms'] == 30000.0
    assert result['remediation_cycle_breakdown_ms']['close/finalization'] is None
    assert result['remediation_cycle_boundary']['multiple_attempts_observed']


def test_rejected_prepare_cannot_mark_cycle_using_only_an_invalid_host_claim(setup):
    from test_remediation import args
    root, _, _, service, _, grant = setup
    before = service.cycles.result(root, grant['remediation']['episode_id'])
    arguments = args(setup)
    result = service.prepare(arguments['remediation_ref'], 'invalid-task-ref', root)
    assert result.get('status') != 'READY_FOR_HOST_FIX'
    assert service.cycles.result(root, grant['remediation']['episode_id']) == before


def test_observability_failure_does_not_change_security_proof_or_core_state(setup, monkeypatch):
    from test_remediation import FIXED, prepare
    root, runtime, provider, service, hook, _ = setup
    def unavailable(*args, **kwargs):
        raise RuntimeError('private clock error')
    monkeypatch.setattr(service.cycles, 'mark', unavailable)
    monkeypatch.setattr(service.cycles, 'result', unavailable)
    prepare(setup)
    root.joinpath('A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    output = hook()
    assert output['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert output['remediation_cycle_measurement']['status'] == 'UNKNOWN'
    assert output['remediation']['security_verification']['phase'] == 'CLOSED'
    state = service.state.path(root, 'codex', 'session').read_text()
    assert 'remediation_cycle' not in state and 'timepoints' not in state


def test_stop_continuation_and_prepare_have_distinct_runtime_observation_endpoints(setup):
    from test_remediation import prepare
    root, runtime, provider, service, _, grant = setup
    before = len(runtime.calls), len(provider.calls)
    assert service.continuation.handle(root, 'session', False)['status'] == 'CONTINUATION_REQUIRED'
    packet = prepare(setup)
    assert packet['status'] == 'READY_FOR_HOST_FIX'
    result = service.cycles.result(root, grant['remediation']['episode_id'])
    points = result['remediation_cycle_timepoints_ms']
    assert points['host_continuation_observed'] <= points['prepare_task_fix_started']
    assert result['remediation_cycle_boundary']['host_continuation_source'] == 'STOP_GUARD'
    assert result['remediation_cycle_breakdown_ms']['continuation_to_prepare'] >= 0
    assert before == (len(runtime.calls), len(provider.calls))


def test_manual_verify_without_fix_hook_does_not_guess_edit_time(setup):
    from test_remediation import FIXED, prepare, args
    root, runtime, provider, service, _, _ = setup
    prepare(setup)
    root.joinpath('A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    values = args(setup)
    output = service.verify(values['remediation_ref'], values['task_ref'], root)
    assert output['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert output['remediation_cycle_measurement']['status'] == 'OBSERVED'
    assert output['remediation_cycle_timepoints_ms']['fix_edit_hook_started'] is None
    assert output['remediation_cycle_timepoints_ms']['host_edit_observed'] is None
    assert output['remediation_cycle_breakdown_ms']['host_fix_window'] is None
    assert output['remediation_cycle_breakdown_measurement']['status'] == 'PARTIAL'


def test_current_episode_prepare_reference_and_timing_are_never_persisted(setup):
    from test_remediation import args, prepare
    root, _, _, service, _, _ = setup
    values = args(setup)
    before = service.state.path(root, 'codex', 'session').read_bytes()
    packet = prepare(setup)
    assert packet['verification_plan']['arguments']['remediation_ref'] == values['remediation_ref']
    assert before == service.state.path(root, 'codex', 'session').read_bytes()
    assert packet['remediation_cycle_boundary']['host_continuation_source'] == 'PREPARE_REQUEST'
    assert str(root) not in json.dumps(packet['remediation_cycle_timepoints_ms'])

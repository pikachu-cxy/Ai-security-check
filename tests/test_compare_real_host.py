"""SIMULATION ONLY: exercise controller orchestration, never model performance.

Fake Runtime/backend receipts explicitly mark model_observed=False. No actual
Codex host, application, scanner or network is invoked by this test module.
"""
from concurrent.futures import Future
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


@pytest.fixture
def controller(monkeypatch):
    scripts = Path(__file__).parents[1] / 'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('compare_real_host_test', scripts / 'compare_real_host.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def simulation_result(*, result=None):
    return dict(status='SIMULATION_TEST_RECEIPT', simulation=True, model_observed=False,
                result=result, usage=dict(input_tokens=100, cached_input_tokens=0,
                                          output_tokens=20, reasoning_output_tokens=5))


class ImmediatePool:
    """Simulation scheduling: completed worker before the next fixed edit."""
    def __init__(self, max_workers):
        assert max_workers == 1

    def submit(self, call, *args, **kwargs):
        future = Future()
        try:
            future.set_result(call(*args, **kwargs))
        except Exception as error:
            future.set_exception(error)
        return future

    def shutdown(self, **kwargs):
        assert kwargs == dict(wait=True, cancel_futures=True)


@pytest.fixture
def simulated_worker(controller, monkeypatch):
    log, hosts, instances = [], [], []
    positive = dict(file_path='order_route.js', line_start=4, line_end=4,
                    category='authorization', title='Unrelated wording')

    class FakeRuntime:
        def __init__(self, output, filesinitial, *, source, side):
            self.side, self.step, self.submitted = side, 0, 0
            self.final_error = self.batch_error = False
            self.source = source
            self.files = dict(filesinitial)
            instances.append(self)

        def apply_step(self, changes):
            # No checkpoint argument: baseline cannot prepare experimental work.
            self.step += 1
            self.files.update(changes)
            log.append(f'edit-{self.step}')

        def prepare_batch(self, checkpoint):
            assert self.side == 'experimental'
            log.append(f'prepare-{self.step}')
            return dict(status='BATCH_REVIEW_REQUIRED', dispatch_required=True,
                        task_ref='task', review_session=f'session-{self.step}',
                        batch_ref=f'batch-{self.step}', checkpoint=checkpoint)

        def read_batch_bound(self, packet, **kwargs):
            return dict(status='SIMULATION_CONTEXT', evidence_id='test-evidence')

        def read_final_bound(self, **kwargs):
            return dict(status='SIMULATION_CONTEXT', evidence_id='test-final-evidence')

        def submit_batch(self, packet, result):
            log.append(f'batch-submit-{packet["batch_ref"]}')
            self.submitted += 1
            if self.batch_error:
                raise RuntimeError('simulated schema rejection')
            return dict(status='SIMULATION_BATCH_ACCEPTED')

        def finish_static(self):
            log.append('finish-static')

        def finish_prepare_final(self):
            log.append('prepare-final')
            return dict(task_ref='task', review_session='final-session')

        def submit_final(self, result):
            log.append('final-submit')
            if self.final_error:
                raise RuntimeError('simulated final rejection')
            # Actual Runtime API nests normalized candidates under host_review.
            return dict(status='COMPLETE', host_review=dict(findings=[positive]))

        def receipt(self):
            return dict(simulation=True, static_execution='SIMULATION_ONLY', task={})

    def fake_review(**kwargs):
        hosts.append(kwargs)
        log.append('review-'+kwargs['output_dir'].name)
        return simulation_result(result=dict(findings=[]))

    monkeypatch.setitem(sys.modules, 'codex_readonly_host', SimpleNamespace(run_review=fake_review,
        probe_host=lambda **kwargs: dict(status='SIMULATION_ISOLATION_GATE',
                                         ready_for_model=True, simulation=True)))
    monkeypatch.setitem(sys.modules, 'real_host_runtime', SimpleNamespace(
        RuntimeCase=FakeRuntime, batch_result_schema=lambda packet: {'simulation': 'batch'},
        final_result_schema=lambda packet: {'simulation': 'final'}))
    monkeypatch.setattr(controller, 'ThreadPoolExecutor', ImmediatePool)
    monkeypatch.setattr(controller, 'source_fingerprint', lambda source: 'same-source-fingerprint')
    return SimpleNamespace(log=log, hosts=hosts, instances=instances, FakeRuntime=FakeRuntime)


def test_baseline_applies_edits_once_and_reads_nested_normalized_candidates(
        controller, simulated_worker, tmp_path):
    result = controller.run_worker(tmp_path/'source', tmp_path/'baseline', 'baseline',
                                   'order-summary', Path('fake-codex'), 10)
    assert simulated_worker.log == ['edit-1', 'edit-2', 'finish-static', 'prepare-final',
                                    'review-final', 'final-submit']
    assert result['quality_screen']['screened_expected_match_count'] == 1
    assert result['quality_measurement_status'] == 'ACCEPTED_REVIEW_SCREENED'
    assert result['model_reviews'][0]['simulation'] is True
    assert result['model_reviews'][0]['model_observed'] is False
    assert [host['output_dir'].name for host in simulated_worker.hosts] == ['final']
    assert result['host_setup_status'] == 'SIMULATION_ISOLATION_GATE'
    assert result['total_elapsed_ms'] >= result['pipeline_elapsed_ms']
    assert result['host_setup_elapsed_ms'] >= 0


def test_worker_isolation_preflight_runs_before_any_fixture_or_development(
        controller, simulated_worker, monkeypatch, tmp_path):
    def rejected_probe(**kwargs):
        assert kwargs['output_dir'] == tmp_path/'experimental-host-setup'
        assert kwargs['timeout_s'] == 60
        assert not simulated_worker.instances
        return dict(ready_for_model=False, status='SIMULATION_GATE_REJECTED')

    monkeypatch.setattr(sys.modules['codex_readonly_host'], 'probe_host', rejected_probe)
    with pytest.raises(RuntimeError, match='prerequisite failed before development'):
        controller.run_worker(tmp_path/'source', tmp_path/'experimental', 'experimental',
                              'order-summary', Path('fake-codex'), 180)
    assert not simulated_worker.instances and not simulated_worker.log


def test_completed_intermediate_workers_are_collected_without_duplicate_preparation(
        controller, simulated_worker, tmp_path):
    result = controller.run_worker(tmp_path/'source', tmp_path/'experimental', 'experimental',
                                   'order-summary', Path('fake-codex'), 10)
    assert simulated_worker.log == [
        'edit-1', 'prepare-1', 'review-batch-1',
        'edit-2', 'batch-submit-batch-1', 'prepare-2', 'review-batch-2',
        'finish-static', 'batch-submit-batch-2', 'prepare-final', 'review-final', 'final-submit']
    assert [row['phase'] for row in result['model_reviews']] == ['batch-1', 'batch-2', 'final']
    assert all(row['dispatched'] for row in result['batch_dispatches'])
    assert result['drain_complete'] is True
    assert [host['output_dir'].name for host in simulated_worker.hosts] == ['batch-1', 'batch-2', 'final']


def test_queued_checkpoint_is_not_dispatched_after_development_end(
        controller, simulated_worker, monkeypatch, tmp_path):
    deferred = []
    class DeferredPool(ImmediatePool):
        def submit(self, call, *args, **kwargs):
            future = Future()
            deferred.append((future, call, args, kwargs))
            return future
    original_prepare = simulated_worker.FakeRuntime.prepare_batch
    def prepare(self, checkpoint):
        if self.step == 2:
            return dict(status='BATCH_QUEUED', dispatch_required=False, batch_ref='queued')
        return original_prepare(self, checkpoint)
    def finish(self):
        simulated_worker.log.append('finish-static')
        future, call, args, kwargs = deferred[0]
        future.set_result(call(*args, **kwargs))
    monkeypatch.setattr(controller, 'ThreadPoolExecutor', DeferredPool)
    monkeypatch.setattr(simulated_worker.FakeRuntime, 'prepare_batch', prepare)
    monkeypatch.setattr(simulated_worker.FakeRuntime, 'finish_static', finish)
    result = controller.run_worker(tmp_path/'source', tmp_path/'experimental', 'experimental',
                                   'order-summary', Path('fake-codex'), 10)
    assert len(deferred) == 1
    assert [row['phase'] for row in result['model_reviews']] == ['batch-1', 'final']
    pending = result['batch_dispatches'][1]
    assert pending['status'] == 'BATCH_QUEUED' and not pending['dispatched']
    assert pending['drain_status'].startswith('NOT_DISPATCHED_AFTER_DEVELOPMENT')
    assert simulated_worker.log.index('finish-static') < simulated_worker.log.index('batch-submit-batch-1')


def test_failed_submission_preserves_gap_instead_of_scoring_zero_findings(
        controller, simulated_worker, monkeypatch, tmp_path):
    def reject(self, result):
        raise RuntimeError('simulated final rejection')
    monkeypatch.setattr(simulated_worker.FakeRuntime, 'submit_final', reject)
    result = controller.run_worker(tmp_path/'source', tmp_path/'baseline', 'baseline',
                                   'order-summary', Path('fake-codex'), 10)
    assert result['final_submission'] is None
    assert result['final_submission_error']['error_type'] == 'RuntimeError'
    assert result['quality_screen'] is None
    assert result['quality_measurement_status'].startswith('UNMEASURED')


def test_nonexception_busy_submission_is_not_an_accepted_empty_review(
        controller, simulated_worker, monkeypatch, tmp_path):
    monkeypatch.setattr(simulated_worker.FakeRuntime, 'submit_final',
                        lambda self, result: dict(status='BUSY'))
    result = controller.run_worker(tmp_path/'source', tmp_path/'baseline', 'baseline',
                                   'order-summary', Path('fake-codex'), 10)
    assert result['final_submission'] == dict(status='BUSY')
    assert result['final_submission_accepted'] is False
    assert result['quality_screen'] is None
    assert result['quality_measurement_status'].startswith('UNMEASURED')


def test_late_worker_usage_is_collected_after_join_without_late_submission(
        controller, simulated_worker, monkeypatch, tmp_path):
    deferred = []

    class DeadlineFuture(Future):
        def result(self, timeout=None):
            if not self.done():
                raise controller.TimeoutError()
            return super().result(timeout=timeout)

    class LatePool(ImmediatePool):
        def submit(self, call, *args, **kwargs):
            future = DeadlineFuture()
            deferred.append((future, call, args, kwargs))
            return future

        def shutdown(self, **kwargs):
            super().shutdown(**kwargs)
            simulated_worker.log.append('join-background-worker')
            for future, call, args, kwargs in deferred:
                result = call(*args, **kwargs)
                result.update(model_observed=True, simulation=False)
                future.set_result(result)

    original_prepare = simulated_worker.FakeRuntime.prepare_batch

    def prepare(self, checkpoint):
        if self.step == 2:
            return dict(status='BATCH_QUEUED', dispatch_required=False, batch_ref='queued')
        return original_prepare(self, checkpoint)

    monkeypatch.setattr(controller, 'ThreadPoolExecutor', LatePool)
    monkeypatch.setattr(simulated_worker.FakeRuntime, 'prepare_batch', prepare)
    result = controller.run_worker(tmp_path/'source', tmp_path/'experimental', 'experimental',
                                   'order-summary', Path('fake-codex'), 10)
    assert result['drain_complete'] is False
    assert result['all_model_sessions_settled_before_receipt'] is True
    assert result['total_elapsed_ms'] >= result['pipeline_completed_ms']
    assert result['late_worker_cleanup_elapsed_ms'] >= 0
    assert result['final_wait_elapsed_ms'] == pytest.approx(
        result['pipeline_completed_ms'] - result['development_elapsed_ms'], abs=0.001)
    assert [row['phase'] for row in result['model_reviews']] == ['final', 'batch-1']
    late = result['model_reviews'][1]
    assert late['late_result_not_submitted'] is True
    assert late['usage']['input_tokens'] == 100
    assert result['batch_dispatches'][0]['usage_receipt_collected_after_final'] is True
    assert simulated_worker.instances[0].submitted == 0
    assert simulated_worker.log.index('final-submit') < simulated_worker.log.index('join-background-worker')
    assert controller.totals(result['model_reviews'])['known_token_subtotals']['input_tokens'] == 100
    saved = json.loads((tmp_path/'experimental/result.json').read_text(encoding='utf-8'))
    assert saved['model_reviews'][1]['usage'] == late['usage']


def test_final_backend_exception_keeps_usage_receipt_and_an_explicit_quality_gap(
        controller, simulated_worker, monkeypatch, tmp_path):
    class ObservedHostFailure(RuntimeError):
        receipt = dict(status='MODEL_TIMEOUT', model_observed=True,
            usage=dict(input_tokens=120, cached_input_tokens=0, output_tokens=15,
                       reasoning_output_tokens=5))

    def fail_review(**kwargs):
        raise ObservedHostFailure('simulation only')

    monkeypatch.setattr(sys.modules['codex_readonly_host'], 'run_review', fail_review)
    result = controller.run_worker(tmp_path/'source', tmp_path/'baseline', 'baseline',
                                   'order-summary', Path('fake-codex'), 10)
    assert result['final_submission'] is None
    assert result['quality_screen'] is None
    assert result['model_reviews'][0]['status'] == 'MODEL_TIMEOUT'
    assert result['model_reviews'][0]['error_type'] == 'ObservedHostFailure'
    assert controller.totals(result['model_reviews'])['input_tokens'] == 120


def test_background_host_failure_does_not_prevent_final_review_or_prove_model_execution(
        controller, simulated_worker, monkeypatch, tmp_path):
    module = sys.modules['codex_readonly_host']
    original = module.run_review
    def failing_review(**kwargs):
        if kwargs['output_dir'].name.startswith('batch-'):
            raise OSError('simulated host launch failure')
        return original(**kwargs)
    monkeypatch.setattr(module, 'run_review', failing_review)
    result = controller.run_worker(tmp_path/'source', tmp_path/'experimental', 'experimental',
                                   'order-summary', Path('fake-codex'), 10)
    failed = [row for row in result['model_reviews'] if row['status'] == 'HOST_EXCEPTION']
    assert len(failed) == 2
    assert all(row['model_observed'] is False and row['usage'] is None for row in failed)
    assert result['final_submission']['status'] == 'COMPLETE'
    assert not controller.any_model_observed([dict(baseline=result, experimental=result)])


def test_simulated_receipts_are_never_counted_as_real_model_usage(controller):
    row = simulation_result(result={})
    row['model_observed'] = True  # Even an inconsistent simulation receipt is excluded.
    result = controller.totals([row])
    assert result['attempted_calls'] == 1 and result['observed_calls'] == 0
    assert result['complete'] is False
    assert all(result[key] is None for key in (
        'input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_output_tokens'))
    assert not controller.any_model_observed([dict(baseline=dict(model_reviews=[row]), experimental={})])


def test_usage_counters_keep_unknown_fields_and_partial_subtotals(controller):
    rows = [dict(model_observed=True, usage=dict(input_tokens=100, cached_input_tokens=20,
        output_tokens=30, reasoning_output_tokens=5)),
        dict(model_observed=True, status='TIMEOUT', usage=dict(input_tokens=40, output_tokens=10))]
    result = controller.totals(rows)
    assert result['observed_calls'] == 2 and result['attempted_calls'] == 2
    assert result['input_tokens'] == 140 and result['output_tokens'] == 40
    assert result['cached_input_tokens'] is None and result['reasoning_output_tokens'] is None
    assert result['known_token_subtotals']['cached_input_tokens'] == 20
    assert result['known_token_subtotals']['reasoning_output_tokens'] == 5
    assert result['complete'] is False


@pytest.mark.parametrize('value', [None, -1, True, 1.5, '2'])
def test_invalid_token_counter_is_not_coerced_to_zero(controller, value):
    receipt = dict(model_observed=True, usage=dict(input_tokens=value, cached_input_tokens=0,
        output_tokens=5, reasoning_output_tokens=0))
    result = controller.totals([receipt])
    assert result['input_tokens'] is None
    assert result['token_fields_complete']['input_tokens'] is False


def test_empty_attempts_do_not_claim_complete_zero_usage(controller):
    result = controller.totals([])
    assert result['complete'] is False and result['observed_calls'] == 0
    assert result['input_tokens'] is None


def test_prompt_hides_launch_profile_and_oracle(controller):
    packet = dict(task_ref='test-task', review_handoff=dict(
        launch=dict(environment={'OPAQUE': 'hidden-test-value'})), scope_files=['order_route.js'])
    prompt = controller.prompt_for(controller.development_cases()[0], packet)
    assert 'hidden-test-value' not in prompt and 'review_handoff' not in prompt
    assert 'expected_findings' not in prompt and 'negative_surfaces' not in prompt
    assert 'review_handoff' in packet  # Removing launch data must not mutate parent packet.


def test_pair_integrity_rejects_different_static_scope_and_missing_results(controller):
    left = dict(initial_files={'a.js': 'first'}, final_files={'a.js': 'last'},
        rules_identity='same-rules', source_unchanged=True, scan_count=1,
        scans=[dict(stage='task_finish', scope=['a.js'])], hooks=[dict(scanner_run=True)],
        model_reviews=[simulation_result(result={})], final_submission={}, quality_screen={})
    import copy
    right = copy.deepcopy(left)
    identical = controller.paired_integrity(left, right)
    assert not identical['passed']  # Simulations cannot prove a real model profile.
    assert identical['checks']['same_initial_files'] is True
    assert identical['checks']['same_model_profile'] is False
    assert not identical['timing_comparable']  # Fake runs never become measurements.
    assert not identical['quality_comparable']
    right['scans'][0]['scope'] = ['another.js']
    mismatch = controller.paired_integrity(left, right)
    assert not mismatch['passed'] and not mismatch['checks']['same_static_scopes']
    assert not mismatch['timing_comparable'] and not mismatch['quality_comparable']
    assert not controller.paired_integrity({}, {})['passed']


def test_pair_integrity_requires_runtime_accepted_final_review(controller):
    import copy
    side = dict(initial_files={'a.js': 'first'}, final_files={'a.js': 'last'},
        rules_identity='same-rules', source_unchanged=True, scan_count=1,
        scans=[dict(stage='task_finish', scope=['a.js'])], hooks=[dict(scanner_run=True)],
        model_reviews=[dict(model_observed=True, model='unit-test-model',
            model_provider='unit-test-provider', reasoning_effort='medium', timeout_s=60,
            usage=dict(input_tokens=1,
            cached_input_tokens=0, output_tokens=1, reasoning_output_tokens=0))],
        final_submission=dict(status='COMPLETE', host_review=dict(findings=[])), quality_screen={})
    right = copy.deepcopy(side)
    assert controller.paired_integrity(side, right)['timing_comparable'] is True
    right['final_submission'] = dict(status='BUSY')
    result = controller.paired_integrity(side, right)
    assert result['passed'] is True
    assert result['timing_comparable'] is False and result['quality_comparable'] is False


@pytest.mark.parametrize('key', ['model', 'model_provider', 'reasoning_effort', 'timeout_s'])
def test_model_profile_never_treats_missing_settings_as_equal(controller, key):
    receipt = dict(model_observed=True, simulation=False, model='unit-model',
                   model_provider='unit-provider', reasoning_effort='medium', timeout_s=60)
    del receipt[key]
    side = dict(model_reviews=[receipt])
    assert controller.paired_integrity(side, side)['checks']['same_model_profile'] is False


@pytest.mark.parametrize(('key', 'value'), [
    ('model', 'another-model'), ('model_provider', 'another-provider'),
    ('reasoning_effort', 'high'), ('timeout_s', 120),
    ('model', ''), ('timeout_s', True), ('timeout_s', 181), ('timeout_s', 9),
])
def test_model_profile_requires_every_observed_batch_and_final_call_to_match(controller, key, value):
    import copy
    receipt = dict(model_observed=True, simulation=False, model='unit-model',
                   model_provider='unit-provider', reasoning_effort='medium', timeout_s=60)
    left = dict(model_reviews=[copy.deepcopy(receipt)])
    right = dict(model_reviews=[copy.deepcopy(receipt), copy.deepcopy(receipt)])
    assert controller.paired_integrity(left, right)['checks']['same_model_profile'] is True
    right['model_reviews'][0][key] = value
    assert controller.paired_integrity(left, right)['checks']['same_model_profile'] is False


def test_model_reroute_cannot_be_reported_as_same_model_comparison(controller):
    import copy
    side = dict(initial_files={'a.js': 'first'}, final_files={'a.js': 'last'},
        rules_identity='same-rules', source_unchanged=True, scan_count=1,
        scans=[dict(stage='task_finish', scope=['a.js'])], hooks=[dict(scanner_run=True)],
        model_reviews=[dict(model_observed=True, model='unit-model',
            model_provider='unit-provider', reasoning_effort='medium', timeout_s=60,
            usage=dict(input_tokens=1, cached_input_tokens=0, output_tokens=1,
                       reasoning_output_tokens=0))],
        final_submission=dict(status='COMPLETE', host_review=dict(findings=[])), quality_screen={})
    right = copy.deepcopy(side)
    assert controller.paired_integrity(side, right)['timing_comparable'] is True
    right['model_reviews'][0]['model_reroutes'] = [dict(fromModel='unit-model', toModel='other-model')]
    check = controller.paired_integrity(side, right)
    assert check['checks']['no_model_reroutes'] is False
    assert not check['passed'] and not check['timing_comparable']
    assert not check['quality_comparable'] and not check['model_cost_comparable']


def test_live_report_keeps_unknown_cost_and_partial_execution_explicit(controller):
    result = dict(status='PILOT_RECORDED', source_fingerprints=dict(
        baseline='baseline-source-sha', experimental='experiment-source-sha'),
        source_unchanged=dict(baseline=True, experimental=False),
        cases=[dict(case_id='unit-case', paired_integrity=dict(passed=False,
            timing_comparable=False, quality_comparable=False, model_cost_comparable=False),
            baseline=dict(total_elapsed_ms=1234, host_setup_elapsed_ms=234, pipeline_elapsed_ms=1000,
                model_reviews=[dict(model_observed=True, usage=dict(input_tokens=100,
                    cached_input_tokens=20, output_tokens=30, reasoning_output_tokens=5))],
                final_submission=dict(status='COMPLETE', host_review=dict(coverage='PARTIAL', findings=[])),
                quality_screen=dict(screened_expected_match_count=1, expected_count=2)),
            experimental=dict(model_reviews=[dict(model_observed=True, usage=None)],
                final_submission=dict(status='BUSY'), quality_screen=None))])
    report = controller.live_report(result)
    assert 'PILOT_RECORDED' in report and '不代表全部' in report
    assert '1.234 | 0.234 | 1.000 | 100 | 20 | 30 | 1/1 | PARTIAL | 1/2，待人工核实' in report
    assert '未测量 | 未测量 | 未测量 | 未知 | 未知 | 未知 | 1/1 | 未接受 | 未测量' in report
    assert '`baseline-source-sha` | 是' in report
    assert '`experiment-source-sha` | 否' in report
    assert '订阅账单金额未测量' in report and '不得重复相加' in report


def test_live_compare_records_source_hashes_markdown_and_bounded_worker_timeout(
        controller, monkeypatch, tmp_path):
    probe = dict(ready_for_model=True, real_model_called=False)
    monkeypatch.setitem(sys.modules, 'codex_readonly_host', SimpleNamespace(probe_host=lambda **kw: probe))
    worker_timeouts = []

    def fake_process(command, **kwargs):
        if 'rev-parse' in command:
            return SimpleNamespace(stdout=controller.BASELINE_COMMIT+'\n')
        if 'status' in command:
            return SimpleNamespace(stdout='')
        worker_timeouts.append(kwargs['timeout'])
        target = Path(command[command.index('--output')+1])
        controller.write_json(target/'result.json', dict(model_reviews=[], final_submission=None))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(controller.subprocess, 'run', fake_process)
    monkeypatch.setattr(controller, 'source_fingerprint', lambda root: root.name+'-unchanged')
    output = tmp_path/'recorded-pilot'
    args = SimpleNamespace(output=output, baseline=tmp_path/'baseline', experimental=tmp_path/'experiment',
                           codex=Path('fake-codex'), python=Path('fake-python'), timeout=180)
    result = controller.compare(args)
    assert worker_timeouts == [630]*6
    assert result['status'] == 'PILOT_RECORDED' and result['model_observed'] is False
    assert not any(row['paired_integrity']['passed'] for row in result['cases'])
    assert result['source_fingerprints'] == dict(baseline='baseline-unchanged', experimental='experiment-unchanged')
    assert (output/'comparison.md').exists()
    assert '不代表全部' in (output/'comparison.md').read_text(encoding='utf-8')


def test_cli_supports_180_second_reviews_while_default_stays_60(controller, monkeypatch, tmp_path):
    captured = []
    monkeypatch.setattr(controller, 'compare', lambda args: captured.append(args.timeout) or dict(
        status='PILOT_RECORDED', model_observed=False))
    arguments = ['compare_real_host', '--baseline', str(tmp_path/'before'), '--experimental',
                 str(tmp_path/'after'), '--codex', 'unit-codex', '--output', str(tmp_path/'output')]
    monkeypatch.setattr(sys, 'argv', arguments)
    assert controller.main() == 0
    monkeypatch.setattr(sys, 'argv', arguments+['--timeout', '180'])
    assert controller.main() == 0
    assert captured == [60, 180]


def test_blocked_preflight_never_starts_workers_or_manufactures_comparison(
        controller, monkeypatch, tmp_path):
    probe = dict(ready_for_model=False, real_model_called=False, actual_model_calls=0,
        status='UNSUPPORTED_HOST', unexpected_tools=['exec_command', 'spawn_agent'],
        opaque_capture='DO-NOT-RENDER-OPAQUE-REQUEST')
    monkeypatch.setitem(sys.modules, 'codex_readonly_host', SimpleNamespace(probe_host=lambda **kw: probe))
    calls = []
    def fake_process(command, **kwargs):
        calls.append(command)
        if 'rev-parse' in command:
            return SimpleNamespace(stdout=controller.BASELINE_COMMIT+'\n')
        if 'status' in command:
            return SimpleNamespace(stdout='')
        raise AssertionError('A blocked host must not start a worker or a model')
    monkeypatch.setattr(controller.subprocess, 'run', fake_process)
    monkeypatch.setattr(controller, 'source_fingerprint', lambda root: root.name+'-unchanged')
    output = tmp_path/'blocked-report'
    args = SimpleNamespace(output=output, baseline=tmp_path/'baseline', experimental=tmp_path/'experiment',
                           codex=Path('fake-codex'), python=Path('fake-python'), timeout=10)
    result = controller.compare(args)
    assert result['status'] == 'HOST_PREFLIGHT_BLOCKED'
    assert result['actual_model_calls'] == 0 and result['model_observed'] is False
    assert result['timing_comparison'] is None and result['quality_comparison'] is None
    assert result['model_cost_comparison'] is None
    assert all(result['source_unchanged'].values())
    assert result['source_fingerprints'] == {'baseline': 'baseline-unchanged',
                                             'experimental': 'experiment-unchanged'}
    assert len(calls) == 2
    saved = json.loads((output/'comparison.json').read_text(encoding='utf-8'))
    assert saved == result
    markdown = (output/'comparison.md').read_text(encoding='utf-8')
    assert 'exec_command' in markdown and 'spawn_agent' in markdown
    assert '真实模型调用：0' in markdown and '未测量' in markdown
    assert 'baseline-unchanged' in markdown and 'experiment-unchanged' in markdown
    assert 'DO-NOT-RENDER-OPAQUE-REQUEST' not in markdown

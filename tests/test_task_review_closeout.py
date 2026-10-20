"""Readable work survives early final submissions, including Git fast-forwards."""
import copy
import subprocess

import pytest

from security_runtime.task_preimages import TaskPreimageUnavailable
from security_runtime.task_security import TaskContextError
from test_task_security import service  # noqa: F401
from task_review_helpers import read_plan, read_window, review_all


def review_units(tasks, root, ref, packet, units):
    for unit in units:
        for window in unit['required_windows']:
            read_window(tasks, root, ref, packet['review_session'], window)
        tasks.submit_batch(root, ref, packet['review_session'], [unit['unit_id']], 'REVIEWED', [])


@pytest.mark.parametrize('update', ['edit', 'fast_forward'])
def test_twenty_one_changes_cannot_close_after_only_three_reviews(service, update):
    tasks, root, runtime = service
    paths = [root / f'change_{i:02}.py' for i in range(21)]
    for path in paths:
        path.write_text('def check(subject):\n    return policy.allow(subject)\n')

    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()

    if update == 'fast_forward':
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'baseline')
        baseline = git('rev-parse', 'HEAD')
        for path in paths:
            path.write_text('def check(subject):\n    return policy.enforce(subject)\n')
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'incoming')
        incoming = git('rev-parse', 'HEAD')
        git('checkout', '--detach', baseline)
    ref = tasks.begin(root, 'twenty-one-' + update)['task_ref']
    if update == 'fast_forward':
        git('merge', '--ff-only', incoming)
    else:
        for path in paths:
            path.write_text('def check(subject):\n    return policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(tasks, root, ref, packet)
    assert len(units) == 21
    review_units(tasks, root, ref, packet, units[:3])
    tasks.submit_batch(root, ref, packet['review_session'], [u['unit_id'] for u in units[3:]],
                       'PARTIAL', ['Remaining eighteen files were not read.'])
    before = tasks.load(root, ref)
    for coverage, limitations in [('PARTIAL', ['Too many files; stopping here.']), ('REVIEWED', [])]:
        result = tasks.submit(root, ref, packet['review_session'], [], coverage, limitations)
        assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
        assert result['review_required'] and not result['result_saved']
        assert result['pending_unit_count'] == 18
        assert not result['scanner_run'] and not result['repair_authorized']
        assert result['next_action']['tool'] == 'read_task_review_context'
        assert result['next_action']['file_path'] == units[3]['path']
        assert tasks.load(root, ref) == before
    review_units(tasks, root, ref, packet, units[3:])
    result = tasks.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['result_saved'] and result['review_progress']['reviewed_unit_count'] == 21
    assert result['review_progress']['coverage'] == 'REVIEWED'
    assert len(runtime.calls) == 1


def test_delivered_code_still_needs_reasoning_submission(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'read-without-submission')['task_ref']
    (root / 'new.py').write_text('policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(tasks, root, ref, packet)
    read_window(tasks, root, ref, packet['review_session'], units[0]['required_windows'][0])
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Did not finish reasoning.'])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
    assert result['next_action']['tool'] == 'submit_task_review_batch'
    assert result['next_action']['unit_ids'] == [units[0]['unit_id']]
    assert tasks.load(root, ref)['phase'] == 'REVIEWING'


def test_masked_semantics_do_not_excuse_another_unread_file(service):
    tasks, root, _ = service
    (root / 'masked.py').write_text("password = 'synthetic-old-credential'\n")
    ref = tasks.begin(root, 'masked-and-readable')['task_ref']
    (root / 'masked.py').write_text("password = 'synthetic-new-credential'\n")
    (root / 'unread.py').write_text('policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(tasks, root, ref, packet)
    masked = next(unit for unit in units if unit['path'] == 'masked.py')
    review_units(tasks, root, ref, packet, [masked])
    assert tasks.load(root, ref)['review_plan']['units'][0]['evidence_gaps']
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Masked values remain unknown.'])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
    assert result['next_action']['file_path'] == 'unread.py'
    review_all(tasks, root, ref, packet)
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Masked values remain unknown.'])
    assert result['result_saved'] and result['review_progress']['coverage'] == 'PARTIAL'


def test_unavailable_before_source_does_not_excuse_current_source(service, monkeypatch):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'missing-before')['task_ref']
    (root / 'routes.py').write_text('def check(subject):\n    return policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(tasks, root, ref, packet)

    def missing(*args):
        raise TaskPreimageUnavailable('TASK_PREIMAGE_MISSING')

    monkeypatch.setattr(tasks, 'before_lines', missing)
    with pytest.raises(TaskContextError):
        tasks.read(root, ref, packet['review_session'], 'routes.py', 1, 2, source_version='BEFORE_TASK')
    tasks.submit_batch(root, ref, packet['review_session'], [units[0]['unit_id']], 'PARTIAL', ['Before source missing.'])
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Before source missing.'])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'
    assert result['next_action']['source_version'] == 'CURRENT'
    for window in units[0]['required_windows']:
        if window['location_version'] == 'CURRENT_TASK_END':
            read_window(tasks, root, ref, packet['review_session'], window)
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Before source missing.'])
    assert result['result_saved'] and result['review_progress']['coverage'] == 'PARTIAL'
    assert len(runtime.calls) == 1


def test_partial_scanner_status_cannot_close_readable_work(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'partial-scanner')['task_ref']
    (root / 'new.py').write_text('policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    record = tasks.load(root, ref)
    record['static']['status'] = record['static']['coverage'] = 'PARTIAL'
    tasks.store(root).save(record)
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Scanner was partial.'])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED'


def test_refused_packet_with_insufficient_remaining_budget_can_save_partial(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'last-few-source-bytes')['task_ref']
    (root / 'new.py').write_text('policy.enforce(subject)\n')
    packet = tasks.prepare(root, ref, protocol_version=3)
    record = tasks.load(root, ref)
    ledger = record['review_ledger']
    ledger['source_bytes'] = ledger['category_limits']['source'] - 1
    ledger['total_bytes'] = sum(ledger[key + '_bytes'] for key in ('source', 'navigation', 'control'))
    tasks.store(root).save(record)
    before = copy.deepcopy(ledger)
    with pytest.raises(TaskContextError) as error:
        tasks.read(root, ref, packet['review_session'], 'new.py', 1, 1)
    assert error.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET'
    saved = tasks.load(root, ref)
    assert saved['review_ledger'] == before and not saved['evidence']
    assert saved['review_delivery_blocker']['reason'] == 'TASK_CONTEXT_SOURCE_BUDGET'
    result = tasks.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['Actual source budget refusal.'])
    assert result['result_saved'] and result['review_progress']['coverage'] == 'PARTIAL'
    # A real subsequent edit can allocate new obligations. A failure on the
    # previous revision must not exempt the new readable source from review.
    (root / 'next.py').write_text(''.join(f'guard_{i} = policy.enforce(subject_{i})\n' for i in range(1000)))
    tasks.finish(root, ref)
    revised = tasks.prepare(root, ref, protocol_version=3)
    current = tasks.load(root, ref)
    assert current['review_revision'] == 2
    assert current['review_ledger']['source_bytes'] == before['source_bytes']
    result = tasks.submit(root, ref, revised['review_session'], [], 'PARTIAL', ['Prior revision exhausted its allowance.'])
    assert result['status'] == 'REVIEW_CONTINUE_REQUIRED' and not result['result_saved']


def test_user_stop_retains_original_incomplete_record(service):
    tasks, root, _ = service
    ref = tasks.begin(root, 'explicit-stop')['task_ref']
    (root / 'new.py').write_text('policy.enforce(subject)\n')
    tasks.prepare(root, ref, protocol_version=3)
    before = copy.deepcopy(tasks.load(root, ref)['baseline'])
    stopped = tasks.skip(root, ref, 'User explicitly stopped this review.')
    assert stopped['status'] == 'INCOMPLETE'
    assert tasks.load(root, ref)['baseline'] == before

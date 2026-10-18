"""Acceptance regressions: disjoint edits and large files use bounded v3 frames."""
import pytest

from security_runtime.task_security import TaskContextError
from security_runtime.task_review_plan import build_plan, DEFAULT_LIMITS
from test_task_review_plan import task
from task_review_helpers import read_plan, read_window, review_all
from test_task_review_invariants import assert_reviewed
from test_task_security import service  # noqa: F401


def scattered_source(count=740):
    return [f'value_{i:04} = policy.check(subject_{i:04}) and '
            f'policy.check(owner_{i:04}) and policy.check(resource_{i:04}) and '
            f'policy.check(scope_{i:04}) and policy.check(group_{i:04})'
            for i in range(count)]


def test_eleven_scattered_hunks_keep_each_before_and_after_window():
    old = scattered_source()
    new = old.copy()
    positions = list(range(91, 642, 55))
    for position in positions:
        new[position] = new[position].replace('policy.check(', 'policy.enforce(', 1)
    record = task({'main.py': old}, {'main.py': new})
    plan = build_plan(record, now=1)
    windows = plan['units'][0]['required_windows']
    assert len(windows) == len(positions) * 2 == 22
    assert all(window['end_line'] - window['start_line'] < 10 for window in windows)
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        selected = [window for window in windows if window['location_version'] == version]
        assert all(any(window['start_line'] <= position + 1 <= window['end_line']
                       for window in selected) for position in positions)
    assert plan['budget']['limits']['response_bytes'] == DEFAULT_LIMITS['response_bytes']


def test_distributed_changes_cover_every_required_hunk_in_one_task(service):
    s, root, runtime = service
    old = scattered_source()
    (root/'routes.py').write_text('\n'.join(old)+'\n')
    ref = s.begin(root, 'eleven-disjoint-hunks')['task_ref']
    new = old.copy()
    for position in range(91, 642, 55):
        new[position] = new[position].replace('policy.check(', 'policy.enforce(', 1)
    (root/'routes.py').write_text('\n'.join(new)+'\n')
    packet = s.prepare(root, ref)
    delivered, units = review_all(s, root, ref, packet)
    assert len(units) == 1 and len(delivered) == 22
    assert all(len(page['lines']) < 10 for page in delivered)
    assert_reviewed(s, root, ref, packet)
    budget = s.load(root, ref)['review_ledger']
    assert budget['total_bytes'] <= budget['limits']['total_bytes']
    assert budget['source_bytes'] <= budget['category_limits']['source']
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('kind', ['ADDED', 'DELETED'])
def test_added_and_deleted_files_still_require_every_original_line(kind):
    body = scattered_source()
    before, after = ({}, {'main.py': body}) if kind == 'ADDED' else ({'main.py': body}, {})
    record = task(before, after, [dict(path='main.py', change=kind)])
    window, = build_plan(record, now=1)['units'][0]['required_windows']
    assert window['start_line'] == 1 and window['end_line'] == len(body)
    assert window['location_version'] == ('CURRENT_TASK_END' if kind == 'ADDED' else 'BEFORE_DELETION')


def test_large_added_file_has_adaptive_source_allowance_and_complete_bounded_delivery(service):
    s, root, runtime = service
    ref = s.begin(root, 'adaptive-large-delivery')['task_ref']
    (root/'added.py').write_text('\n'.join(scattered_source(900))+'\n')
    packet = s.prepare(root, ref)
    delivered, _ = review_all(s, root, ref, packet)
    assert all(len(page['lines']) <= 80 for page in delivered)
    assert sum(len(page['lines']) for page in delivered) == 900
    assert_reviewed(s, root, ref, packet)
    saved = s.load(root, ref)
    assert saved['review_ledger']['source_bytes'] > 64_000
    assert len(runtime.calls) == 1


def test_exhausted_source_allowance_retains_unread_gap_without_completion_claim(service):
    s, root, runtime = service
    ref = s.begin(root, 'source-category-exhaustion')['task_ref']
    (root/'added.py').write_text('\n'.join(scattered_source(900))+'\n')
    packet = s.prepare(root, ref)
    units, _ = read_plan(s, root, ref, packet)
    window = units[0]['required_windows'][0]
    read_window(s, root, ref, packet['review_session'], dict(window, end_line=1))
    record = s.load(root, ref)
    ledger = record['review_ledger']
    ledger['source_bytes'] = ledger['category_limits']['source']
    s.store(root).save(record)
    with pytest.raises(TaskContextError) as rejected:
        s.read(root, ref, packet['review_session'], 'added.py', 2, 2)
    assert rejected.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET'
    receipt = s.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['added.py has unread source'])
    assert receipt['result_saved'] is True
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'PARTIAL'
    gaps = s.load(root, ref)['review_completion']['gaps']
    assert any(gap['reason'] == 'SOURCE_RANGE_UNREAD' and gap['path'] == 'added.py' for gap in gaps)
    assert len(runtime.calls) == 1

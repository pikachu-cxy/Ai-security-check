"""Acceptance regressions: disjoint edits stay bounded without weakening limits."""
import pytest

from security_runtime.task_security import TaskContextError
from security_runtime.task_review_plan import build_plan, DEFAULT_LIMITS
from test_task_review_plan import task
from test_task_review_v2 import review_all, assert_reviewed
from test_task_security import service  # noqa: F401; shared fixture


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
    assert plan['budget']['limits'] == DEFAULT_LIMITS


def test_distributed_cli_sized_changes_finish_under_original_64kb_batch(service):
    s, root, runtime = service
    old = scattered_source()
    (root/'routes.py').write_text('\n'.join(old)+'\n')
    ref = s.begin(root, 'eleven-disjoint-hunks')['task_ref']
    new = old.copy()
    for position in range(91, 642, 55):
        new[position] = new[position].replace('policy.check(', 'policy.enforce(', 1)
    (root/'routes.py').write_text('\n'.join(new)+'\n')
    packet = s.prepare(root, ref, protocol_version=2)
    delivered, units = review_all(s, root, ref, packet)
    assert len(units) == 1 and len(delivered) == 22
    assert all(page['end_line'] - page['start_line'] < 10 for page in delivered)
    assert_reviewed(s, root, ref, packet)
    saved = s.load(root, ref)
    budget = saved['review_ledger']
    assert budget['limits'] == DEFAULT_LIMITS
    assert max(budget['batches'].values()) <= 64_000
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('kind', ['ADDED', 'DELETED'])
def test_added_and_deleted_files_still_require_every_original_line(kind):
    body = scattered_source()
    before, after = ({}, {'main.py': body}) if kind == 'ADDED' else ({'main.py': body}, {})
    record = task(before, after, [dict(path='main.py', change=kind)])
    window, = build_plan(record, now=1)['units'][0]['required_windows']
    assert window['start_line'] == 1 and window['end_line'] == len(body)
    assert window['location_version'] == ('CURRENT_TASK_END' if kind == 'ADDED' else 'BEFORE_DELETION')


def test_genuinely_large_added_file_retains_gap_when_fixed_batch_is_exhausted(service):
    s, root, runtime = service
    ref = s.begin(root, 'real-delivery-limit')['task_ref']
    (root/'added.py').write_text('\n'.join(scattered_source(900))+'\n')
    packet = s.prepare(root, ref, protocol_version=2)
    next_line = 1
    with pytest.raises(TaskContextError) as rejected:
        while True:
            page = s.read(root, ref, packet['review_session'], 'added.py', next_line, 900)
            if not page['has_more']:
                pytest.fail('The original 64KB batch should not fit this full file')
            next_line = page['next_read']['start_line']
    assert rejected.value.reason_code == 'TASK_CONTEXT_BATCH_BUDGET'
    result = s.submit(root, ref, packet['review_session'], [], 'PARTIAL', ['added.py has unread source after the fixed delivery limit'])
    assert result['host_review']['coverage'] == 'PARTIAL'
    gaps = s.load(root, ref)['review_completion']['gaps']
    assert any(gap['reason'] == 'SOURCE_RANGE_UNREAD' and gap['path'] == 'added.py' for gap in gaps)
    assert len(runtime.calls) == 1

"""Readable v3 transport on isolated task records; no scanner/model execution."""
import copy
import json

import pytest

from security_runtime import task_review_plan as plans
from security_runtime import task_review_transport as transport
from security_runtime.task_review import TaskReviewCoordinator
from security_runtime.task_security import TaskContextError
from security_runtime.task_security import TaskSecurityService
from security_runtime.task_ownership import session_owner
from test_task_security import service  # noqa: F401


@pytest.fixture
def coordinator(service, monkeypatch):
    tasks, root, runtime = service
    # This suite tests the transport boundary independently of shipped guidance.
    monkeypatch.setattr(TaskReviewCoordinator, '_method', lambda self, protocol_version=3:
        dict(version=f'fixture-review-v{protocol_version}', sha256='a' * 64, content='Fixture method'))
    return TaskReviewCoordinator(tasks), tasks, root, runtime


def prepared(sample, source=None):
    coordinator, tasks, root, _ = sample
    ref = tasks.begin(root, 'transport-v3')['task_ref']
    (root / 'added.py').write_text(source or 'allowed = policy.check(subject)\n', encoding='utf-8')
    packet = coordinator.prepare(root, ref, protocol_version=3)
    assert packet['status'] == 'REVIEW_REQUIRED'
    return ref, packet['review_session'], packet


def test_compact_lines_preserve_source_characters_without_repeated_location():
    lines = ['def check(user):', '    return policy.enforce(user)', '', '# 任意说明按原样处理']
    evidence = dict(evidence_id='te3-fixture', start_line=1, end_line=4, total_lines=4)
    packet = transport.source_packet(evidence, 'sr1-fixture', lines, requested_high=4)
    assert packet['lines'] == lines
    assert not {'path', 'file_sha256', 'location_version', 'numbered_lines'} & packet.keys()
    assert packet['start_line'] + len(packet['lines']) - 1 == 4
    assert json.loads(json.dumps(packet, ensure_ascii=False)) == packet


def test_delivered_ranges_do_not_confuse_before_current_or_another_hash():
    record = dict(evidence={
        'first': dict(path='a.py', file_sha256='one', location_version='CURRENT_TASK_END', start_line=2, end_line=4),
        'old': dict(path='a.py', file_sha256='one', location_version='BEFORE_TASK', start_line=1, end_line=8),
        'changed': dict(path='a.py', file_sha256='two', location_version='CURRENT_TASK_END', start_line=1, end_line=8),
        'last': dict(path='a.py', file_sha256='one', location_version='CURRENT_TASK_END', start_line=7, end_line=8)})
    missing, refs = transport.delivered_ranges(record, 'a.py', 'one', 'CURRENT_TASK_END', 1, 10)
    assert missing == [[1, 1], [5, 6], [9, 10]] and refs == ['first', 'last']


def test_source_bindings_are_registered_in_plan_and_not_repeated_on_each_read(coordinator):
    c, tasks, root, runtime = coordinator
    ref, session, packet = prepared(coordinator, ''.join(f'guard_{i} = policy.check(user_{i})\n' for i in range(100)))
    bindings = {row['source_ref']: row for row in packet['plan']['sources']}
    first = c.read(root, ref, session, 'added.py', 1, 50)
    second = c.read(root, ref, session, 'added.py', 51, 100)
    assert first['source_ref'] == second['source_ref']
    assert bindings[first['source_ref']]['path'] == 'added.py'
    assert all('source' not in row for row in (first, second))
    assert all('numbered_lines' not in row and len(row['lines']) == 50 for row in (first, second))
    assert len(runtime.calls) == 1 and tasks.load(root, ref)['review_ledger']['reads'] == 2


def test_duplicate_delivery_is_only_navigation_and_does_not_renew_or_add_evidence(coordinator):
    c, tasks, root, _ = coordinator
    clock = [1_000.0]
    tasks.now = lambda: clock[0]
    ref, session, _ = prepared(coordinator)
    sent = c.read(root, ref, session, 'added.py', 1, 1)
    before = tasks.load(root, ref)
    clock[0] += 100
    duplicate = c.read(root, ref, session, 'added.py', 1, 1)
    after = tasks.load(root, ref)
    assert duplicate['status'] == 'ALREADY_DELIVERED'
    assert duplicate['evidence_refs'] == [sent['evidence_id']] and duplicate['source_lines_delivered'] == 0
    assert 'lines' not in duplicate and after['evidence'] == before['evidence']
    assert after['review_ledger']['reads'] == before['review_ledger']['reads']
    assert after['review_ledger']['source_bytes'] == before['review_ledger']['source_bytes']
    assert after['review_ledger']['navigation_bytes'] > before['review_ledger']['navigation_bytes']
    assert after['review_deadline'] == before['review_deadline']


def test_overlapping_read_delivers_only_first_unread_interval_and_preserves_remaining_gaps(coordinator):
    c, tasks, root, _ = coordinator
    ref, session, packet = prepared(coordinator, ''.join(f'item_{i} = access.check(user_{i})\n' for i in range(20)))
    c.read(root, ref, session, 'added.py', 5, 10)
    first = c.read(root, ref, session, 'added.py', 1, 20)
    assert first['start_line'] == 1 and len(first['lines']) == 4
    assert first['next_range'] == [5, 20]
    partial = c.submit_batch(root, ref, session, [packet['plan']['units'][0]['unit_id']], 'REVIEWED', [])
    assert partial['coverage'] == 'PARTIAL'
    next_page = c.read(root, ref, session, 'added.py', *first['next_range'])
    assert next_page['start_line'] == 11 and len(next_page['lines']) == 10
    assert 'next_range' not in next_page
    done = c.submit_batch(root, ref, session, [packet['plan']['units'][0]['unit_id']], 'REVIEWED', [])
    assert done['coverage'] == 'REVIEWED'
    assert tasks.load(root, ref)['review_ledger']['reads'] == 3


def test_bounded_source_pages_cover_every_requested_line_and_never_claim_unsent_tail(coordinator):
    c, tasks, root, _ = coordinator
    source = ''.join(f'guard_{i:03} = policy.enforce(subject_{i:03}, tenant_context)\n' for i in range(600))
    ref, session, packet = prepared(coordinator, source)
    low, high, sent = 1, 600, []
    while True:
        page = c.read(root, ref, session, 'added.py', low, high)
        assert transport.packet_bytes(page) <= tasks.load(root, ref)['review_ledger']['limits']['response_bytes']
        sent.extend(range(page['start_line'], page['start_line'] + len(page['lines'])))
        if 'next_range' not in page:
            break
        low, high = page['next_range']
        gaps = plans.plan_gaps(tasks.load(root, ref))
        assert any(gap.get('reason') == 'SOURCE_RANGE_UNREAD' for gap in gaps)
    assert sent == list(range(1, 601))
    assert c.submit_batch(root, ref, session, [packet['plan']['units'][0]['unit_id']], 'REVIEWED', [])['coverage'] == 'REVIEWED'


def test_refused_source_packet_retains_request_without_evidence_or_lease_progress(coordinator):
    c, tasks, root, _ = coordinator
    ref, session, _ = prepared(coordinator)
    record = tasks.load(root, ref)
    record['review_ledger']['source_bytes'] = record['review_ledger']['category_limits']['source']
    tasks.store(root).save(record)
    original = copy.deepcopy(record)
    with pytest.raises(TaskContextError) as rejected:
        c.read(root, ref, session, 'added.py', 1, 1)
    assert rejected.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET'
    after = tasks.load(root, ref)
    assert after['evidence'] == original['evidence']
    assert after['review_ledger'] == original['review_ledger']
    assert after['review_deadline'] == original['review_deadline']
    assert after['context_requests']
    assert any(gap.get('reason') == 'SOURCE_RANGE_UNREAD' for gap in plans.plan_gaps(after))


def test_idle_resume_preserves_same_plan_session_and_consumption_but_polling_does_not_extend(coordinator):
    c, tasks, root, runtime = coordinator
    clock = [1_000.0]
    tasks.now = lambda: clock[0]
    ref, session, _ = prepared(coordinator)
    c.read(root, ref, session, 'added.py', 1, 1)
    before = tasks.load(root, ref)
    clock[0] += 100
    c.prepare(root, ref, protocol_version=3)
    active = tasks.load(root, ref)
    assert active['review_deadline'] == before['review_deadline']
    clock[0] = active['review_deadline'] + 1
    resumed = c.prepare(root, ref, protocol_version=3)
    after = tasks.load(root, ref)
    assert resumed['review_session'] == session
    assert after['review_plan']['plan_id'] == before['review_plan']['plan_id']
    assert after['review_ledger']['source_bytes'] == before['review_ledger']['source_bytes']
    assert after['review_ledger']['reads'] == before['review_ledger']['reads']
    assert after['evidence'] == before['evidence'] and after['baseline'] == before['baseline']
    assert after['review_ledger']['activity_lease']['resumes'] == 1
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('protocol', [1, 2])
def test_old_protocol_is_rejected_without_creating_or_replacing_a_plan(coordinator, protocol):
    from security_runtime.task_review_protocol import UnsupportedTaskReviewProtocol
    c, tasks, root, runtime = coordinator
    ref = tasks.begin(root, 'no-protocol-downgrade')['task_ref']
    (root / 'added.py').write_text('allowed = access.check(subject)\n')
    before = tasks.load(root, ref)
    with pytest.raises(UnsupportedTaskReviewProtocol):
        c.prepare(root, ref, protocol_version=protocol)
    assert tasks.load(root, ref) == before and not runtime.calls
    c.prepare(root, ref)
    prepared_record = tasks.load(root, ref)
    with pytest.raises(UnsupportedTaskReviewProtocol):
        c.prepare(root, ref, protocol_version=protocol)
    assert tasks.load(root, ref) == prepared_record and len(runtime.calls) == 1


def test_terminal_receipt_never_uses_source_budget_or_carries_unbounded_host_prose(coordinator, monkeypatch):
    c, tasks, root, _ = coordinator
    ref, _, _ = prepared(coordinator)
    record = tasks.load(root, ref)
    record.update(phase='COMPLETE', review=dict(coverage='PARTIAL', findings=[{'title': 'private host prose'}]),
        review_completion=dict(unit_count=1, reviewed_unit_count=0, coverage='PARTIAL'))
    before = copy.deepcopy(record['review_ledger'])
    monkeypatch.setattr(plans, 'charge_packet', lambda *a, **kw: pytest.fail('terminal receipt charged source ledger'))
    receipt = c.completion_packet(record)
    assert receipt['result_saved'] and receipt['result_details_required']
    assert receipt['scan_status'] == record['static']['status']
    assert receipt['review_progress']['coverage'] == 'PARTIAL'
    assert record['review_ledger'] == before and transport.packet_bytes(receipt) <= 1_600
    assert 'private host prose' not in json.dumps(receipt) and 'added.py' not in json.dumps(receipt)


def complete_service_plan(tasks, root, ref, prepared):
    """Use only public plan/source/batch entry points and their real bindings."""
    session, page, sources, delivered = prepared['review_session'], prepared['plan'], {}, []
    while True:
        sources.update({binding['source_ref']: binding for binding in page['sources']})
        for unit in page['units']:
            for window in unit['required_windows']:
                binding = sources[window['source_ref']]
                version = 'CURRENT' if binding['location_version'] == 'CURRENT_TASK_END' else 'BEFORE_TASK'
                low, high = window['start_line'], window['end_line'] or 2_147_483_647
                while True:
                    result = tasks.read(root, ref, session, binding['path'], low, high, source_version=version)
                    delivered.append(result)
                    if 'next_range' not in result:
                        break
                    low, high = result['next_range']
            tasks.submit_batch(root, ref, session, [unit['unit_id']], 'REVIEWED', [])
        if page['next_cursor'] is None:
            return delivered
        page = tasks.review_plan(root, ref, session, cursor=page['next_cursor'], limit=5)


def test_real_service_v3_first_prepare_full_before_deleted_review_save_and_history(service):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'real-v3-complete')['task_ref']
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return policy.enforce(user, order_id)\n')
    (root / 'auth.py').unlink()
    prepared = tasks.prepare(root, ref, protocol_version=3)
    assert prepared['quick_skill']['version'] == 'quick-task-review-v3'
    started = tasks.load(root, ref)['review_started_at']
    assert prepared['protocol_version'] == 3
    delivered = complete_service_plan(tasks, root, ref, prepared)
    assert all('lines' in row or row.get('status') == 'ALREADY_DELIVERED' for row in delivered)
    saved = tasks.submit(root, ref, prepared['review_session'], [], 'REVIEWED', [])
    assert saved['result_saved'] and saved['review_progress']['coverage'] == 'REVIEWED'
    record = tasks.load(root, ref)
    assert record['review']['coverage'] == 'REVIEWED' and record['review_started_at'] == started
    assert record['static']['status'] == 'SUCCESS' and len(runtime.calls) == 1
    assert any(e['location_version'] == 'BEFORE_DELETION' for e in record['evidence'].values())
    before = copy.deepcopy(record)
    history = tasks.get(root, ref, finding_limit=1)
    assert history['history_read_only'] is True and history['host_review']['coverage'] == 'REVIEWED'
    assert tasks.load(root, ref) == before


def test_real_service_idle_resume_rejects_foreign_owner_and_changed_source_without_rebaseline(service):
    original, root, runtime = service
    clock = [1_000.0]
    tasks = TaskSecurityService(runtime, original.hooks, now=lambda: clock[0],
                                owner=session_owner('codex', 'v3-original-owner'))
    foreign = TaskSecurityService(runtime, original.hooks, now=lambda: clock[0],
                                  owner=session_owner('codex', 'v3-other-owner'))
    ref = tasks.begin(root, 'real-v3-resume')['task_ref']
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return policy.enforce(user, order_id)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    tasks.read(root, ref, prepared['review_session'], 'routes.py', 1, 2)
    before = tasks.load(root, ref)
    clock[0] = before['review_deadline'] + 1
    with pytest.raises(ValueError, match='another session'):
        foreign.prepare(root, ref, protocol_version=3)
    assert tasks.load(root, ref) == before
    resumed = tasks.prepare(root, ref, protocol_version=3)
    after = tasks.load(root, ref)
    assert resumed['review_session'] == prepared['review_session']
    assert after['review_plan']['plan_id'] == before['review_plan']['plan_id']
    assert after['evidence'] == before['evidence'] and after['baseline'] == before['baseline']
    assert after['review_ledger']['source_bytes'] == before['review_ledger']['source_bytes']
    clock[0] = after['review_deadline'] + 1
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return policy.deny(user, order_id)\n')
    rejected = tasks.prepare(root, ref, protocol_version=3)
    assert rejected['status'] == 'STALE'
    assert tasks.load(root, ref) == after and len(runtime.calls) == 1


def test_real_service_saves_partial_when_all_delivery_categories_are_spent(service):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'real-v3-terminal')['task_ref']
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return policy.enforce(user, order_id)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    record = tasks.load(root, ref)
    for category, limit in record['review_ledger']['category_limits'].items():
        record['review_ledger'][category + '_bytes'] = limit
    record['review_ledger']['total_bytes'] = record['review_ledger']['limits']['total_bytes']
    tasks.store(root).save(record)
    ledger = copy.deepcopy(record['review_ledger'])
    result = tasks.submit(root, ref, prepared['review_session'], [], 'PARTIAL', ['Caller remains unread.'])
    assert result['result_saved'] and result['scan_status'] == 'SUCCESS'
    assert result['review_progress']['coverage'] == 'PARTIAL'
    saved = tasks.load(root, ref)
    assert saved['phase'] == 'COMPLETE' and saved['review_ledger'] == ledger
    assert 'Caller remains unread.' in saved['review']['limitations']
    assert saved['review_completion']['gaps'] and len(runtime.calls) == 1


def test_real_service_record_capacity_preflight_preserves_all_changes_and_history(service, monkeypatch):
    from security_runtime import task_security_state
    from security_runtime.closeout_state import encode
    tasks, root, runtime = service
    ref = tasks.begin(root, 'real-v3-record-capacity')['task_ref']
    for index in range(24):
        (root / f'unit_{index:02}.py').write_text(f'guard_{index} = policy.enforce(subject_{index})\n')
    tasks.finish(root, ref)
    before = tasks.load(root, ref)
    # Exercise the real signed-store bound with a small isolated-test capacity;
    # no large project, production setting, or real runtime file is modified.
    monkeypatch.setattr(task_security_state, 'MAX_RECORD_BYTES', len(encode(before)) + 6_000)
    result = tasks.prepare(root, ref, protocol_version=3)
    assert result['status'] == 'CAPACITY_REQUIRED' and not result['review_required']
    saved = tasks.load(root, ref)
    assert saved['review_capacity']['unit_count'] == 24
    assert saved['changes'] == before['changes'] and saved['baseline'] == before['baseline']
    assert saved['static'] == before['static'] and not saved.get('review_plan')
    assert not saved.get('review_ledger') and not saved.get('review_session')
    monkeypatch.setattr(plans, 'build_plan', lambda *a, **kw: pytest.fail('blocked plan was rebuilt'))
    assert tasks.prepare(root, ref, protocol_version=3) == result
    history = tasks.get(root, ref)
    assert history['status'] == 'CAPACITY_REQUIRED' and not history['review_required']
    assert history['review_capacity'] == saved['review_capacity']
    assert '未省略文件' in history['development_summary']
    with pytest.raises(ValueError):
        tasks.submit(root, ref, 'nonexistent-review-session', [], 'REVIEWED', [])
    assert len(runtime.calls) == 1

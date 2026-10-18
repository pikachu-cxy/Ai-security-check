"""Task service acceptance for immutable preimages and complete review plans.

The engine fixture records calls; these tests never invoke an installed scanner.
"""
import hashlib
import os
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.task_security import TaskSecurityService, TaskContextError
from security_runtime.task_ownership import session_owner
from test_task_security import LedgerRuntime, service  # noqa: F401; shared fixture


from task_review_helpers import read_plan, read_window, review_all


def review_units(s, root, ref, session, units):
    for unit in units:
        for window in unit['required_windows']:
            read_window(s, root, ref, session, window)
        s.submit_batch(root, ref, session, [unit['unit_id']], 'REVIEWED', [])


def assert_reviewed(s, root, ref, packet):
    receipt = s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE' and receipt['result_saved'] is True
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert result['host_review']['limitations']['total_count'] == 0
    return result


def test_refused_extra_critical_window_remains_an_explicit_unread_gap(service):
    s, root, _ = service
    source = ''.join(f'item_{i} = policy.allow(subject_{i})\n' for i in range(100))
    (root/'routes.py').write_text(source)
    ref = s.begin(root, 'explicit-critical-gap')['task_ref']
    (root/'routes.py').write_text(source.replace('policy.allow(subject_5)', 'policy.enforce(subject_5)'))
    packet = s.prepare(root, ref, protocol_version=3)
    review_all(s, root, ref, packet)
    record = s.load(root, ref)
    ledger = record['review_ledger']
    ledger['source_bytes'] = ledger['category_limits']['source']
    s.store(root).save(record)
    with pytest.raises(TaskContextError) as rejected:
        s.read(root, ref, packet['review_session'], 'routes.py', 90, 92)
    assert rejected.value.reason_code == 'TASK_CONTEXT_SOURCE_BUDGET'
    receipt = s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['result_saved'] is True
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert 'routes.py:90-92' in ' '.join(result['host_review']['limitations']['items'])


def test_unrelated_long_line_does_not_poison_a_completed_hunk_review(service):
    s, root, _ = service
    source = 'wide = '+ '1 + '*200+'1\n'+''.join(f'item_{i} = policy.allow(subject_{i})\n' for i in range(100))
    (root/'routes.py').write_text(source)
    ref = s.begin(root, 'only-requested-long-lines')['task_ref']
    (root/'routes.py').write_text(source.replace('policy.allow(subject_55)', 'policy.enforce(subject_55)'))
    packet = s.prepare(root, ref, protocol_version=3)
    delivered, _ = review_all(s, root, ref, packet)
    assert all(page['start_line'] > 1 for page in delivered)
    assert_reviewed(s, root, ref, packet)


def test_fully_masked_long_comment_is_not_a_character_truncation_gap(service):
    s, root, _ = service
    ref = s.begin(root, 'masked-comment-is-complete')['task_ref']
    (root/'added.py').write_text('# '+ 'context '*100+'\ndef allowed(user):\n    return auth.check(user)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    review_all(s, root, ref, packet)
    assert_reviewed(s, root, ref, packet)


def test_719_file_project_reviews_all_fourteen_changes_without_old_preimage_ceiling(service):
    s, root, runtime = service
    # The shared fixture supplies three files. These 716 make the actual task
    # inventory 719; the final fourteen bodies exceed the old 512KB collectively.
    (root/'bulk').mkdir()
    large = ''.join(f'guard_{i:04} = policy.allow(subject_{i:04})\n' for i in range(960))
    affected = []
    for i in range(716):
        path = root/'bulk'/f'file_{i:03}.py'
        path.write_text(large if i >= 702 else 'allowed = policy.allow(subject)\n', encoding='utf-8')
        if i >= 702:
            affected.append(path)
    ref = s.begin(root, 'large-719-14')['task_ref']
    before = s.load(root, ref)['baseline']
    assert len(before['hashes']) == 719
    assert not before['texts']
    assert len(before['preimages']) == 719
    assert sum(value['body_bytes'] for value in before['preimages'].values()) > 512_000
    for path in affected:
        path.write_text(large.replace('policy.allow(subject_0480)',
                                      'policy.enforce(subject_0480)'), encoding='utf-8')
    assert s.finish(root, ref)['status'] == 'READY'
    packet = s.prepare(root, ref, protocol_version=3)
    assert packet['protocol_version'] == 3
    assert packet['changed_file_count'] == 14
    assert packet['plan']['unit_count'] == 14
    assert 'content' not in packet['quick_skill']
    delivered, units = review_all(s, root, ref, packet)
    assert len(units) == 14
    assert {unit['path'] for unit in units} == {p.relative_to(root).as_posix() for p in affected}
    assert {p['location_version'] for p in s.load(root, ref)['evidence'].values()} == {'BEFORE_TASK', 'CURRENT_TASK_END'}
    assert_reviewed(s, root, ref, packet)
    record = s.load(root, ref)
    assert record['static_attempts'] == 1
    assert len(runtime.calls) == 1 and len(runtime.calls[0]) == 14
    assert record['review_ledger']['total_bytes'] <= record['review_ledger']['limits']['total_bytes']


def test_an_unrequested_second_plan_page_prevents_a_full_review_claim(service):
    s, root, runtime = service
    for i in range(6):
        (root/f'changed_{i}.py').write_text('def check(subject):\n    return policy.allow(subject)\n')
    ref = s.begin(root, 'all-units-required')['task_ref']
    for i in range(6):
        (root/f'changed_{i}.py').write_text('def check(subject):\n    return policy.enforce(subject)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(s, root, ref, packet)
    assert len(units) == 6
    review_units(s, root, ref, packet['review_session'], units[:5])
    # The last unit was never navigated to or requested. Runtime still owns
    # the fixed complete plan and must not equate first-page completion to all.
    receipt = s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['result_saved'] is True
    result = s.get(root, ref)
    assert result['host_review']['coverage'] == 'PARTIAL'
    assert result['host_review']['limitations']
    record = s.load(root, ref)
    pending = [unit for unit in record['review_plan']['units'] if unit['submitted_at'] is None]
    assert len(pending) == 1 and pending[0]['path'] == 'changed_5.py'
    assert len(runtime.calls) == 1


def test_read_pagination_can_be_completed_without_a_permanent_false_missing_gap(service):
    s, root, runtime = service
    ref = s.begin(root, 'finish-issued-pages')['task_ref']
    (root/'added.py').write_text(''.join(f'guard_{i:03} = policy.check(item_{i:03})\n' for i in range(190)))
    packet = s.prepare(root, ref, protocol_version=3)
    session = packet['review_session']
    units, _ = read_plan(s, root, ref, packet)
    unit = units[0]
    window = unit['required_windows'][0]
    first = s.read(root, ref, session, 'added.py', 1, 80, source_version='CURRENT')
    assert first['start_line'] == 1 and len(first['lines']) == 80
    partial = s.submit_batch(root, ref, session, [unit['unit_id']], 'REVIEWED', [])
    assert partial['coverage'] == 'PARTIAL'
    read_window(s, root, ref, session, dict(window, start_line=81))
    completed = s.submit_batch(root, ref, session, [unit['unit_id']], 'REVIEWED', [])
    assert completed['coverage'] == 'REVIEWED'
    assert window['end_line'] == 190
    assert_reviewed(s, root, ref, packet)
    assert len(runtime.calls) == 1


def test_same_length_external_edit_with_restored_mtime_invalidates_final_submission(service):
    s, root, runtime = service
    ref = s.begin(root, 'external-edit-freshness')['task_ref']
    source = root/'routes.py'
    source.write_bytes(b'def route(user):\n    return auth.check(user)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    review_all(s, root, ref, packet)
    before = source.stat()
    source.write_bytes(b'def route(user):\n    return auth.deny_(user)\n')
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert source.stat().st_size == before.st_size
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    with pytest.raises(ValueError, match='stale|changed'):
        s.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('kind', ['dirty', 'staged', 'untracked', 'non_git'])
def test_actual_before_version_survives_existing_user_changes_and_non_git(tmp_path, kind):
    root = tmp_path/'project'
    root.mkdir()
    (root/'routes.py').write_text('def route(subject):\n    return policy.committed(subject)\n')
    if kind != 'non_git':
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        subprocess.run(['git', '-C', str(root), 'add', 'routes.py'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture',
            '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
    name = 'new.py' if kind == 'untracked' else 'routes.py'
    source = root/name
    initial = f'def route(subject):\n    return policy.preexisting_{kind}(subject)\n'
    source.write_text(initial)
    if kind == 'staged':
        subprocess.run(['git', '-C', str(root), 'add', name], check=True)
    runtime = LedgerRuntime()
    s = TaskSecurityService(runtime, HookStateStore(tmp_path/'state'))
    ref = s.begin(root, f'before-{kind}')['task_ref']
    source.write_text('def route(subject):\n    return policy.updated(subject)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    assert packet['plan']['unit_count'] == 1
    assert packet['plan']['units'][0]['change'] == 'MODIFIED'
    delivered, _ = review_all(s, root, ref, packet)
    sources = s.load(root, ref)['review_plan']['sources']
    previous = '\n'.join(line for item in delivered if sources[item['source_ref']]['location_version']=='BEFORE_TASK'
                         for line in item['lines'])
    current = '\n'.join(line for item in delivered if sources[item['source_ref']]['location_version']=='CURRENT_TASK_END'
                        for line in item['lines'])
    assert f'preexisting_{kind}' in previous
    assert 'policy.committed' not in previous
    assert 'policy.updated' in current and f'preexisting_{kind}' not in current
    assert_reviewed(s, root, ref, packet)
    assert len(runtime.calls) == 1


def test_deleted_renamed_crlf_file_keeps_original_hash_and_before_pagination(service):
    s, root, runtime = service
    raw = ''.join(f'guard_{i:03} = policy.check(item_{i:03})\r\n' for i in range(190)).encode()
    old = root/'old_name.py'
    old.write_bytes(raw)
    ref = s.begin(root, 'delete-rename-crlf')['task_ref']
    old.rename(root/'new_name.py')
    packet = s.prepare(root, ref, protocol_version=3)
    delivered, units = review_all(s, root, ref, packet)
    assert {(unit['path'], unit['change']) for unit in units} == {
        ('old_name.py', 'DELETED'), ('new_name.py', 'ADDED')}
    sources = s.load(root, ref)['review_plan']['sources']
    prior = [p for p in delivered if sources[p['source_ref']]['location_version']=='BEFORE_DELETION']
    assert len(prior) >= 3
    assert all(sources[p['source_ref']]['path']=='old_name.py' and
               sources[p['source_ref']]['file_sha256']==hashlib.sha256(raw).hexdigest() for p in prior)
    assert sum(len(p['lines']) for p in prior) == 190
    assert_reviewed(s, root, ref, packet)
    assert len(runtime.calls) == 1


def test_reconnect_same_owner_keeps_plan_evidence_and_cumulative_budgets(service):
    s, root, runtime = service
    owner = session_owner('codex', 'same-review-conversation')
    s.owner = owner
    ref = s.begin(root, 'resume-review-v3')['task_ref']
    (root/'routes.py').write_text('def route(user):\n    return policy.enforce(user)\n')
    packet = s.prepare(root, ref, protocol_version=3)
    units, _ = read_plan(s, root, ref, packet)
    read_window(s, root, ref, packet['review_session'], units[0]['required_windows'][0])
    before = s.load(root, ref)
    restarted = TaskSecurityService(runtime, s.hooks, owner=dict(owner))
    resumed = restarted.prepare(root, ref, protocol_version=3)
    after = restarted.load(root, ref)
    assert resumed['review_session'] == packet['review_session']
    assert resumed['plan']['plan_id'] == packet['plan']['plan_id']
    assert after['review_deadline'] == before['review_deadline']
    assert after['review_ledger']['reads'] == before['review_ledger']['reads']
    assert after['review_ledger']['source_bytes'] == before['review_ledger']['source_bytes']
    assert after['review_ledger']['total_bytes'] > before['review_ledger']['total_bytes']
    assert after['evidence'] == before['evidence']
    assert restarted.begin(root, 'resume-review-v3')['task_ref'] == ref
    outsider = TaskSecurityService(runtime, s.hooks, owner=session_owner('codex', 'other-conversation'))
    with pytest.raises(ValueError, match='another session'):
        outsider.review_plan(root, ref, packet['review_session'])
    review_all(restarted, root, ref, resumed)
    assert_reviewed(restarted, root, ref, resumed)
    assert len(runtime.calls) == 1

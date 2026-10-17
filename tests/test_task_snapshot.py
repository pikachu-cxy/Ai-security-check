"""Before-edit collection is bounded by work, never a machine-speed cutoff."""
import json
import time

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.local_evidence import EvidenceUnavailable, WorkspaceReader, safe_source
from security_runtime import task_preimages
from security_runtime.task_preimages import TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.task_snapshot import SnapshotPolicy, collect_snapshot


REF = 'ts1-'+'a'*32


def project(tmp_path, count=3):
    root = tmp_path/'source'
    root.mkdir()
    names = [f'module_{index:04}.py' for index in range(count)]
    for name in names:
        (root/name).write_text('value = auth.check(user)\n', encoding='utf-8')
    return root, names


def private_store(tmp_path, root):
    hooks = HookStateStore(tmp_path/'private-state')
    hooks.key(root)
    return TaskPreimageStore(hooks, root)


def test_slow_768_file_preparation_retains_complete_before_edit_evidence(tmp_path, monkeypatch):
    root, names = project(tmp_path, 768)
    store = private_store(tmp_path, root)
    elapsed = [0.0]
    original = task_preimages.safe_source

    def slow_source(text, **kwargs):
        elapsed[0] += .1
        return original(text, **kwargs)

    monkeypatch.setattr(task_preimages, 'safe_source', slow_source)
    monkeypatch.setattr(time, 'monotonic', lambda: elapsed[0])
    with store.writer(REF) as writer:
        snapshot = collect_snapshot(root, inventory=names, preimage_writer=writer)
    stats = snapshot['capture_stats']
    assert elapsed[0] > 5
    assert stats['hash_complete'] and stats['body_complete']
    assert stats['hashed_file_count'] == stats['saved_body_file_count'] == 768
    assert not snapshot['limitations'] and stats['pending_hash_file_count'] == 0
    last = names[-1]
    reference = snapshot['preimages'][last]
    before = store.read(REF, last, snapshot['hashes'][last], reference)
    (root/last).write_text('changed_after_baseline = True\n', encoding='utf-8')
    assert store.read(REF, last, snapshot['hashes'][last], reference) == before


def test_file_capacity_keeps_priority_and_exact_unread_count(tmp_path):
    root, names = project(tmp_path, 4)
    snapshot = collect_snapshot(root, inventory=names, priority_paths=[names[-1]],
                                policy=SnapshotPolicy(max_files=2))
    assert list(snapshot['hashes']) == [names[-1], names[0]]
    assert snapshot['inventory'] == names and snapshot['inventory_complete']
    assert snapshot['limitations'] == [dict(reason='SNAPSHOT_READ_FILE_BUDGET',
                                           limit=2, used=2, pending_count=2)]
    assert snapshot['capture_stats']['pending_hash_file_count'] == 2
    assert snapshot['capture_stats']['pending_body_file_count'] == 2
    assert not snapshot['capture_stats']['hash_complete']


def test_read_bytes_are_finite_and_report_budget_separately_from_file_size(tmp_path):
    root, names = project(tmp_path, 3)
    cost = (root/names[0]).stat().st_size
    snapshot = collect_snapshot(root, inventory=names,
                                policy=SnapshotPolicy(max_read_bytes=cost))
    assert snapshot['capture_stats']['accepted_source_bytes'] == cost
    assert snapshot['limitations'] == [dict(reason='SNAPSHOT_READ_BYTE_BUDGET',
                                           limit=cost, used=cost, pending_count=2)]
    assert len(snapshot['hashes']) == 1


def test_failed_read_reservation_is_not_reset_to_grant_unlimited_work(tmp_path):
    root, names = project(tmp_path, 3)
    calls = []

    class RejectedReader:
        def __init__(self, root):
            pass

        def read(self, name, maximum):
            calls.append((name, maximum))
            raise EvidenceUnavailable('DECODE_FAILED_UTF8')

    snapshot = collect_snapshot(root, inventory=names, reader_factory=RejectedReader,
                                policy=SnapshotPolicy(max_read_bytes=100))
    assert calls == [(names[0], 100)]
    assert snapshot['capture_stats']['failed_read_reserved_bytes'] == 100
    assert snapshot['capture_stats']['pending_hash_file_count'] == 3
    assert [item['reason'] for item in snapshot['limitations']] == [
        'DECODE_FAILED_UTF8', 'SNAPSHOT_READ_BYTE_BUDGET']


def test_remaining_aggregate_bytes_are_not_misreported_as_oversized_source(tmp_path):
    root, names = project(tmp_path, 4)
    cost = (root/names[0]).stat().st_size
    snapshot = collect_snapshot(root, inventory=names,
        policy=SnapshotPolicy(max_files=2, max_read_bytes=cost+1))
    assert len(snapshot['hashes']) == 1
    assert snapshot['capture_stats']['attempted_file_count'] == 2
    assert snapshot['capture_stats']['limitation_reason_counts'] == {'SNAPSHOT_READ_BYTE_BUDGET':1}
    assert snapshot['limitations'][0]['pending_count'] == 3


def test_inline_body_quota_does_not_claim_hash_failure_or_full_before_body(tmp_path):
    root, names = project(tmp_path)
    snapshot = collect_snapshot(root, inventory=names,
                                policy=SnapshotPolicy(max_inline_text_bytes=1))
    stats = snapshot['capture_stats']
    assert stats['hash_complete'] and not stats['body_complete']
    assert stats['pending_hash_file_count'] == 0 and stats['pending_body_file_count'] == 3
    assert stats['limitation_reason_counts'] == {'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET':3}
    assert not snapshot['read_limitations']
    assert all(value == 'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET'
               for value in snapshot['text_unavailable'].values())


def test_private_store_limits_are_reported_without_making_hash_coverage_fail(tmp_path, monkeypatch):
    root, names = project(tmp_path)
    store, policy = private_store(tmp_path, root), SnapshotPolicy()
    monkeypatch.setattr(task_preimages, 'MAX_TASK_BYTES', 1)
    with store.writer(REF) as writer:
        snapshot = collect_snapshot(root, inventory=names, preimage_writer=writer, policy=policy)
    assert snapshot['capture_stats']['hash_complete']
    assert not snapshot['capture_stats']['body_complete']
    assert snapshot['capture_stats']['limitation_reason_counts'] == {'TASK_PREIMAGE_TASK_BYTE_BUDGET':3}
    assert snapshot['capture_stats']['limits']['max_private_task_bytes'] == 1
    assert not snapshot['preimages']


def test_private_store_prepares_once_and_never_persists_raw_literals(tmp_path, monkeypatch):
    root, names = project(tmp_path, 1)
    (root/names[0]).write_text("password = 'private-canary-secret'\nvalue = 'business-data'\n", encoding='utf-8')
    store = private_store(tmp_path, root)
    original, calls = task_preimages.safe_source, []

    def checked_source(text, **kwargs):
        calls.append(text)
        return original(text, **kwargs)

    monkeypatch.setattr(task_preimages, 'safe_source', checked_source)
    with store.writer(REF) as writer:
        snapshot = collect_snapshot(root, inventory=names, preimage_writer=writer,
            sanitizer=lambda *args, **kwargs: pytest.fail('Store owns preparation'))
    assert len(calls) == 1
    assert snapshot['capture_stats']['body_complete']
    assert b'private-canary-secret' not in store.path.read_bytes()
    assert 'private-canary-secret' not in json.dumps(snapshot)
    assert b'business-data' not in store.path.read_bytes()


def test_body_preparation_new_entry_keeps_closed_writer_and_source_guards(tmp_path):
    root, _ = project(tmp_path, 1)
    store = private_store(tmp_path, root)
    with store.writer(REF) as writer:
        for name, raw in [('../escape.py', b'value = 1'), ('module.py', b'\0binary'),
                          ('.env', b'SECRET=private')]:
            with pytest.raises(TaskPreimageUnavailable):
                writer.put_source(name, raw)
    with pytest.raises(TaskPreimageUnavailable, match='TASK_PREIMAGE_WRITER_CLOSED'):
        writer.put_source('module.py', b'value = 1')


def test_environment_hash_is_retained_without_body_or_false_body_gap(tmp_path):
    root, names = project(tmp_path, 1)
    (root/'.env').write_text('SECRET=private-canary\n', encoding='utf-8')
    snapshot = collect_snapshot(root, inventory=[*names,'.env'])
    assert '.env' in snapshot['hashes'] and '.env' not in snapshot['texts']
    assert snapshot['capture_stats']['expected_body_file_count'] == 1
    assert snapshot['capture_stats']['body_complete']
    assert 'private-canary' not in json.dumps(snapshot)


def test_full_limitation_counts_survive_bounded_navigation_list(tmp_path):
    root, names = project(tmp_path, 105)
    snapshot = collect_snapshot(root, inventory=names,
                                policy=SnapshotPolicy(max_inline_text_bytes=1))
    assert len(snapshot['limitations']) == 100
    assert snapshot['capture_stats']['limitation_count'] == 105
    assert snapshot['capture_stats']['limitation_omitted_count'] == 5
    assert snapshot['capture_stats']['limitation_reason_counts'] == {'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET':105}


def test_inventory_limit_preserves_missing_hash_and_body_denominators(tmp_path):
    root, names = project(tmp_path, 4)
    snapshot = collect_snapshot(root, inventory=names,
                                policy=SnapshotPolicy(max_inventory_paths=2))
    stats = snapshot['capture_stats']
    assert not snapshot['inventory_complete']
    assert stats['inventory_file_count'] == 4 and stats['selected_inventory_file_count'] == 2
    assert stats['pending_hash_file_count'] == stats['pending_body_file_count'] == 2
    assert not stats['hash_complete'] and not stats['body_complete']
    assert snapshot['limitations'][0]['reason'] == 'SNAPSHOT_INVENTORY_FILE_BUDGET'


@pytest.mark.parametrize('overrides', [dict(max_files=True), dict(max_files=1001),
    dict(max_read_bytes=20_000_001), dict(max_inline_text_bytes=512_001),
    dict(max_inventory_paths=0), dict(max_inventory_depth=13)])
def test_policy_cannot_exceed_supported_storage_or_accept_invalid_limits(overrides):
    with pytest.raises(ValueError, match='Invalid task snapshot capacity'):
        SnapshotPolicy(**overrides)

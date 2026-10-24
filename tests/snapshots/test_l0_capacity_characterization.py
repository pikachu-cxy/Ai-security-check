"""Characterize existing capacity gaps without invoking scanners or changing limits."""
import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.preimages import TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.tasks.snapshot import collect_snapshot


RAW = b'value = auth.check(uid)\n'
TASK_REF = 'ts1-' + 'a' * 32


@pytest.fixture
def project_1001(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    names = [f'module_{index:04d}.py' for index in range(1001)]
    for name in names:
        (root / name).write_bytes(RAW)
    return root, names


@pytest.mark.parametrize('prioritize_last', [False, True])
def test_default_capture_leaves_one_of_1001_files_unread(project_1001, prioritize_last):
    root, names = project_1001
    snapshot = collect_snapshot(root, inventory=names,
                                priority_paths=[names[-1]] if prioritize_last else ())
    stats = snapshot['capture_stats']

    assert snapshot['inventory'] == names and snapshot['inventory_complete']
    assert stats['inventory_file_count'] == stats['expected_body_file_count'] == 1001
    assert stats['attempted_file_count'] == stats['hashed_file_count'] == 1000
    assert stats['saved_body_file_count'] == 1000
    assert stats['pending_hash_file_count'] == stats['pending_body_file_count'] == 1
    assert not stats['hash_complete'] and not stats['body_complete']
    assert snapshot['limitations'] == snapshot['read_limitations'] == [
        dict(reason='SNAPSHOT_READ_FILE_BUDGET', limit=1000, used=1000, pending_count=1)
    ]

    # The same final file is readable when prioritized: the gap is a prefix cap.
    missing = names[-2] if prioritize_last else names[-1]
    assert set(names) - set(snapshot['hashes']) == {missing}
    assert set(names) - set(snapshot['texts']) == {missing}
    if prioritize_last:
        assert snapshot['read_priority'][0] == names[-1]
        assert snapshot['texts'][names[-1]] == [RAW.decode().rstrip('\n')]


def test_private_writer_independently_rejects_1001st_file(project_1001, tmp_path):
    root, names = project_1001
    hooks = HookStateStore(tmp_path / 'private-state')
    hooks.key(root)
    store = TaskPreimageStore(hooks, root)

    with store.writer(TASK_REF) as writer:
        for name in names[:-1]:
            reference = writer.put_source(name, RAW)['reference']
        with pytest.raises(TaskPreimageUnavailable) as error:
            writer.put_source(names[-1], RAW)
        assert error.value.reason_code == 'TASK_PREIMAGE_FILE_COUNT_BUDGET'
        assert len(writer.references) == 1000
        assert names[-1] not in writer.references

    assert store.read(TASK_REF, names[-2], reference['raw_sha256'], reference) == [
        RAW.decode().rstrip('\n')
    ]

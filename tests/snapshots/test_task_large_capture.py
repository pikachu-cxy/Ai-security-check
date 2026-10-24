"""Real task admission/closeout across the former 1000-file boundary."""
import json
import sqlite3
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import LedgerRuntime


def large_service(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
    for index in range(1001):
        (root/f'file_{index:04}.py').write_text(f'value = {index}\n')
    service = TaskSecurityService(LedgerRuntime(), HookStateStore(tmp_path/'state'),
                                  owner=session_owner('codex', 'large-task'))
    return root, service


def test_new_task_captures_all_1001_files_and_reopens_immutable_pages(tmp_path):
    root, service = large_service(tmp_path)
    result = service.begin(root, 'large', check_policy=POLICY)
    ref = result['task_ref']
    record = service.load(root, ref)
    assert record['capture_policy'] == 'BATCHED_FILES_GC_V1'
    stats = record['baseline']['capture_stats']
    assert stats['hashed_file_count'] == stats['saved_body_file_count'] == 1001
    assert stats['hash_complete'] and stats['body_complete']
    assert not record['baseline']['limitations']
    (root/'file_1000.py').write_text('value = 99999\n')
    (root/'file_0000.py').unlink()
    (root/'new.py').write_text('new_value = 1\n')
    assert service.before_lines(root, record, 'file_1000.py') == ['value = 1000']
    out = service.finish(root, ref)
    assert out['status'] == 'READY'
    final = service.load(root, ref)
    assert {(c['path'], c['change']) for c in final['changes']} == {
        ('file_0000.py', 'DELETED'), ('file_1000.py', 'MODIFIED'), ('new.py', 'ADDED')}
    assert service.end_lines(root, final, 'file_1000.py') == ['value = 99999']
    assert service.before_lines(root, final, 'file_1000.py') == ['value = 1000']
    assert service.get(root, ref)['current_version']
    # Control JSON stores references instead of 1001 per-file maps.
    with sqlite3.connect(service.store(root).path) as db:
        stored = json.loads(db.execute('SELECT data FROM security_tasks WHERE ref=?', (ref,)).fetchone()[0])
    for field in ('baseline', 'end'):
        assert 'paged_entries' in stored[field]
        assert 'hashes' not in stored[field] and 'preimages' not in stored[field]


def test_unsealed_checkpoint_is_never_read_as_original_evidence(tmp_path):
    root = tmp_path/'source'
    root.mkdir()
    hooks = HookStateStore(tmp_path/'state')
    hooks.key(root)
    store = TaskPreimageStore(hooks, root, namespace='closeout')
    ref = 'ts1-'+'d'*32
    with pytest.raises(RuntimeError):
        with store.writer(ref, paged=True) as writer:
            evidence = writer.put_source('a.py', b'old = 1\n')['reference']
            writer.checkpoint()
            with pytest.raises(TaskPreimageUnavailable):
                store.read(ref, 'a.py', evidence['raw_sha256'], evidence)
            raise RuntimeError('interrupted after committed page')
    with pytest.raises(TaskPreimageUnavailable):
        store.read(ref, 'a.py', evidence['raw_sha256'], evidence)
    with pytest.raises(TaskPreimageUnavailable, match='TASK_PREIMAGE_TASK_ALREADY_CAPTURED'):
        with store.writer(ref, paged=True):
            pass

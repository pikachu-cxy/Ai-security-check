"""Partial captures and retained risk facts never regain source authority."""
import copy
import json
import sqlite3

import pytest

from security_runtime.closeout_state import encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotStore
from security_runtime.tasks.activity import IDLE_TTL, POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import (
    CONTRACT as LEGACY_PREIMAGE_CONTRACT, PAGED_CONTRACT,
    TaskPreimageStore, TaskPreimageUnavailable,
)
from security_runtime.tasks.projection import _basis, enqueue, reconcile_pending
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import CONTRACT, MAX_RECORD_BYTES, TaskSecurityStore


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail('Retention and rejected admission must not invoke scanners')


def source_and_hooks(tmp_path):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    hooks = HookStateStore(tmp_path.resolve() / 'private-state')
    hooks.key(root)
    return root, hooks


@pytest.mark.parametrize('defect', ['missing_row', 'missing_table', 'wrong_mac'])
@pytest.mark.parametrize('sealed', [False, True])
def test_paged_reference_requires_original_valid_seal(tmp_path, defect, sealed):
    root, hooks = source_and_hooks(tmp_path)
    store = TaskPreimageStore(hooks, root, namespace='closeout')
    ref = 'ts1-' + 'a' * 32

    def write_page():
        with store.writer(ref, paged=True) as writer:
            evidence = writer.put_source('original.py', b'value = 1\n')['reference']
            writer.checkpoint()
            if not sealed:
                raise RuntimeError(evidence)
            return evidence

    if sealed:
        evidence = write_page()
        assert store.read(ref, 'original.py', evidence['raw_sha256'], evidence) == ['value = 1']
    else:
        with pytest.raises(RuntimeError) as interrupted:
            write_page()
        evidence = interrupted.value.args[0]
    assert evidence['contract'] == PAGED_CONTRACT

    with sqlite3.connect(store.path) as db:
        if defect == 'missing_row':
            db.execute('DELETE FROM task_preimage_seals WHERE task_ref=?', (ref,))
        elif defect == 'missing_table':
            db.execute('DROP TABLE task_preimage_seals')
        else:
            db.execute('UPDATE task_preimage_seals SET sealed=1,mac=? WHERE task_ref=?', ('0' * 64, ref))
    with pytest.raises(TaskPreimageUnavailable, match='^TASK_PREIMAGE_SOURCE_UNAVAILABLE$'):
        store.read(ref, 'original.py', evidence['raw_sha256'], evidence)
    # Missing seal data never grants permission to restart an old capture.
    with pytest.raises(TaskPreimageUnavailable, match='^TASK_PREIMAGE_TASK_ALREADY_CAPTURED$'):
        with store.writer(ref, paged=True):
            pytest.fail('Original paged capture must not restart')


def test_legacy_reference_remains_readable_without_paged_seal(tmp_path):
    root, hooks = source_and_hooks(tmp_path)
    store = TaskPreimageStore(hooks, root, namespace='closeout')
    ref = 'ts1-' + 'b' * 32
    with store.writer(ref) as writer:
        evidence = writer.put_source('legacy.py', b'value = 1\n')['reference']
    assert evidence['contract'] == LEGACY_PREIMAGE_CONTRACT
    assert store.read(ref, 'legacy.py', evidence['raw_sha256'], evidence) == ['value = 1']


def test_closeout_without_owner_is_rejected_before_source_capture(tmp_path, monkeypatch):
    root, hooks = source_and_hooks(tmp_path)
    service = TaskSecurityService(NoScanner(), hooks)
    monkeypatch.setattr('security_runtime.tasks.security.capture',
                        lambda *args, **kwargs: pytest.fail('Owner rejection must precede source capture'))
    with pytest.raises(ValueError, match='^Closeout tasks require an explicit owner$'):
        service.begin(root, 'unowned', check_policy=POLICY)
    directory = hooks.workspace_directory(root)
    assert not (directory / 'task-closeout-preimages.db').exists()
    assert not (directory / 'snapshot-pages').exists()


def test_expired_paged_projection_stays_small_and_recovers_without_pages(tmp_path, monkeypatch):
    root, hooks = source_and_hooks(tmp_path)
    clock = [1_000_000.0]
    owner = session_owner('codex', 'paged-retention')
    service = TaskSecurityService(NoScanner(), hooks, now=lambda: clock[0], owner=owner)
    store = TaskSecurityStore(hooks, root, now=lambda: clock[0])
    names = [f'module_{index:04d}.py' for index in range(550)]
    hashes = {name: 'a' * 64 for name in names}
    snapshot = dict(hashes=hashes, inventory=names, read_priority=names,
                    texts={name: ['private-captured-body:' + 'x' * 8000] for name in names},
                    preimages={}, line_counts={name: 1 for name in names},
                    text_unavailable={}, text_truncations={}, limitations=[],
                    read_limitations=[], inventory_complete=True, redaction_version=3)
    ref = 'ts1-' + 'c' * 32
    finding = dict(id='fixture-risk', title='Retained risk', category='authorization',
                   file_path=names[-1])
    original = dict(contract=CONTRACT, task_ref=ref, task_key='original', workspace=str(root),
                    generation=0, created_at=clock[0], phase='READY', review_protocol=3,
                    task_owner=owner, check_policy=POLICY, capture_policy='BATCHED_FILES_V1',
                    baseline=copy.deepcopy(snapshot), end=copy.deepcopy(snapshot),
                    static=dict(scan_id='fixture-scan', findings=[finding]))
    original = enqueue(original)
    assert len(encode(original)) > MAX_RECORD_BYTES
    saved = store.save(original, new=True)
    expected_basis = _basis(saved)
    expected_projection = copy.deepcopy(saved['ledger_projection'])

    clock[0] += IDLE_TTL + 1
    later = dict(contract=CONTRACT, task_ref='ts1-' + 'd' * 32, task_key='later',
                 workspace=str(root), generation=0, created_at=clock[0], phase='ACTIVE',
                 review_protocol=3, task_owner=owner, baseline=dict(hashes={}, texts={}))
    store.save(later, new=True)
    assert store.get(ref) is None
    with sqlite3.connect(store.path) as db:
        retained_raw = db.execute('SELECT data FROM retained_task_projections WHERE ref=?', (ref,)).fetchone()[0]
    assert len(retained_raw.encode()) < 100_000
    assert 'private-captured-body:' not in retained_raw
    assert 'paged_entries' not in retained_raw
    raw_value = json.loads(retained_raw)
    assert raw_value['end']['hashes'] == hashes

    # Expired risk facts have all authority they need; source pages may be gone.
    with monkeypatch.context() as guarded:
        for method in ('resume', 'page', 'read_content'):
            guarded.setattr(SnapshotStore, method,
                            lambda *args, **kwargs: pytest.fail('Retained risk facts must not reopen source pages'))
        retained = store.pending_projections()
        assert len(retained) == 1
        assert retained[0]['ledger_projection'] == expected_projection
        assert _basis(retained[0]) == expected_basis
        with hooks.lock(root) as acquired:
            assert acquired
            result = reconcile_pending(service, root)
        assert result == dict(applied=1, pending=0, foreign=0,
                              scanner_run=False, repair_authorized=False)
        assert store.pending_projections() == []
        rows = TaskRiskLedger(hooks, root).read(ref)
        assert rows[ref + ':fixture-risk']['original_hashes'] == {names[-1]: hashes[names[-1]]}

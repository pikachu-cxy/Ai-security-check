"""Expired pending projection metadata survives without reviving task/source TTL."""
import copy

from security_runtime.tasks.projection import reconcile_pending
from security_runtime.tasks.security_state import TTL
from test_task_projection_recovery import pending_static
from test_task_security import service  # noqa: F401


def test_task_ttl_archives_pending_facts_and_recovery_never_rescans(service, monkeypatch):
    tasks, root, runtime = service
    ref, baseline = pending_static(service)
    original = tasks.load(root, ref)
    monkeypatch.setattr(tasks, 'now', lambda: original['created_at']+TTL+1)
    next_ref = tasks.begin(root, 'later-work')['task_ref']
    store = tasks.store(root)
    assert store.get(ref) is None
    retained = store.pending_projections()
    assert len(retained) == 1 and retained[0]['task_ref'] == ref
    assert retained[0]['baseline']['hashes'] == baseline['hashes']
    assert retained[0]['ledger_projection'] == original['ledger_projection']
    assert retained[0].get('review_ledger') == original.get('review_ledger')
    for version in ('baseline', 'end'):
        assert not {'texts', 'semantic_proofs', 'text_truncations'} & retained[0][version].keys()
    next_task = copy.deepcopy(store.get(next_ref))
    with tasks.hooks.lock(root) as acquired:
        assert acquired
        result = reconcile_pending(tasks, root)
    assert result == dict(applied=1, pending=0, foreign=0, scanner_run=False, repair_authorized=False)
    assert store.pending_projections() == []
    assert store.get(ref) is None and store.get(next_ref) == next_task
    assert len(runtime.calls) == 1

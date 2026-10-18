"""A durable user decision releases only its exact captured workflow version."""
import copy

import pytest

from security_runtime.risk_disposition import RiskDispositionStore
from security_runtime.native_repair_intent import NativeRepairIntents
from security_runtime.repair_impact_models import RepairImpactError
from test_native_repair_intent import sample, ready, SOURCE, OWNER  # noqa: F401


def decisions(sample):
    tasks, intents, root, _ = sample
    return RiskDispositionStore(tasks.hooks.workspace_directory(root)/'risk-dispositions.db')


def pause(sample, request_id='pause-once'):
    _, intents, root, _ = sample
    store = decisions(sample)
    template = intents.release_effect(SOURCE)
    store.set(root,'selected-risk','DEFER',user_requested=True,request_id=request_id,
              effects=[template] if template else [])
    return store


def test_target_failure_retains_choice_and_intent_then_reconnect_recovers(sample, monkeypatch):
    _, intents, root, _ = sample
    ready(sample)
    store = pause(sample)
    original = NativeRepairIntents.apply_release
    monkeypatch.setattr(NativeRepairIntents,'apply_release',lambda *a: (_ for _ in ()).throw(OSError('target unavailable')))
    assert intents.drain_releases(store)['status'] == 'PENDING'
    assert store.status(root,'selected-risk')['active']
    assert intents.get()['status'] == 'READY'
    assert len(store.pending_effects(root)) == 1
    monkeypatch.setattr(NativeRepairIntents,'apply_release',original)
    reconnected = NativeRepairIntents(intents.hooks,root,OWNER,now=intents.now)
    assert reconnected.drain_releases(store)['applied'] == 1
    assert reconnected.get()['status'] == 'CANCELLED' and store.pending_effects(root) == []
    assert store.status(root,'selected-risk')['repair_authorized'] is False


def test_late_release_cannot_cancel_newer_preparation_or_foreign_owner(sample):
    _, intents, root, preparation = sample
    ready(sample)
    store = pause(sample)
    later = copy.deepcopy(preparation)
    later['revision'] += 1
    intents.ready(later)
    assert intents.drain_releases(store)['superseded'] == 1
    assert intents.get()['status'] == 'READY' and intents.get()['preparation'] == later
    newer_store = pause(sample,request_id='second-pause')
    other = NativeRepairIntents(intents.hooks,root,dict(host='codex',session='d'*64))
    assert other.drain_releases(newer_store)['foreign'] == 1
    with pytest.raises(RepairImpactError,match='OWNER_MISMATCH'):
        other.apply_release(newer_store.pending_effects(root)[0])
    assert intents.get()['status'] == 'READY'


def test_ack_failure_uses_target_inbox_and_never_cancels_newer_request(sample, monkeypatch):
    _, intents, root, _ = sample
    ready(sample)
    store = pause(sample)
    original = store.acknowledge_effect
    monkeypatch.setattr(store,'acknowledge_effect',lambda *a,**k: (_ for _ in ()).throw(OSError('source ack failed')))
    assert intents.drain_releases(store)['status'] == 'PENDING'
    assert intents.get()['status'] == 'CANCELLED'
    intents.request(SOURCE,'ria1-'+'3'*32)
    newer = intents.get()
    monkeypatch.setattr(store,'acknowledge_effect',original)
    assert intents.drain_releases(store)['applied'] == 1
    assert intents.get() == newer and newer['status'] == 'WAITING'
    assert store.pending_effects(root) == []


def test_request_retry_never_retargets_old_decision_to_new_intent(sample):
    _, intents, root, _ = sample
    ready(sample)
    store = pause(sample)
    first = store.pending_effects(root)[0]
    intents.cancel()
    intents.request(SOURCE,'ria1-'+'3'*32)
    pause(sample)  # same request ID: original capture stays immutable.
    assert store.pending_effects(root) == [first]
    assert intents.drain_releases(store)['superseded'] == 1
    assert intents.get()['status'] == 'WAITING'


def test_unknown_captured_snapshot_stays_pending_and_cannot_cancel_later_intent(sample):
    _,intents,root,_ = sample
    ready(sample)
    store = decisions(sample)
    store.set(root,'selected-risk','EXCLUDE',user_requested=True,effects=[dict(
        kind='RELEASE_NATIVE_INTENT',payload=dict(owner=OWNER,source=SOURCE,intent_sha256=None))])
    before = intents.get()
    with pytest.raises(RepairImpactError,match='SNAPSHOT_UNAVAILABLE'):
        intents.apply_release(store.pending_effects(root)[0])
    assert store.status(root,'selected-risk')['active']
    assert intents.get() == before and len(store.pending_effects(root)) == 1


def test_foreign_and_unknown_pending_before_ready_owner_cannot_starve_recovery(sample):
    _,intents,root,_ = sample
    ready(sample)
    store = decisions(sample)
    other_owner = dict(host='codex',session='d'*64)
    for number in range(20):
        store.set(root,'foreign-'+str(number),'DEFER',user_requested=True,effects=[dict(
            kind='RELEASE_NATIVE_INTENT',payload=dict(owner=other_owner,source=SOURCE,intent_sha256='f'*64))])
        store.set(root,'unknown-'+str(number),'DEFER',user_requested=True,effects=[dict(
            kind='RELEASE_NATIVE_INTENT',payload=dict(owner=OWNER,source=SOURCE,intent_sha256=None))])
    pause(sample)
    result = intents.drain_releases(store)
    assert result['applied'] == 1 and result['pending'] == 20 and result['foreign'] == 20
    assert intents.get()['status'] == 'CANCELLED'
    assert store.pending_effect_count(root) == 40


def test_one_failed_owned_release_does_not_block_later_valid_owned_release(sample,monkeypatch):
    _,intents,root,preparation = sample
    ready(sample)
    store = pause(sample,request_id='first-pause')
    first_id = store.pending_effects(root)[0]['event_id']
    changed = copy.deepcopy(preparation)
    changed['revision'] += 1
    intents.ready(changed)
    pause(sample,request_id='second-pause')
    original = intents.apply_release
    def fail_first(effect):
        if effect['event_id'] == first_id: raise OSError('first target temporarily unavailable')
        return original(effect)
    monkeypatch.setattr(intents,'apply_release',fail_first)
    result = intents.drain_releases(store)
    assert result['applied'] == 1 and result['errors'] == result['pending'] == 1
    assert intents.get()['status'] == 'CANCELLED'
    assert store.pending_effects(root)[0]['event_id'] == first_id


@pytest.mark.parametrize('phase', ['read', 'count'])
def test_queue_query_failure_is_unknown_pending_without_grant_or_choice_loss(sample, monkeypatch, phase):
    import sqlite3
    _, intents, root, _ = sample
    ready(sample)
    store = pause(sample)
    before = intents.get()
    method = 'pending_effects' if phase == 'read' else 'pending_effect_count'
    original = getattr(store, method)
    def failed(*args, **kwargs):
        raise sqlite3.DatabaseError('private source details must not be echoed')
    monkeypatch.setattr(store, method, failed)
    result = intents.drain_releases(store)
    assert result['status'] == 'PENDING' and result['pending'] is None and result['foreign'] is None
    assert result['reason_code'] == 'NATIVE_RELEASE_QUEUE_UNAVAILABLE'
    assert result['errors'] == 1 and result['repair_authorized'] is False
    assert 'private source details' not in str(result)
    assert store.status(root, 'selected-risk')['active']
    if phase == 'read':
        assert intents.get() == before
    else:
        assert intents.get()['status'] == 'CANCELLED' and result['applied'] == 1
    monkeypatch.setattr(store, method, original)
    assert intents.drain_releases(store)['status'] == 'APPLIED'
    assert store.pending_effects(root) == []

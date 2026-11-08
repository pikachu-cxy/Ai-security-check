"""Incremental audit transitions; no scanner, clock sleeps, or file reads."""
import copy
import json
import pytest
from security_runtime import incremental_audit as audit


@pytest.fixture
def check():
    return dict(dirty_seq=1, observed_paths=['a.py'], effective_config={'values':{'agent':{'audit_business_logic':True}}})


def begin(check, paths=('a.py',), agent='child-1'):
    audit.record_changes(check, paths)
    return audit.claim(check, agent, now=10)


def received(check, batch, key='request-0001', now=11):
    return audit.receive(check,batch['batch_id'],batch['token'],key,{'reviews':['concrete evidence']},now=now)


def test_disabled_record_is_zero_allocation(check):
    check['effective_config']['values']['agent']['audit_business_logic']=False
    before=copy.deepcopy(check)
    audit.record_changes(check,['a.py'])
    assert audit.cutoff(check) is None
    assert check==before


def test_edits_merge_unclaimed_versions(check):
    audit.record_changes(check,['a.py'])
    check['dirty_seq']=2
    audit.record_changes(check,['a.py','b.py'])
    b=audit.claim(check,'child',now=0)
    assert b['versions']=={'a.py':2,'b.py':2}
    assert 'token_hash' not in b
    assert b['token'] not in json.dumps(check)


def test_mid_audit_edit_preserves_received_result_but_requires_new_version(check):
    b=begin(check)
    check['dirty_seq']=2
    audit.record_changes(check,['a.py'])
    received(check,b)
    receipt=audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    assert receipt['status']=='NEEDS_REVIEW' and receipt['payload']
    assert audit.progress(check)['pending_paths']==['a.py']
    assert audit.claim(check,'child-1',now=20)['versions']=={'a.py':2}


def test_stop_cutoff_does_not_expand_and_new_round_can_share_executor(check):
    b=begin(check)
    first=audit.cutoff(check)
    assert audit.cutoff(check)==first
    check['dirty_seq']=2
    audit.record_changes(check,['b.py'])
    received(check,b)
    audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    assert audit.progress(check,first)['status']=='COMPLETE'
    assert audit.progress(check)['pending_paths']==['b.py']
    assert audit.progress(check)['cutoff_seq'] is None
    assert audit.claim(check,'child-1')['versions']=={'b.py':2}


def test_late_received_result_is_saved_and_can_apply(check):
    b=begin(check)
    assert audit.progress(check,now=311)['status']=='INTERRUPTED'
    receipt=received(check,b,now=311)
    assert receipt['late'] and receipt['status']=='RECEIVED'
    audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    audit.cutoff(check)
    assert audit.progress(check)['status']=='COMPLETE'


def test_serialized_state_survives_preparer_disappearance(check):
    b=begin(check)
    restored=json.loads(json.dumps(check))
    received(restored,b)
    audit.complete(restored,b['batch_id'],'request-0001',['a.py'])
    assert audit.progress(restored)['status']=='CAUGHT_UP'


def test_receipt_idempotency_survives_intervening_batch(check):
    b=begin(check)
    first=copy.deepcopy(received(check,b))
    audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    check['dirty_seq']=2
    audit.record_changes(check,['b.py'])
    other=audit.claim(check,'child-1')
    received(check,other,'request-0002')
    replay=received(check,b)
    assert replay['received_at']==first['received_at']
    assert replay['status']=='APPLIED'
    assert len(check['audit_stream']['receipts'])==2
    with pytest.raises(ValueError,match='REQUEST_CONFLICT'):
        audit.receive(check,b['batch_id'],b['token'],'request-0001',{'changed':True})


def test_token_and_executor_binding_and_cancellation(check):
    b=begin(check)
    with pytest.raises(ValueError,match='TOKEN_INVALID'):
        audit.receive(check,b['batch_id'],'wrong','request-0001',{})
    with pytest.raises(ValueError,match='EXECUTOR_MISMATCH'):
        audit.authenticate(check,b['batch_id'],b['token'],'other')
    audit.cancel(check,b['batch_id'])
    with pytest.raises(ValueError,match='CANCELLED'):
        received(check,b)
    assert audit.claim(check,'replacement')['versions']=={'a.py':1}


def test_pending_batch_cannot_be_claimed_twice(check):
    b=begin(check)
    assert audit.claim(check,'child-1')['batch_id']==b['batch_id']
    assert audit.claim(check,'child-2')['status']=='CAUGHT_UP'
    audit.renew(check,b['batch_id'],b['token'],now=400)
    assert audit.progress(check,now=500)['status']=='RUNNING'


def test_dependency_change_enqueues_related_result(check):
    b=begin(check)
    received(check,b)
    audit.complete(check,b['batch_id'],'request-0001',['a.py'],dependencies={'a.py':['auth.py']})
    check['dirty_seq']=2
    audit.record_changes(check,['auth.py'])
    assert audit.progress(check)['pending_paths']==['a.py','auth.py']


def test_filtered_outputs_are_not_required_at_cutoff(check):
    audit.record_changes(check,['a.py','generated.json'])
    audit.cutoff(check,['a.py'])
    b=audit.claim(check,'child')
    assert b['versions']=={'a.py':1}


def test_complete_requires_received_result_and_subset_scope(check):
    b=begin(check)
    with pytest.raises(ValueError,match='RECEIPT_UNKNOWN'):
        audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    received(check,b)
    with pytest.raises(ValueError,match='OUTSIDE_BATCH'):
        audit.complete(check,b['batch_id'],'request-0001',['outside.py'])
    assert audit.progress(check)['status']=='RESULT_PENDING'


def test_new_round_supersedes_unreadable_old_input_without_starving(check):
    b=begin(check)
    old=audit.cutoff(check)
    check['dirty_seq']=2
    audit.record_changes(check,['a.py'])
    # Old executor may still return; this receipt is retained but not applied.
    received(check,b)
    assert audit.complete(check,b['batch_id'],'request-0001',['a.py'])['status']=='NEEDS_REVIEW'
    assert audit.progress(check,old)['status']=='SUPERSEDED'
    assert audit.progress(check,old)['pending_paths']==['a.py']
    new=audit.claim(check,'child-1')
    assert new['round_id']!=old and new['versions']=={'a.py':2}


def test_cutoff_preserves_related_dependency_obligations(check):
    b=begin(check)
    received(check,b)
    audit.complete(check,b['batch_id'],'request-0001',['a.py'],dependencies={'a.py':['auth.py']})
    audit.cutoff(check)
    check['dirty_seq']=2
    audit.record_changes(check,['auth.py'])
    audit.cutoff(check,['auth.py'])
    assert audit.progress(check)['pending_paths']==['a.py','auth.py']


def test_capacity_errors_preserve_previous_results_and_pending(check,monkeypatch):
    b=begin(check)
    received(check,b)
    audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    monkeypatch.setattr(audit,'MAX_BATCHES',1)
    check['dirty_seq']=2
    audit.record_changes(check,['b.py'])
    before=copy.deepcopy(check)
    with pytest.raises(ValueError,match='CAPACITY_REQUIRED'):
        audit.claim(check,'child-1')
    assert check==before
    monkeypatch.setattr(audit,'MAX_BATCHES',10)
    next_batch=audit.claim(check,'child-1')
    monkeypatch.setattr(audit,'MAX_RESULT_BYTES',1)
    before=copy.deepcopy(check)
    with pytest.raises(ValueError,match='CAPACITY_REQUIRED'):
        received(check,next_batch,'request-0002')
    assert check==before


def test_current_coverage_index_does_not_require_historical_round_walk(check):
    b=begin(check)
    received(check,b)
    audit.complete(check,b['batch_id'],'request-0001',['a.py'])
    s=check['audit_stream']
    assert s['accepted_current']=={'a.py':dict(seq=1,request_id='request-0001')}
    audit.cutoff(check)
    check['dirty_seq']=2
    audit.record_changes(check,['a.py','generated.json'])
    assert not s['accepted_current'] and s['latest_versions']['a.py']==2
    audit.cutoff(check,['a.py'])
    assert 'generated.json' not in s['latest_versions']

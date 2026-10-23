"""Receipt facts track response boundaries, never inferred user consumption."""
from copy import deepcopy
import json
import sqlite3

import pytest

from security_runtime.hook_state import HookStateStore,identity
from security_runtime.host_event_journal import JournalError
from security_runtime.tasks.delivery_receipts import TaskDeliveryReceipts, result_version, unavailable
from security_runtime.task_review.protocol import UnsupportedTaskReviewProtocol


@pytest.fixture
def delivery(tmp_path):
    root=tmp_path/'workspace';root.mkdir()
    store=TaskDeliveryReceipts(HookStateStore(tmp_path/'state'),root)
    owner=dict(host='cursor',session=identity('private-session'))
    task=dict(task_ref='ts1-'+'a'*32,phase='ACTIVE',review_protocol=3,task_owner=owner,
              baseline={'hashes':{'private-source.java':'a'*64}},generation=1)
    return store,task,owner


def prepare(store,task,owner,category='POST_TOOL_CONTEXT'):
    return store.prepare(task,owner,intent='TASK_CLOSEOUT',category=category)


def test_prepared_is_durable_but_not_sent_or_consumed(delivery):
    store,task,owner=delivery
    receipt=prepare(store,task,owner)
    assert receipt['response_prepared'] and not receipt['transport_written']
    assert receipt['host_report_submitted']=='NOT_OBSERVED' and receipt['user_consumption']=='UNKNOWN'
    assert receipt==prepare(TaskDeliveryReceipts(store.hooks,store.root),task,owner)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM task_deliveries').fetchone()[0]==1
        raw=db.execute('SELECT data FROM task_deliveries').fetchone()[0]
    assert 'private-session' not in raw and 'private-source' not in raw and 'baseline' not in raw
    assert unavailable()['recording']=='UNAVAILABLE' and unavailable()['user_consumption']=='UNKNOWN'


def test_observations_are_monotonic_and_strictly_bound(delivery):
    store,task,owner=delivery;receipt=prepare(store,task,owner)
    args=(receipt['delivery_ref'],owner,receipt['result_version'])
    reported=store.observe(*args,stage='HOST_REPORT_SUBMITTED')
    assert reported['host_report_submitted']=='REPORTED' and not reported['transport_written']
    sent=store.observe(*args,stage='TRANSPORT_WRITTEN')
    assert sent['transport_written'] and sent['user_consumption']=='UNKNOWN'
    assert store.observe(*args,stage='HOST_REPORT_SUBMITTED')==sent
    for wrong in [dict(host='cursor',session='0'*64),None]:
        with pytest.raises(JournalError,match='binding'):
            store.observe(receipt['delivery_ref'],wrong,receipt['result_version'],stage='TRANSPORT_WRITTEN')
        with pytest.raises(JournalError,match='owner'):
            store.get(receipt['delivery_ref'],wrong)
    with pytest.raises(JournalError,match='binding'):
        store.observe(receipt['delivery_ref'],owner,'0'*64,stage='TRANSPORT_WRITTEN')
    with pytest.raises(JournalError):store.observe(*args,stage='USER_CONSUMED')


def test_new_result_version_is_separate_and_old_ack_cannot_ack_new(delivery):
    store,task,owner=delivery;first=prepare(store,task,owner)
    task['hook_checks']=[dict(scan_id='scan-2',status='SCANNED')]
    second=prepare(store,task,owner)
    assert first['result_version']!=second['result_version'] and first['delivery_ref']!=second['delivery_ref']
    store.observe(first['delivery_ref'],owner,first['result_version'],stage='HOST_REPORT_SUBMITTED')
    assert store.get(second['delivery_ref'],owner)==second
    stop=prepare(store,task,owner,'STOP_FOLLOWUP')
    assert stop['delivery_ref']!=second['delivery_ref'] and stop['result_version']==second['result_version']


def test_bookkeeping_does_not_change_result_but_phase_proof_and_gaps_do(delivery):
    _,task,_=delivery;original=result_version(task)
    task.update(generation=999,lease={'token':'private-token'},cursor_followups=['x'],activity_at=99,
                review_evidence=[{'read':True}],task_delivery={'anything':'ignored'})
    assert result_version(task)==original
    for change in [dict(phase='COMPLETE'),dict(review_revision=1),dict(hook_pending_scope_files=['A.java']),
                   dict(ledger_projection={'state':'PENDING'}),dict(static={'scan_id':'new'})]:
        assert result_version(dict(task,**change))!=original


@pytest.mark.parametrize('protocol',[None,1,2,True,'3'])
def test_history_never_creates_receipts(delivery,protocol):
    store,task,owner=delivery;task['review_protocol']=protocol
    with pytest.raises(UnsupportedTaskReviewProtocol):prepare(store,task,owner)
    assert not store.path.exists()


def test_owner_mismatch_and_tampering_do_not_prepare_or_disclose(delivery):
    store,task,owner=delivery
    with pytest.raises(JournalError):prepare(store,task,None)
    assert not store.path.exists()
    receipt=prepare(store,task,owner)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE task_deliveries SET data=?',(json.dumps({'secret':'must-not-echo'}),))
    with pytest.raises(JournalError,match='verified') as caught:prepare(store,task,owner)
    assert 'must-not-echo' not in str(caught.value)

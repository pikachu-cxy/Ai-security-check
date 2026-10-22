import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest

from security_runtime.collector_health import health_data, write_checkpoint
from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import ObservationWorker
from security_runtime.monitoring.host_context import VisibleContext
from security_runtime.monitoring.host_reader import HostReader
from security_runtime.monitoring.service import MonitorService
from security_runtime.triage import TriageService
from test_model_observation import Collector, packet, reply, setup


def test_selected_host_log_visible_inputs_do_not_claim_final_model_context(tmp_path):
    path=tmp_path/'log.jsonl'
    rows=[{'type':'session_meta','payload':{'id':'PRIVATE_SESSION','cwd':str(tmp_path)}},
          {'type':'turn_context','payload':{'cwd':str(tmp_path)}},
          {'type':'response_item','payload':{'id':'private-item','type':'message','role':'user',
            'content':[{'type':'input_text','text':'PRIVATE_USER_TEXT'},{'type':'input_image','image_url':'PRIVATE_IMAGE_URL'}]}},
          {'type':'response_item','payload':{'type':'function_call_output','output':'PRIVATE_TOOL_RESULT'}},
          {'type':'event_msg','payload':{'type':'token_count','info':{'total_token_usage':{'input_tokens':50,'output_tokens':10}}}}]
    path.write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8')
    reader=HostReader(path,expected_identity=hashlib.sha256(b'PRIVATE_SESSION').hexdigest())
    view=reader.poll()
    visible=view['visible_context']
    assert visible['status']=='PARTIAL' and visible['request_usage_link']=='UNAVAILABLE'
    assert visible['inputs'][0]['final_model_input'] is False
    assert visible['inputs'][0]['items']==2
    assert view['usage']['total_tokens']==60
    encoded=json.dumps(view)
    for secret in ('PRIVATE_SESSION','PRIVATE_USER_TEXT','PRIVATE_IMAGE_URL','PRIVATE_TOOL_RESULT','private-item'):
        assert secret not in encoded
    assert reader.poll()['visible_context']==visible
    with path.open('a',encoding='utf-8') as stream:
        stream.write(json.dumps(rows[2])+'\n')
    assert reader.poll()['visible_context']==visible  # Explicit item id deduplicates.


def test_unmatched_or_replaced_host_log_never_exposes_context(tmp_path):
    path=tmp_path/'log.jsonl'
    path.write_text(json.dumps({'type':'session_meta','payload':{'id':'OTHER'}})+'\n')
    reader=HostReader(path,expected_identity='a'*64)
    result=reader.poll()
    assert result['status']=='UNAVAILABLE' and result['visible_context']['inputs']==[]


def test_visible_context_is_bounded_and_does_not_double_count_user_event():
    value=VisibleContext()
    for _ in range(40):
        value.consume({'type':'turn_context','payload':{}})
        value.consume({'type':'event_msg','payload':{'type':'user_message','message':'not a second copy'}})
        value.consume({'type':'response_item','payload':{'type':'message','role':'user','content':'hello'}})
    view=value.view()
    assert len(view['inputs'])==32 and view['omitted_inputs']==8
    assert all(item['items']==1 and item['components'][0]['text_bytes']==5 for item in view['inputs'])


def test_collector_checkpoint_preserves_loss_without_later_successful_call(tmp_path,monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE',raising=False)
    store=ContextCostStore(tmp_path/'metrics.db')
    store.set_monitoring('basic')
    stats=dict(producer_id='local-producer',offered=4,enqueued=3,dropped=1,invalid=0,
               persisted=1,write_errors=1,disabled=0,settings_errors=0,queued=1,pending=1)
    write_checkpoint(store,stats,'RUNNING')
    snap=store.snapshot()
    assert not snap['events'] and len(snap['collector_checkpoints'])==1
    old=snap['collector_checkpoints'][0]
    view=health_data([old],now=old['at']+20)
    assert view['producers'][0]['state']=='STALE_OR_BLOCKED'
    assert view['producers'][0]['dropped']==1 and not view['lossless']
    write_checkpoint(store,stats,'STOPPED')
    closed=health_data(store.snapshot()['collector_checkpoints'])
    assert closed['producers'][0]['state']=='STOPPED_WITH_PENDING'
    assert closed['tail_coverage']=='UNKNOWN_AFTER_LAST_CHECKPOINT'
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    other=ContextCostStore(tmp_path/'off.db')
    write_checkpoint(other,stats,'STOPPED')
    assert not other.path.exists()


def test_close_does_not_wait_for_blocked_writer_or_checkpoint(monkeypatch):
    entered,release=threading.Event(),threading.Event()
    class Store:
        def monitoring(self): return dict(status='AVAILABLE',mode='debug',source='default')
        def record_observation(self,row):
            entered.set()
            release.wait(10)
            return {'status':'RECORDED'}
    worker=ObservationWorker(Store)
    worker.start()
    try:
        assert worker.offer(dict(tool='runtime_scan',measurements={},observations={}))
        assert entered.wait(2)
        worker.close()
        assert worker.stats()['stopped'] and not release.is_set()
    finally:
        release.set()
        assert worker.wait_idle(2)


def test_direct_triage_scope_binds_real_scan_reference_and_filters_project(setup,monkeypatch,tmp_path):
    collector,provider=setup
    reply(monkeypatch,value={'finding_id':'PRIVATE_FINDING'},usage={'prompt_tokens':12,'completion_tokens':3})
    source=SimpleNamespace(get_scan=lambda scan_id:dict(target_profile={'path':str(tmp_path)},findings=[]))
    service=TriageService(source)
    def prepare(scan_id,**kwargs):
        service.scan(scan_id)
        return dict(packets=[dict(packet(),category='code')],cached_finding_ids=[],errors=[])
    monkeypatch.setattr(service,'prepare',prepare)
    monkeypatch.setattr(service,'submit',lambda *a,**k:None)
    monkeypatch.setattr(service,'view',lambda *a,**k:{'unchanged':True})
    result=service.run('private-scan',provider)
    assert result['completed']==1 and result['view']=={'unchanged':True}
    store=ContextCostStore(tmp_path/'metrics.db')
    store.set_monitoring('basic')
    for item in collector.rows:
        assert store.record_observation(item)['status']=='RECORDED'
    monitor=MonitorService(store,project=tmp_path)
    data=monitor.snapshot('project')
    assert data['model_requests']['reported_usage']['total_tokens']==15
    assert data['model_requests']['requests'][0]['parent_call_id']==data['events'][0]['call_id']
    other=MonitorService(store,project=tmp_path/'other')
    assert other.snapshot('project')['model_requests']['observed_attempts']==0
    assert monitor.snapshot('chat')['model_requests']['observed_attempts']==0
    assert monitor.snapshot('scan')['model_requests']['observed_attempts']==1


def test_request_metrics_never_add_to_host_usage_total(setup,monkeypatch,tmp_path):
    collector,provider=setup
    reply(monkeypatch,usage={'prompt_tokens':12,'completion_tokens':3})
    provider.triage(packet())
    store=ContextCostStore(tmp_path/'metrics.db')
    store.set_monitoring('basic')
    for item in collector.rows: store.record_observation(item)
    data=MonitorService(store).snapshot('all')
    assert data['usage'] is None and data['attribution']['chat_total_tokens'] is None
    assert data['model_requests']['reported_usage']['total_tokens']==15
    assert data['calls']==0

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime import observation
from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import bounded_record
from security_runtime.context_cost_sync import observed
from security_runtime.model_observation import input_manifest, provider_usage
from security_runtime.model_report import request_data
from security_runtime.triage_providers import AIConfig, OpenAICompatibleProvider


class Collector:
    def __init__(self, failure=None):
        self.rows = []
        self.failure = failure

    def snapshot_settings(self):
        if self.failure == 'settings':
            raise OSError('monitor settings failed')
        return dict(mode='debug', source='saved', run='model-test')

    def offer(self, value):
        if self.failure == 'write':
            raise OSError('monitor write failed')
        if self.failure == 'full':
            return False
        row = bounded_record(value)
        assert row is not None
        self.rows.append(row)
        return True


@pytest.fixture
def setup(monkeypatch):
    collector = Collector()
    monkeypatch.setattr('security_runtime.context_cost_worker.get_worker', lambda:collector)
    monkeypatch.setenv('SECURITY_RUNTIME_AI_KEY','PRIVATE_API_KEY_NEVER_RETAIN')
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','0')
    for name in ('SECURITY_RUNTIME_CONTEXT_MONITOR','SECURITY_RUNTIME_CONTEXT_MODE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE','basic')
    provider = OpenAICompatibleProvider(AIConfig('https://synthetic.invalid/v1','fake'),allow_external_code_context=True)
    return collector, provider


def reply(monkeypatch, value=None, *, usage=None, raw=None):
    requests = []
    payload = dict(id='PRIVATE_PROVIDER_RESPONSE',choices=[dict(message=dict(content=json.dumps(value or {'result':'ok'})))])
    if usage is not None:
        payload['usage'] = usage
    class Response:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def read(self,n): return (raw if raw is not None else json.dumps(payload).encode())[:n]
    def open(request, **kwargs):
        requests.append((request.data,dict(request.headers),request.full_url,kwargs))
        return Response()
    monkeypatch.setattr('security_runtime.triage_providers.build_opener',lambda *a:SimpleNamespace(open=open))
    return requests


def packet():
    return dict(context=[{'text':'PRIVATE_REPOSITORY_正文'}],related_evidence=[{'text':'PRIVATE_RELATED'}],finding_id='PRIVATE_FINDING')


@pytest.mark.parametrize('failure', [None,'off','settings','write','full','absent'])
def test_exact_request_response_and_single_send_under_monitor_failure(setup, monkeypatch, failure):
    collector, provider = setup
    requests = reply(monkeypatch)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    expected = provider.triage(packet())
    baseline = requests[-1]
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR')
    collector.failure = failure
    if failure == 'off':
        monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    if failure == 'absent':
        import sys
        monkeypatch.setitem(sys.modules,'security_runtime.model_observation',None)
    result = provider.triage(packet())
    assert result == expected and len(requests) == 2 and requests[-1] == baseline
    if failure is None:
        assert [row['model_request']['state'] for row in collector.rows] == ['STARTED','COMPLETED']
    else:
        assert not collector.rows


def test_request_input_usage_and_product_link_are_private_and_reportable(setup, monkeypatch, tmp_path):
    collector, provider = setup
    usage = dict(prompt_tokens=100, completion_tokens=20,total_tokens=120,
                 prompt_tokens_details={'cached_tokens':30},completion_tokens_details={'reasoning_tokens':5})
    sent = reply(monkeypatch,usage=usage)
    @observed('run_triage')
    def product():
        observation.bind_chat(dict(host='codex',session='a'*64))
        observation.bind_workspace(str(tmp_path))
        observation.bind_product('scan','PRIVATE_SCAN_REF',relation='SCAN_RECORD_READ')
        return provider.triage(packet())
    assert product() == {'result':'ok'}
    assert not observation.active()
    store = ContextCostStore(tmp_path/'metrics.db')
    for row in collector.rows:
        assert store.record_observation(row)['status'] == 'RECORDED'
    snapshot = store.snapshot()
    assert len(snapshot['events']) == 1 and len(snapshot['model_requests']) == 2
    start, end = collector.rows[:2]
    assert end['model_request']['attempt_id'] == start['model_request']['attempt_id']
    assert end['correlation']['call_id'] == collector.rows[-1]['correlation']['call_id']
    manifest = end['model_request']['manifest']
    messages = json.loads(sent[0][0])['messages']
    assert manifest['content_bytes'] == sum(len(row['content'].encode()) for row in messages)
    assert sum(row['bytes'] for row in manifest['components']) == manifest['content_bytes']
    assert {'repository_evidence','related_evidence','system_instructions','output_schema'} <= {r['category'] for r in manifest['components']}
    assert manifest['request_bytes'] == len(sent[0][0])
    from security_runtime.context_report import report_data
    report = report_data(store)
    model = report['model_requests']
    assert model['observed_attempts'] == 1 and model['reported_usage']['total_tokens'] == 120
    assert model['requests'][0]['links'][0]['subject'] == report['associations']['calls'][0]['links'][0]['subject']
    assert model['requests'][0]['parent_call_id'] == report['events'][0]['call_id']
    for private in ('PRIVATE_API_KEY','PRIVATE_REPOSITORY','PRIVATE_RELATED','PRIVATE_FINDING',
                    'PRIVATE_PROVIDER_RESPONSE'):
        assert private not in json.dumps(collector.rows) and private not in json.dumps(report)
        assert private.encode() not in store.path.read_bytes()
    assert 'PRIVATE_SCAN_REF' not in json.dumps(report)
    assert b'PRIVATE_SCAN_REF' not in store.path.read_bytes()
    assert 'fingerprint' not in json.dumps(model)


@pytest.mark.parametrize('usage,expected', [
    (None, 'MISSING'), ({},'INVALID'),
    ({'prompt_tokens':True,'completion_tokens':1},'INVALID'),
    ({'prompt_tokens':1,'completion_tokens':2,'total_tokens':4},'INVALID'),
    ({'prompt_tokens':1,'completion_tokens':2,'prompt_tokens_details':{'cached_tokens':2}},'INVALID'),
    ({'prompt_tokens':1,'completion_tokens':2},'REPORTED'),
    ({'prompt_tokens':0,'completion_tokens':0},'REPORTED')])
def test_usage_counts_and_unknown_details(usage, expected):
    result,status = provider_usage(usage)
    assert status == expected
    if status == 'REPORTED':
        assert result['cached_input_tokens'] is None and result['reasoning_output_tokens'] is None


@pytest.mark.parametrize('failure', ['json','http','timeout','cancel'])
def test_failure_records_do_not_change_exception_or_retry(setup, monkeypatch, failure):
    collector,provider = setup
    if failure == 'json':
        calls=reply(monkeypatch,raw=b'{bad')
        expected=ValueError
    else:
        from urllib.error import HTTPError
        error={'http':HTTPError('https://invalid',500,'secret',None,None),
               'timeout':TimeoutError('secret'),'cancel':KeyboardInterrupt()}[failure]
        calls=[]
        def open(*a,**k):
            calls.append(1)
            raise error
        monkeypatch.setattr('security_runtime.triage_providers.build_opener',lambda *a:SimpleNamespace(open=open))
        expected=KeyboardInterrupt if failure == 'cancel' else ValueError
    with pytest.raises(expected):
        provider.triage(packet())
    assert len(calls)==1
    assert collector.rows[-1]['model_request']['state']=='FAILED'
    assert collector.rows[-1]['model_request']['usage'] is None


def test_existing_external_authorization_and_offline_gates_run_before_observation(setup,monkeypatch):
    collector,provider=setup
    with pytest.raises(ValueError,match='Explicit'):
        OpenAICompatibleProvider(provider.config)
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    with pytest.raises(ValueError,match='offline'):
        provider.triage(packet())
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','0')
    monkeypatch.delenv('SECURITY_RUNTIME_AI_KEY')
    with pytest.raises(ValueError,match='missing'):
        provider.triage(packet())
    assert collector.rows==[]


def test_batch_partition_and_repeat_detection(setup,monkeypatch,tmp_path):
    collector,provider=setup
    reply(monkeypatch,value={'results':[{},{}]})
    provider.triage_batch([packet(),packet()])
    provider.triage_batch([packet(),packet()])
    store=ContextCostStore(tmp_path/'models.db')
    for item in collector.rows:
        assert store.record_observation(item)['status']=='RECORDED'
    data=request_data(store.snapshot()['model_requests'])
    assert data['observed_attempts']==2
    assert all(c['reuse']=='PREVIOUSLY_OBSERVED' for c in data['requests'][1]['input']['components'])
    assert data['reported_usage'] is None


def test_unfinished_attempt_and_replayed_observation_are_not_double_counted(setup,monkeypatch,tmp_path):
    collector,provider=setup
    reply(monkeypatch,usage={'prompt_tokens':2,'completion_tokens':3})
    provider.triage(packet())
    store=ContextCostStore(tmp_path/'models.db')
    start,end=collector.rows
    store.record_observation(start)
    pending=request_data(store.snapshot()['model_requests'])
    assert pending['pending_attempts']==1 and pending['reported_usage'] is None
    store.record_observation(end)
    store.record_observation(end)
    data=request_data(store.snapshot()['model_requests'])
    assert data['observed_attempts']==1 and data['reported_usage']['total_tokens']==5
    assert store.summary()['calls']==0


def test_monitor_metadata_schema_rejects_body_and_invalid_counts(setup,monkeypatch):
    collector,provider=setup
    reply(monkeypatch)
    provider.triage(packet())
    record=collector.rows[-1]
    record['model_request']['body']='PRIVATE'
    assert bounded_record(record) is None
    del record['model_request']['body']
    record['model_request']['manifest']['content_bytes']+=1
    assert bounded_record(record) is None


def test_sync_nested_capture_and_fault_preserve_exact_result(setup):
    collector,_=setup
    result=object()
    @observed('runtime_scan')
    def inner(): return result
    @observed('run_triage')
    def outer(): return inner()
    assert outer() is result and len(collector.rows)==1 and not observation.active()
    collector.failure='write'
    assert outer() is result and not observation.active()


def test_rebinding_missing_optional_host_fields_preserves_known_turn():
    capture,token=observation.begin_call()
    try:
        observation.bind_host('codex','a'*64,'b'*64,'c'*64)
        observation.bind_host('codex','a'*64,'b'*64)
        facts=observation.current_facts()['correlation']
        assert facts['turn_binding']=='c'*64 and not facts['chat_conflict']
    finally:
        observation.end_call(capture,token)

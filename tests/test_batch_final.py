"""Real workspace freshness and protocol tests; host reasoning is a fixture."""
import pytest

from test_task_security import service, begin
from security_runtime.batch_final import CHECKS
from security_runtime.task_security_batch import TaskSecurityBatchService, budget_usage
from security_runtime.mcp_server import create_server
from security_runtime.batch_final import validate_integration


def final_packet(sample):
    tasks, root, _ = sample
    ref = begin(sample)
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    batches = TaskSecurityBatchService(tasks)
    batch = batches.prepare(root, ref, 'route-complete')
    window = batches.read(root, ref, batch['batch_ref'], batch['review_session'], 'routes.py')
    batches.submit(root, ref, batch['batch_ref'], batch['review_session'], [],
                   'PARTIAL', ['Host result is a protocol fixture, not an accuracy evaluation.'])
    tasks.finish(root, ref)
    packet = tasks.prepare(root, ref)
    current = tasks.read(root, ref, packet['review_session'], 'routes.py')
    return tasks, root, ref, packet, current, batch, window


def report(packet, current):
    return dict(snapshot_id=packet['batch_review']['snapshot_id'], batch_refs=[],
        reviewed_paths=packet['batch_review']['review_scope'],
        evidence_refs=[current['evidence_id']],
        checks={key:'Fixture examined the final source; no accuracy claim.' for key in CHECKS},
        candidate_dispositions=[], limitations=[])


def test_legacy_flow_does_not_require_integration(service):
    tasks,root,_ = service
    ref = begin(service)
    (root/'routes.py').write_text('def get_order(order_id):\n    return load_order(order_id) # changed\n')
    tasks.finish(root,ref)
    packet=tasks.prepare(root,ref)
    assert 'batch_review' not in packet
    result=tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[])
    assert result['status']=='COMPLETE'


def test_batch_completion_requires_explicit_final_integration(service):
    tasks,root,ref,packet,current,_,_=final_packet(service)
    result=tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[])
    review=tasks.load(root,ref)['review']
    assert review['coverage']=='PARTIAL'
    assert any('跨批次' in limit for limit in review['limitations'])


def test_final_report_binds_source_and_current_evidence(service):
    tasks,root,ref,packet,current,_,_=final_packet(service)
    result=tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[],
                        integration_review=report(packet,current))
    record=tasks.load(root,ref)
    assert record['review']['integration_review']['snapshot_id']==packet['batch_review']['snapshot_id']
    assert record['review']['integration_review']['evidence_refs']==[current['evidence_id']]


@pytest.mark.parametrize('bad', ['snapshot','batch','evidence','checks'])
def test_forged_or_cross_version_integration_rejected(service,bad):
    tasks,root,ref,packet,current,_,old=final_packet(service)
    value=report(packet,current)
    if bad=='snapshot': value['snapshot_id']='bs1-'+'0'*32
    if bad=='batch': value['batch_refs']=['not-issued']
    if bad=='evidence': value['evidence_refs']=[old['evidence_id']]
    if bad=='checks': value['checks']={}
    with pytest.raises(ValueError):
        tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[],integration_review=value)


def test_changed_final_source_rejects_otherwise_valid_report(service):
    tasks,root,ref,packet,current,_,_=final_packet(service)
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    with pytest.raises(ValueError,match='stale'):
        tasks.submit(root,ref,packet['review_session'],[],'REVIEWED',[],
                     integration_review=report(packet,current))


def test_batch_budget_is_carried_into_final_session(service):
    tasks,root,ref,packet,current,_,_=final_packet(service)
    record=tasks.load(root,ref)
    usage=budget_usage(record)
    assert usage['context_bytes']>0 and usage['context_reads']==1
    assert record['context_bytes']>usage['context_bytes']
    assert packet['budget']['batch_context_bytes']==usage['context_bytes']


def test_final_preparation_closes_late_worker_reads(service):
    tasks,root,_=service
    ref=begin(service)
    (root/'routes.py').write_text('def get_order(order_id,user):\n    return load_order(order_id)\n')
    batches=TaskSecurityBatchService(tasks)
    batch=batches.prepare(root,ref,'route')
    tasks.finish(root,ref)
    tasks.prepare(root,ref)
    with pytest.raises(ValueError):
        batches.read(root,ref,batch['batch_ref'],batch['review_session'],'routes.py')


def test_batch_tools_are_opt_in_and_strict(service):
    tasks,root,runtime=service
    base=create_server(runtime,global_mode=False)
    experimental=create_server(runtime,global_mode=False,include_batch_review=True)
    names=lambda server:{t.name for t in server._tool_manager.list_tools()}
    assert 'prepare_security_batch' not in names(base)
    assert {'prepare_security_batch','read_security_batch_context',
            'submit_security_batch_review','get_security_batches'}<=names(experimental)
    tool=experimental._tool_manager.get_tool('prepare_security_batch')
    assert tool.parameters['additionalProperties'] is False


def test_default_and_experimental_runtime_identity(service):
    _,_,runtime=service
    for enabled in (False,True):
        server=create_server(runtime,global_mode=False,include_batch_review=enabled)
        info=server._tool_manager.get_tool('get_runtime_info').fn()
        assert ('task_batch_review' in info['features']) is enabled


def test_reusable_scope_uses_structured_path_receipts():
    record=dict(batch_state={'batches':[]},changes=[],
        evidence={'now':dict(path='auth.py',location_version='CURRENT_TASK_END')},
        packet={'batch_review':dict(snapshot_id='final',review_scope=['routes.py'],
            reusable_candidates=[dict(batch_ref='b1',review_scope=[dict(path='routes.py')])])})
    packet={'batch_review':record['packet']['batch_review']}
    value=report(packet,{'evidence_id':'now'})
    value['batch_refs']=['b1']
    _,gaps=validate_integration(record,value,[])
    assert not gaps


def test_reused_batch_cannot_replace_final_current_evidence():
    record=dict(batch_state={'batches':[]},changes=[],
        evidence={'before':dict(path='routes.py',location_version='BEFORE_TASK')},
        packet={'batch_review':dict(snapshot_id='final',review_scope=['routes.py'],
            reusable_candidates=[dict(batch_ref='b1',review_scope=[dict(path='routes.py')])])})
    value=report(record['packet'],{'evidence_id':'before'})
    value['batch_refs']=['b1']
    with pytest.raises(ValueError,match='historical'):
        validate_integration(record,value,[])


def test_historical_preimage_cannot_exclude_batch_candidate():
    record=dict(batch_state={'batches':[dict(batch_ref='b1',review={'findings':[
        dict(id='c1',file_path='routes.py',title='Candidate',evidence_locations=[])]})]},
        changes=[],evidence={'now':dict(path='routes.py',location_version='CURRENT_TASK_END'),
            'before':dict(path='routes.py',location_version='BEFORE_TASK')},
        packet={'batch_review':dict(snapshot_id='final',review_scope=['routes.py'],reusable_candidates=[])})
    value=report(record['packet'],{'evidence_id':'now'})
    value['candidate_dispositions']=[dict(batch_ref='b1',candidate_id='c1',outcome='EXCLUDED',
        evidence_refs=['before'],reason='Historical source does not establish a current control.')]
    with pytest.raises(ValueError,match='Historical'):
        validate_integration(record,value,[])


def test_changed_file_budget_is_shared_after_reverts(service,monkeypatch):
    from security_runtime import task_security
    tasks,root,_=service
    ref=begin(service)
    original=(root/'routes.py').read_text()
    (root/'routes.py').write_text(original+'# edit\n')
    batches=TaskSecurityBatchService(tasks)
    batch=batches.prepare(root,ref,'route')
    batches.read(root,ref,batch['batch_ref'],batch['review_session'],'routes.py')
    batches.submit(root,ref,batch['batch_ref'],batch['review_session'],[],'PARTIAL',['Fixture review.'])
    (root/'routes.py').write_text(original)
    (root/'service.py').write_text('def load_order(order_id):\n    return repository.get_checked(order_id)\n')
    monkeypatch.setattr(task_security,'MAX_CHANGED',1)
    tasks.finish(root,ref)
    packet=tasks.prepare(root,ref)
    with pytest.raises(task_security.TaskContextError,match='Cumulative'):
        tasks.read(root,ref,packet['review_session'],'service.py')

"""Real snapshot isolation and version arbitration; model output is a fixture."""
import json
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.task_security import TaskSecurityService, TaskContextError
from security_runtime.task_security_batch import TaskSecurityBatchService, budget_usage
import security_runtime.task_security_batch as batches


class NoScanRuntime:
    def scan(self, *args, **kwargs):
        pytest.fail('Batch preparation/read/submission must never invoke a scanner')


@pytest.fixture
def sample(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    subprocess.run(['git','init','-q',str(root)],check=True)
    (root/'routes.py').write_text('def route(user):\n    return service.load(user)\n')
    (root/'service.py').write_text('def load(user):\n    return repository.get(user.id)\n')
    (root/'auth.py').write_text('def allowed(user):\n    return user.active\n')
    service = TaskSecurityService(NoScanRuntime(),HookStateStore(tmp_path/'state'))
    ref = service.begin(root,'batch-fixture')['task_ref']
    return service,TaskSecurityBatchService(service),root,ref


def prepare(sample, checkpoint='feature-1', text='def route(user):\n    return service.unchecked(user)\n'):
    _,service,root,ref = sample
    (root/'routes.py').write_text(text)
    return service.prepare(root,ref,checkpoint)


def read(sample, packet, name='routes.py', start=1, end=80, version='SNAPSHOT'):
    _,service,root,ref = sample
    return service.read(root,ref,packet['batch_ref'],packet['review_session'],name,start,end,version)


def submit(sample, packet, findings=None, coverage='REVIEWED', limitations=None):
    _,service,root,ref = sample
    return service.submit(root,ref,packet['batch_ref'],packet['review_session'],
                          findings or [],coverage,limitations or [])


def candidate(primary, refs=None):
    return dict(title='Unbound user object',category='authorization',severity='MEDIUM',
        primary_evidence=primary,evidence_refs=refs or [primary],
        impact='A caller may read another user record.',
        preconditions=['Reachable route without another ownership check'],
        unknowns=['Deployment access is unknown'],counterevidence=[],
        fix_advice='Bind the query to the current authenticated user.')


def test_batch_keeps_active_task_and_never_scans(sample):
    task,batch,root,ref = sample
    assert batch.prepare(root,ref,'empty')['status']=='NO_BATCH_CHANGES'
    packet = prepare(sample)
    assert packet['status']=='REVIEW_REQUIRED' and packet['dispatch_required']
    assert task.load(root,ref)['phase']=='ACTIVE'
    assert task.load(root,ref)['static_attempts']==0
    assert packet['static']['new_scanner_invocation'] is False
    assert packet['static']['exact_version_verified'] is False


def test_context_reads_frozen_snapshot_while_development_continues(sample):
    _,_,root,_ = sample
    packet = prepare(sample)
    (root/'routes.py').write_text('def route(user):\n    return replacement.version(user)\n')
    evidence = read(sample,packet)
    assert 'unchecked' in '\n'.join(evidence['numbered_lines'])
    assert 'replacement' not in json.dumps(evidence)
    result = submit(sample,packet)
    assert result['status']=='COMPLETE' and result['validity']=='STALE'
    assert result['stale_paths']==['routes.py']


def test_zero_findings_also_requires_issued_scope_evidence(sample):
    packet = prepare(sample)
    result = submit(sample,packet)
    assert result['coverage']=='PARTIAL'
    assert result['review_scope'][0]['path']=='routes.py'
    assert result['review_scope'][0]['evidence_refs']==[]


def test_exact_and_unrelated_versions_have_different_reuse_contracts(sample):
    task,batch,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    assert submit(sample,packet)['validity']=='CURRENT_REUSABLE'
    # Bookkeeping generation is not a new source version.
    record = task.load(root,ref)
    record['diagnostic_counter']=1
    task.store(root).save(record)
    assert batch.get(root,ref)['batches'][0]['validity']=='CURRENT_REUSABLE'
    (root/'new_entry.py').write_text('from routes import route\n')
    assert batch.get(root,ref)['batches'][0]['validity']=='INTEGRATION_RECHECK'
    final = batch.final_coverage(root,task.load(root,ref))
    assert final['integration_required']
    assert final['path_coverage'][0]['path']=='new_entry.py'
    assert final['unreviewed_paths']==['new_entry.py']
    assert final['reusable_candidates'][0]['validity']=='INTEGRATION_RECHECK'


def test_read_related_auth_change_invalidates_zero_finding_result(sample):
    _,batch,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    read(sample,packet,'auth.py')
    submit(sample,packet)
    (root/'auth.py').write_text('def allowed(user):\n    return True\n')
    result = batch.get(root,ref)['batches'][0]
    assert result['validity']=='STALE' and result['stale_paths']==['auth.py']


def test_pending_checkpoints_merge_and_old_completion_preserves_new_dirty_version(sample):
    task,batch,root,ref = sample
    first = prepare(sample)
    read(sample,first)
    second = prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    assert second['status']=='BATCH_QUEUED'
    third = prepare(sample,'feature-3','def route(user):\n    return service.third(user)\n')
    assert third['status']=='BATCH_QUEUED'
    record = task.load(root,ref)
    record['ai_dirty_versions']={'routes.py':'new-version-hash'}
    task.store(root).save(record)
    assert submit(sample,first)['pending_ready']
    assert task.load(root,ref)['ai_dirty_versions']=={'routes.py':'new-version-hash'}
    assert len(batch.get(root,ref)['batches'])==1
    # The earlier queued checkpoint maps to the merged latest pending snapshot.
    next_packet = batch.prepare(root,ref,'feature-2')
    assert next_packet['status']=='REVIEW_REQUIRED'
    assert next_packet['batch_ref']==third['batch_ref']
    evidence = read(sample,next_packet)
    assert 'third' in '\n'.join(evidence['numbered_lines'])
    assert batch.prepare(root,ref,'feature-3')['review_session']==next_packet['review_session']


def test_checkpoint_retry_is_idempotent_and_does_not_reset_budget(sample):
    task,batch,root,ref = sample
    packet = prepare(sample)
    initial = budget_usage(task.load(root,ref))
    assert batch.prepare(root,ref,'feature-1')['review_session']==packet['review_session']
    assert budget_usage(task.load(root,ref))==initial
    read(sample,packet)
    used = budget_usage(task.load(root,ref))
    read(sample,packet)
    assert budget_usage(task.load(root,ref))==used
    submit(sample,packet)
    assert batch.prepare(root,ref,'feature-1')['status']=='BATCH_ALREADY_REVIEWED'
    assert budget_usage(task.load(root,ref))==used


def test_candidate_requires_issued_evidence_and_rejects_proof_authority(sample):
    packet = prepare(sample)
    with pytest.raises(ValueError,match='issued batch evidence'):
        submit(sample,packet,[candidate('invented')])
    evidence = read(sample,packet)
    bad = candidate(evidence['evidence_id'])
    bad['scanner_sources']=['claimed-scanner']
    with pytest.raises(ValueError,match='forbidden'):
        submit(sample,packet,[bad])
    result = submit(sample,packet,[candidate(evidence['evidence_id'])])
    finding = result['findings'][0]
    assert finding['source']=='HOST_BATCH_REVIEW'
    assert finding['scanner_sources']==[] and finding['batch_ref']==packet['batch_ref']


def test_evidence_from_another_batch_is_rejected(sample):
    packet = prepare(sample)
    evidence = read(sample,packet)
    submit(sample,packet)
    next_packet = prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    with pytest.raises(ValueError,match='issued batch evidence'):
        submit(sample,next_packet,[candidate(evidence['evidence_id'])])


def test_read_budget_is_cumulative_across_batches(sample,monkeypatch):
    task,_,_,_ = sample
    monkeypatch.setattr(batches,'MAX_BATCH_CONTEXT_READS',2)
    first = prepare(sample)
    read(sample,first)
    read(sample,first,'auth.py')
    submit(sample,first)
    second = prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    with pytest.raises(TaskContextError) as error:
        read(sample,second)
    assert error.value.reason_code=='BATCH_CONTEXT_READ_BUDGET'
    assert budget_usage(task.load(sample[2],sample[3]))['context_reads']==2


def test_missing_snapshot_cache_never_falls_back_to_live_source(sample,monkeypatch):
    monkeypatch.setattr(batches,'MAX_SNAPSHOT_TEXT_BYTES',0)
    packet = prepare(sample)
    with pytest.raises(TaskContextError) as error:
        read(sample,packet)
    assert error.value.reason_code=='BATCH_SNAPSHOT_TEXT_UNAVAILABLE'


def test_environment_secret_and_unsafe_paths_are_excluded(sample):
    _,_,root,_ = sample
    (root/'.env').write_text('API_KEY=private_fixture_password_value\n')
    (root/'secret.py').write_text('api_key = "private_fixture_password_value"\n')
    packet = prepare(sample)
    for name in ('../outside.py','.env','C:/outside.py','routes.py:stream'):
        with pytest.raises(ValueError):
            read(sample,packet,name)
    assert 'private_fixture_password_value' not in json.dumps(read(sample,packet,'secret.py'))


def test_deleted_file_reads_original_snapshot_and_final_matches_absence(sample):
    task,batch,root,ref = sample
    (root/'routes.py').unlink()
    packet = batch.prepare(root,ref,'remove-route')
    evidence = read(sample,packet)
    assert evidence['location_version']=='BEFORE_DELETION'
    assert submit(sample,packet)['validity']=='CURRENT_REUSABLE'
    final = batch.final_coverage(root,task.load(root,ref))
    assert final['path_coverage'][0]['snapshot_file_sha256']=='ABSENT'
    (root/'routes.py').write_text('def route(user):\n    return None\n')
    assert batch.get(root,ref)['batches'][0]['validity']=='STALE'


def test_before_batch_evidence_cannot_locate_current_candidate(sample):
    packet = prepare(sample)
    evidence = read(sample,packet,version='BEFORE_BATCH')
    with pytest.raises(ValueError,match='preimage'):
        submit(sample,packet,[candidate(evidence['evidence_id'])])


def test_unread_requested_pages_force_partial(sample):
    packet = prepare(sample,text='\n'.join(f'value_{i} = {i}' for i in range(100))+'\n')
    evidence = read(sample,packet,end=100)
    assert evidence['has_more'] and evidence['end_line']==80
    result = submit(sample,packet)
    assert result['coverage']=='PARTIAL'
    assert any('读完' in limitation for limitation in result['limitations'])


def test_expired_worker_cannot_restart_same_checkpoint(sample):
    task,batch,root,ref = sample
    packet = prepare(sample)
    record = task.load(root,ref)
    record['batch_state']['batches'][0]['review_deadline']=0
    task.store(root).save(record)
    assert batch.get(root,ref)['batches'][0]['status']=='EXPIRED'
    assert batch.prepare(root,ref,'feature-1')['status']=='BATCH_EXPIRED'
    with pytest.raises(ValueError,match='expired'):
        read(sample,packet)


def test_original_task_closeout_phase_rejects_new_background_dispatch(sample):
    task,batch,root,ref = sample
    record = task.load(root,ref)
    record['phase']='INCOMPLETE'
    task.store(root).save(record)
    assert batch.prepare(root,ref,'late')['status']=='BATCH_TASK_NOT_ACTIVE'


def test_final_coverage_uses_net_task_diff_not_historical_batch_union(sample):
    task,batch,root,ref = sample
    original = (root/'routes.py').read_text()
    packet = prepare(sample)
    read(sample,packet)
    submit(sample,packet)
    (root/'routes.py').write_text(original)
    final = batch.final_coverage(root,task.load(root,ref))
    assert final['review_scope']==[] and final['reusable_candidates']==[]


def test_multi_file_batch_requires_related_control_evidence(sample):
    _,_,root,_ = sample
    (root/'service.py').write_text('def load(user):\n    return repository.all()\n')
    packet = prepare(sample)
    read(sample,packet)
    read(sample,packet,'service.py')
    assert submit(sample,packet)['coverage']=='PARTIAL'


def test_snapshot_byte_limit_never_silently_drops_existing_worker_cache(sample,monkeypatch):
    _,batch,root,ref = sample
    first = prepare(sample)
    before = read(sample,first)
    monkeypatch.setattr(batches,'MAX_SNAPSHOT_BYTES',1)
    second = prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    assert second['status']=='BATCH_BUDGET_EXCEEDED'
    assert read(sample,first)['numbered_lines']==before['numbered_lines']
    assert batch.get(root,ref)['pending_batch_ref'] is None


def test_finalization_closes_worker_reads_and_submissions_without_budget_changes(sample):
    task,_,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    record = task.load(root,ref)
    original_budget = budget_usage(record)
    record['batch_state']['finalizing']=True
    record['batch_state']['batches'][0]['status']='CANCELLED_AT_FINAL'
    task.store(root).save(record)
    with pytest.raises(ValueError,match='closed for final'):
        read(sample,packet,'auth.py')
    with pytest.raises(ValueError,match='closed for final'):
        submit(sample,packet)
    assert budget_usage(task.load(root,ref))==original_budget


def test_new_valid_batch_supersedes_old_stale_coverage(sample):
    task,batch,root,ref = sample
    first = prepare(sample)
    read(sample,first)
    submit(sample,first)
    second = prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    read(sample,second)
    submit(sample,second)
    result = batch.final_coverage(root,task.load(root,ref))
    assert result['unreviewed_paths']==[] and result['stale_paths']==[]
    assert result['path_coverage'][0]['batch_refs']==[second['batch_ref']]


def test_full_worker_launch_profile_is_included_in_shared_context_cost(sample):
    from security_runtime.batch_reviewer import SESSION_ENV, HOOK_STATE_ENV
    task,_,root,ref = sample
    packet = prepare(sample)
    profile = packet['review_handoff']
    assert profile['expected_agent_tools']==['read_security_batch_context']
    assert profile['launch']['environment'][SESSION_ENV]==packet['review_session']
    assert profile['launch']['environment'][HOOK_STATE_ENV]==str(task.hooks.directory.resolve())
    actual = dict(packet)
    actual.pop('review_session')
    assert budget_usage(task.load(root,ref))['context_bytes']==batches._bytes(actual)


@pytest.mark.parametrize('phase',['COMPLETE','NO_CHANGES','INCOMPLETE'])
def test_terminal_task_rejects_late_worker_reads_and_submissions(sample,phase):
    task,batch,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    record = task.load(root,ref)
    original_budget = budget_usage(record)
    record['phase']=phase
    task.store(root).save(record)
    with pytest.raises(ValueError,match='task is terminal'):
        read(sample,packet,'auth.py')
    with pytest.raises(ValueError,match='task is terminal'):
        submit(sample,packet)
    assert batch.get(root,ref)['batches'][0]['batch_ref']==packet['batch_ref']
    assert budget_usage(task.load(root,ref))==original_budget


def test_history_never_exports_session_environment_or_token_echo(sample):
    task,batch,root,ref = sample
    packet = prepare(sample)
    record = task.load(root,ref)
    record['batch_state']['batches'][0]['limitations'].append(
        {'reason':'MODEL_TEXT_ECHO','detail':packet['review_session']})
    task.store(root).save(record)
    result = batch.get(root,ref)
    assert packet['review_session'] not in json.dumps(result)
    assert 'launch' not in json.dumps(result) and 'environment' not in json.dumps(result)


def test_capture_drift_rejects_mixed_checkpoint_without_dispatch(sample,monkeypatch):
    task,batch,root,ref = sample
    actual_capture = batches.capture
    def mutate_after_text_capture(*args,**kwargs):
        snapshot = actual_capture(*args,**kwargs)
        if kwargs.get('include_text',True):
            (root/'auth.py').write_text('def allowed(user):\n    return False\n')
        return snapshot
    monkeypatch.setattr(batches,'capture',mutate_after_text_capture)
    result = prepare(sample)
    assert result['status']=='SNAPSHOT_UNSTABLE'
    assert result['dispatch_required'] is False and 'review_handoff' not in result
    assert 'batch_state' not in task.load(root,ref)
    assert budget_usage(task.load(root,ref))['context_bytes']==0


def test_capture_drift_does_not_replace_running_or_pending_batches(sample,monkeypatch):
    task,batch,root,ref = sample
    first = prepare(sample)
    prepare(sample,'feature-2','def route(user):\n    return service.second(user)\n')
    existing = task.load(root,ref)['batch_state']
    actual_capture = batches.capture
    def mutate_after_text_capture(*args,**kwargs):
        snapshot = actual_capture(*args,**kwargs)
        if kwargs.get('include_text',True):
            (root/'auth.py').write_text('def allowed(user):\n    return False\n')
        return snapshot
    monkeypatch.setattr(batches,'capture',mutate_after_text_capture)
    result = prepare(sample,'feature-3','def route(user):\n    return service.third(user)\n')
    assert result['status']=='SNAPSHOT_UNSTABLE'
    assert task.load(root,ref)['batch_state']==existing
    assert read(sample,first)['location_version']=='BATCH_SNAPSHOT'


def test_method_change_invalidates_review_without_changing_source_snapshot(sample,monkeypatch):
    task,batch,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    submit(sample,packet)
    stored = task.load(root,ref)['batch_state']['batches'][0]
    original_id = stored['snapshot_id']
    assert stored['method_sha256']==packet['quick_skill']['sha256']
    assert stored['review_schema_version']==batches.REVIEW_SCHEMA_VERSION
    newer_method = dict(batches.method(),sha256='a'*64)
    monkeypatch.setattr(batches,'method',lambda:newer_method)
    result = batch.get(root,ref)['batches'][0]
    assert result['validity']=='STALE'
    assert result['snapshot_id']==original_id
    final = batch.final_coverage(root,task.load(root,ref))
    assert final['unreviewed_paths']==['routes.py']
    assert final['reusable_candidates']==[]


def test_candidate_schema_change_invalidates_historical_review(sample,monkeypatch):
    _,batch,root,ref = sample
    packet = prepare(sample)
    read(sample,packet)
    submit(sample,packet)
    monkeypatch.setattr(batches,'REVIEW_SCHEMA_VERSION','batch-review-candidates-v2')
    assert batch.get(root,ref)['batches'][0]['validity']=='STALE'


def test_compact_batch_method_retains_worker_rules_and_parent_policy_binding(monkeypatch):
    from security_runtime.batch_reviewer import REVIEWER_INSTRUCTIONS
    compact = batches.method()
    assert compact['version']=='batch-review-method-v1'
    assert compact['content'].startswith(REVIEWER_INSTRUCTIONS)
    assert len(compact['content'].encode())<4_000
    parent = batches.task_method()
    assert compact['parent_method_sha256']==parent['sha256']
    monkeypatch.setattr(batches,'task_method',lambda:dict(parent,sha256='b'*64))
    assert batches.method()['sha256']!=compact['sha256']


def test_batch_reads_bounded_scanner_history_without_invoking_a_scan(sample):
    task,_,root,ref = sample
    record = task.load(root,ref)
    record['hook_checks']=[dict(scan_id=f'scan-{i}') for i in range(4)]
    task.store(root).save(record)
    calls = []
    def scan_reader(scan_id):
        calls.append(scan_id)
        return dict(target_profile={'path':str(root)},
            findings=[dict(id='outside',file_path='auth.py',evidence='RAW_PRIVATE_EVIDENCE'),
                *[dict(id=f'{scan_id}-{i}',category='authorization',severity='MEDIUM',
                    plain_title='Stored scanner clue',title='Stored scanner clue',
                    file_path='routes.py',line_start=2,line_end=2,evidence='RAW_PRIVATE_EVIDENCE')
                  for i in range(12)]],
            scanner_runs=[dict(scanner='fixture-static',version='0',status='SUCCESS',
                               diagnostic_detail='PRIVATE_DIAGNOSTIC')])
    batch = TaskSecurityBatchService(task,scan_reader=scan_reader)
    packet = prepare((task,batch,root,ref))
    static = packet['static']
    assert calls==['scan-3','scan-2','scan-1']
    assert len(static['findings'])==10
    assert {finding['file_path'] for finding in static['findings']}=={'routes.py'}
    assert static['scanner_runs'][0]==dict(scan_id='scan-3',scanner='fixture-static',version='0',status='SUCCESS')
    assert static['scanner_run'] is False and static['exact_version_verified'] is False
    assert static['history_read_status']=='READ_ONLY_HISTORY'
    assert 'RAW_PRIVATE_EVIDENCE' not in json.dumps(static)
    assert 'PRIVATE_DIAGNOSTIC' not in json.dumps(static)
    actual = dict(packet)
    actual.pop('review_session')
    assert budget_usage(task.load(root,ref))['context_bytes']==batches._bytes(actual)


def test_batch_rejects_foreign_or_unreadable_scan_history_and_preserves_unknown(sample):
    task,batch,root,ref = sample
    record = task.load(root,ref)
    record['hook_checks']=[dict(scan_id='foreign'),dict(scan_id='missing')]
    task.store(root).save(record)
    calls = []
    def scan_reader(scan_id):
        calls.append(scan_id)
        if scan_id=='missing':
            raise OSError('PRIVATE_STORE_DIAGNOSTIC')
        return dict(target_profile={'path':str(root.parent/'other-project')},
            findings=[dict(id='foreign-risk',file_path='routes.py',title='PRIVATE_FOREIGN_FINDING')],
            scanner_runs=[dict(scanner='foreign',version='1',status='SUCCESS')])
    batch = TaskSecurityBatchService(task,scan_reader=scan_reader)
    packet = prepare((task,batch,root,ref))
    static = packet['static']
    assert calls==['missing','foreign']
    assert static['findings']==[] and static['scanner_runs']==[]
    assert static['history_read_status']=='UNKNOWN_NO_ADMITTED_SCAN_RECORDS'
    assert {item['status'] for item in static['history_read_results']}=={'REJECTED_WORKSPACE','UNKNOWN_UNREADABLE'}
    assert 'PRIVATE_' not in json.dumps(static)
    assert static['scanner_run'] is False and static['exact_version_verified'] is False

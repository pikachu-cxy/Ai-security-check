"""The real-host adapter must retain Runtime evidence and version checks."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest
from jsonschema import ValidationError


spec = importlib.util.spec_from_file_location('real_host_runtime',
    Path(__file__).parents[1]/'scripts/real_host_runtime.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

FILES = {'a.js': 'export function run(input) { return Number(input); }\n',
         'auth.js': 'export function allowed(user) { return Boolean(user); }\n'}
UNSAFE = 'export function run(input) { return new Function(input)(); }\n'
FINAL = 'export function run(input) { return String(input); }\n'


@pytest.fixture
def case(tmp_path):
    return bridge.RuntimeCase(tmp_path/'case', FILES)


def response(packet):
    return dict(task_ref=packet['task_ref'], review_session=packet['review_session'],
                findings=[], coverage='REVIEWED', limitations=[])


def integration(packet, evidence):
    return dict(snapshot_id=packet['batch_review']['snapshot_id'], batch_refs=[],
        reviewed_paths=packet['batch_review']['review_scope'], evidence_refs=[evidence],
        checks={k:'Inspected the bounded fixture source.' for k in
            ('authorization', 'data_flow', 'configuration', 'cross_batch_calls')},
        candidate_dispositions=[], limitations=[])


def test_snapshot_reads_stay_bound_and_final_version_is_reconciled(case):
    packet = case.apply_step({'a.js': UNSAFE}, checkpoint='first meaningful change')
    assert packet['dispatch_required']
    assert len(case.runtime.calls) == 1
    case.apply_step({'a.js': FINAL})
    before = case.workspace_fingerprint()
    evidence = case.read_batch_bound(packet, 'a.js', 1, 2)
    assert 'new Function' in str(evidence)
    assert case.workspace_fingerprint() == before
    batch_result = {**response(packet), 'batch_ref': packet['batch_ref']}
    static = case.finish_static()
    assert static is case.finish_static()
    assert len(case.runtime.calls) == 3
    # READY permits an already dispatched worker to drain; prepare closes it.
    assert case.read_batch_bound(packet, 'a.js', 1, 2)['evidence_id']
    case.submit_batch(packet, batch_result)
    assert case.batches.get(case.project, case.task_ref)['batches'][0]['validity'] == 'STALE'
    final = case.finish_prepare_final()
    assert len(case.runtime.calls) == 3  # Two synchronous edit scans plus finish.
    issued = case.read_final_bound('a.js', 1, 2)
    assert 'String' in str(issued)
    assert 'new Function' not in str(issued)
    result = response(final)
    result['integration_review'] = integration(final, issued['evidence_id'])
    submitted = case.submit_final(result)
    assert submitted['status'] == 'COMPLETE'
    receipt = case.receipt()
    assert receipt['source_unchanged']
    assert receipt['task']['current_version']
    assert receipt['batches'][0]['prepare_scanner_calls'] == 0
    assert {r['stage'] for r in receipt['scans']} == {
        'hook_edit_1_1', 'hook_edit_2_1', 'task_finish'}
    with pytest.raises(ValueError, match='terminal|closed'):
        case.read_batch_bound(packet, 'a.js')


def test_baseline_keeps_existing_final_submission_and_no_batches(tmp_path):
    case = bridge.RuntimeCase(tmp_path/'legacy', FILES, side='baseline')
    case.apply_step({'a.js': UNSAFE})
    with pytest.raises(ValueError, match='Baseline'):
        case.prepare_batch('forbidden')
    final = case.finish_prepare_final()
    assert 'batch_review' not in final
    case.read_final_bound('a.js', 1, 2)
    case.submit_final(response(final))
    receipt = case.receipt()
    assert receipt['scan_count'] == 2
    assert receipt['batch_summary'] is None
    assert receipt['final_result']['status'] == 'COMPLETE'


@pytest.mark.parametrize('field', ['task_ref', 'batch_ref', 'review_session'])
def test_parent_rejects_rebinding_model_response_before_service_submit(case, field):
    packet = case.apply_step({'a.js': UNSAFE}, checkpoint='review')
    model = {**response(packet), 'batch_ref': packet['batch_ref']}
    model[field] = 'other-session'
    with pytest.raises(ValidationError):
        case.submit_batch(packet, model)
    assert case.batches.get(case.project, case.task_ref)['batches'][0]['status'] == 'RUNNING'


@pytest.mark.parametrize('name', ['../escape.js', '.git/config', 'C:/escape.js', 'sub\\escape.js'])
def test_fixed_edits_cannot_escape_fixture(case, name):
    before = case.workspace_fingerprint()
    with pytest.raises(ValueError):
        case.apply_step({name:'x'})
    assert case.workspace_fingerprint() == before


def test_final_schema_requires_current_integration_but_legacy_does_not(case):
    case.apply_step({'a.js': UNSAFE}, checkpoint='review')
    final = case.finish_prepare_final()
    model = response(final)
    with pytest.raises(ValidationError, match='integration_review'):
        case.submit_final(model)
    model['integration_review'] = integration(final, 'not-issued')
    with pytest.raises(ValueError, match='current issued evidence'):
        case.submit_final(model)


def test_final_schema_forbids_model_authority_and_stale_bindings(case):
    case.apply_step({'a.js': UNSAFE})
    final = case.finish_prepare_final()
    model = response(final)
    model['scanner_proof'] = True
    with pytest.raises(ValidationError, match='Additional properties'):
        case.submit_final(model)
    model.pop('scanner_proof')
    model['review_session'] = 'invented'
    with pytest.raises(ValidationError):
        case.submit_final(model)


def test_baseline_source_selection_is_checked_before_writes(tmp_path):
    with pytest.raises(ValueError, match='differs'):
        bridge.RuntimeCase(tmp_path/'untouched', FILES, source=tmp_path/'other')
    assert not (tmp_path/'untouched').exists()


def test_finding_schema_matches_runtime_candidate_contract():
    from security_runtime.batch_reviewer import _result_schema
    packet = dict(task_ref='task', batch_ref='batch', review_session='session')

    def without_guidance(value):
        if isinstance(value, dict):
            return {key:without_guidance(item) for key,item in value.items()
                    if key not in {'description', 'pattern'}}
        if isinstance(value, list):
            return [without_guidance(item) for item in value]
        return value

    assert without_guidance(bridge._finding_schema()) == _result_schema(packet)['properties']['findings']['items']


def test_evidence_guidance_rejects_prose_without_constraining_finding_titles():
    from jsonschema import Draft202012Validator
    from security_runtime.batch_reviewer import _result_schema
    packet = dict(task_ref='task', batch_ref='batch', review_session='session')
    batch_fields = bridge.batch_result_schema(packet)['properties']['findings']['items']['properties']
    final_fields = bridge._finding_schema()['properties']
    identifier = 'be1-'+'a'*32
    for fields in (batch_fields, final_fields):
        assert 'exact issued evidence identifier' in fields['task_evidence']['description']
        Draft202012Validator(fields['task_evidence']).validate(identifier)
        Draft202012Validator(fields['title']).validate('Ownership check missing')
        assert 'pattern' not in fields['category']
        with pytest.raises(ValidationError):
            Draft202012Validator(fields['task_evidence']).validate(identifier+' lines 4-6 explain the flow')
    # The source Runtime schema remains unchanged, including its shared short fields.
    assert 'pattern' not in _result_schema(packet)['properties']['findings']['items']['properties']['title']


def test_final_output_schema_limits_reviewed_scope_and_reusable_proof_refs():
    from jsonschema import Draft202012Validator
    packet = dict(task_ref='task', review_session='session', batch_review=dict(
        snapshot_id='snapshot', review_scope=['changed.js'],
        reusable_candidates=[dict(batch_ref='reusable-batch')]))
    fields = bridge.final_result_schema(packet)['properties']['integration_review']['properties']
    assert fields['reviewed_paths']['items']['enum'] == ['changed.js']
    assert fields['batch_refs']['items']['enum'] == ['reusable-batch']
    Draft202012Validator(fields['reviewed_paths']).validate(['changed.js'])
    Draft202012Validator(fields['batch_refs']).validate(['reusable-batch'])
    with pytest.raises(ValidationError):
        Draft202012Validator(fields['reviewed_paths']).validate(['changed.js', 'related.js'])
    with pytest.raises(ValidationError):
        Draft202012Validator(fields['batch_refs']).validate(['historical-stale-batch'])
    assert 'not an inventory' in fields['batch_refs']['description']
    assert 'related unchanged files' in fields['reviewed_paths']['description']


def test_empty_reusable_set_requires_empty_array_in_original_contract():
    from jsonschema import Draft202012Validator
    packet = dict(task_ref='task', review_session='session', batch_review=dict(
        snapshot_id='snapshot', review_scope=['changed.js'], reusable_candidates=[]))
    refs = bridge.final_result_schema(packet)['properties']['integration_review']['properties']['batch_refs']
    Draft202012Validator(refs).check_schema(refs)
    Draft202012Validator(refs).validate([])
    assert refs['maxItems'] == 0
    assert 'return the empty array []' in refs['description']
    with pytest.raises(ValidationError):
        Draft202012Validator(refs).validate(['stale'])

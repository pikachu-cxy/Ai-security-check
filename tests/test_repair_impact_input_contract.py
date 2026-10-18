"""Impact parameter errors stay actionable without reflecting host source text."""
import asyncio
import copy
import json

import pytest
from pydantic import ValidationError

from security_runtime.global_mcp import create_global_server
from security_runtime.repair_impact_contract import impact_failure, impact_input_failure
from security_runtime.repair_impact_models import (
    COVERAGES, KINDS, SOURCE_KINDS, validate_impact_request,
)
from summary_fixtures import sample, snapshot  # noqa: F401
from test_global_integration import structured
from test_repair_impact_mcp import call, make_server


REF = 'ria1-' + 'a' * 32
SECRET = 'source-api-key-must-never-be-returned'


def arguments(name):
    if name == 'prepare_repair_impact':
        return dict(source=dict(kind='HOST_TASK_RISK', task_ref='ts1-original', finding_id='risk-1'),
            proposal=dict(security_goal='Correct access checking.', summary='Retain owner and shared member access.',
                changes=[dict(file_path='app.py', start_line=2, end_line=3, reason='Selected check.')],
                preserve=['Keep explicitly shared member access.']))
    if name == 'submit_repair_impact':
        return dict(assessment_ref=REF,
            impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION', summary='Reject unshared users.',
                          evidence_refs=['ri-evidence-' + 'b' * 32])], unknowns=[])
    if name == 'read_repair_impact_context':
        return dict(assessment_ref=REF, file_path='app.py', start_line=1, end_line=160)
    return dict(assessment_ref=REF, offset=0, limit=10)


@pytest.mark.parametrize('source', [
    dict(kind='SCANNER_TASK_GROUP', task_ref='tg1-original'),
    dict(kind='HOST_TASK_RISK', task_ref='ts1-original', finding_id='risk-1'),
])
def test_source_discriminator_keeps_inherited_text_validation(source):
    data = arguments('prepare_repair_impact')
    data['source'] = source
    request = validate_impact_request('prepare_repair_impact', data)
    assert request.source.model_dump(exclude_unset=True) == source

    data['source'] = dict(source, task_ref=' \t ')
    with pytest.raises(ValidationError) as error:
        validate_impact_request('prepare_repair_impact', data)
    assert any(row['loc'] == ('source', source['kind'], 'task_ref')
               for row in error.value.errors())


@pytest.mark.parametrize('change', [
    lambda data: data['proposal'].update(summary=' \t '),
    lambda data: data['proposal'].update(preserve=['Keep owner access.', ' \t ']),
    lambda data: data['source'].update(task_ref=1),
])
def test_text_validation_remains_nonempty_and_strict(change):
    data = arguments('prepare_repair_impact')
    change(data)
    with pytest.raises(ValidationError):
        validate_impact_request('prepare_repair_impact', data)


def test_public_schema_exposes_source_kind_coverage_business_choice_and_page_limits(sample):
    server = make_server(sample)
    prepare = server._tool_manager.get_tool('prepare_repair_impact').parameters
    source = prepare['properties']['source']
    assert set(source['discriminator']['mapping']) == SOURCE_KINDS
    assert source['discriminator']['propertyName'] == 'kind'
    assert len(source['oneOf']) == 2
    assert prepare['$defs']['ScannerImpactSource']['additionalProperties'] is False
    native = prepare['$defs']['NativeImpactSource']
    assert {'kind', 'task_ref', 'finding_id'} <= set(native['required'])
    changes = prepare['$defs']['RepairImpactProposal']['properties']['changes']
    assert changes['minItems'] == 1 and changes['maxItems'] == 1024

    submit = server._tool_manager.get_tool('submit_repair_impact').parameters
    assert set(submit['properties']['coverage']['enum']) == COVERAGES
    item = submit['$defs']['RepairImpactItem']
    assert item['additionalProperties'] is False
    assert set(item['properties']['kind']['enum']) == KINDS
    assert set(item['required']) == {'kind', 'summary', 'evidence_refs'}
    assert item['properties']['evidence_refs']['minItems'] == 1
    assert item['properties']['evidence_refs']['maxItems'] == 12
    assert submit['properties']['impacts']['maxItems'] == 20
    unknown = submit['$defs']['RepairImpactUnknown']
    assert unknown['properties']['critical']['type'] == 'boolean'
    choice = submit['$defs']['RepairImpactBusinessChoice']
    assert choice['additionalProperties'] is False
    assert choice['properties']['decision']['const'] == 'ACCEPT_PROPOSED_CHANGE'
    assert choice['properties']['user_requested']['const'] is True
    assert choice['properties']['proposal_revision']['pattern'] == '^[a-f0-9]{64}$'

    page = server._tool_manager.get_tool('get_repair_impact').parameters['properties']
    assert page['offset']['minimum'] == 0
    assert page['limit']['minimum'] == 1 and page['limit']['maximum'] == 10
    read = server._tool_manager.get_tool('read_repair_impact_context').parameters['properties']
    assert read['start_line']['minimum'] == 1
    # A long requested obligation is delivered in bounded windows, not rejected.
    assert read['end_line']['maximum'] == 2_147_483_647
    request = validate_impact_request('read_repair_impact_context', arguments('read_repair_impact_context'))
    assert request.end_line == 160


@pytest.mark.parametrize('name,change,field,allowed', [
    ('prepare_repair_impact', lambda a: a['source'].update(kind=SECRET), 'source', SOURCE_KINDS),
    ('submit_repair_impact', lambda a: a['impacts'][0].update(kind=SECRET), 'impacts[0].kind', KINDS),
    ('submit_repair_impact', lambda a: a.update(coverage=SECRET), 'coverage', COVERAGES),
    ('submit_repair_impact', lambda a: a.update(business_choice=dict(user_requested=True,
        proposal_revision='c' * 64, decision=SECRET)), 'business_choice.decision', {'ACCEPT_PROPOSED_CHANGE'}),
])
def test_invalid_enums_return_allowed_values_without_echoing_source(name, change, field, allowed):
    data = arguments(name)
    change(data)
    result = impact_input_failure(name, data)
    assert result['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
    assert not result['repair_authorized'] and not result['source_modified']
    detail = next(row for row in result['field_errors'] if row['field'] == field)
    assert set(detail['allowed_values']) == allowed
    assert detail['correction']
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize('user_requested', [False, 1, 'true', None])
def test_business_choice_requires_a_literal_true_without_coercion(user_requested):
    data = arguments('submit_repair_impact')
    data['business_choice'] = dict(user_requested=user_requested,
        proposal_revision='c' * 64, decision='ACCEPT_PROPOSED_CHANGE')
    result = impact_input_failure('submit_repair_impact', data)
    detail = next(row for row in result['field_errors'] if row['field'] == 'business_choice.user_requested')
    assert detail['allowed_values'] == [True]
    assert 'business_choice' in detail['correction']


@pytest.mark.parametrize('change,field', [
    (lambda a: a['impacts'][0].update(kind='SECURITY_RESTRICTION'), 'impacts[0].kind'),
    (lambda a: a.update(unknowns=[dict(summary='Unknown caller.', critical=1)]), 'unknowns[0].critical'),
    (lambda a: a['impacts'][0].update(evidence_refs=[]), 'impacts[0].evidence_refs'),
])
def test_old_guessed_kind_boolean_coercion_and_empty_evidence_are_not_accepted(change, field):
    data = arguments('submit_repair_impact')
    change(data)
    result = impact_input_failure('submit_repair_impact', data)
    assert any(row['field'] == field for row in result['field_errors'])
    assert not result['repair_authorized']


@pytest.mark.parametrize('offset,limit,expected', [(-1, 10, 'offset'), (0, 11, 'limit'),
                                                (0, 0, 'limit'), (False, 10, 'offset')])
def test_pagination_bounds_are_explicit_and_strict(offset, limit, expected):
    data = dict(assessment_ref=REF, offset=offset, limit=limit)
    result = impact_input_failure('get_repair_impact', data)
    detail = next(row for row in result['field_errors'] if row['field'] == expected)
    assert detail['bounds']['minimum'] == (0 if expected == 'offset' else 1)
    if expected == 'limit':
        assert detail['bounds']['maximum'] == 10


def test_source_variants_do_not_accept_group_subsets_or_caller_snapshot_ids():
    data = arguments('prepare_repair_impact')
    data['source'] = dict(kind='SCANNER_TASK_GROUP', task_ref='tg1-original',
                          finding_id='subset', origin_snapshot_id=SECRET)
    result = impact_input_failure('prepare_repair_impact', data)
    assert any(row['code'] == 'UNSUPPORTED_FIELD' for row in result['field_errors'])
    assert SECRET not in json.dumps(result)
    data['source'] = dict(kind='HOST_TASK_RISK', task_ref='ts1-original')
    result = impact_input_failure('prepare_repair_impact', data)
    assert any(row['field'] == 'source.finding_id' and row['code'] == 'REQUIRED'
               for row in result['field_errors'])


def test_diagnostics_have_a_finite_size_and_hide_unknown_extra_field_names():
    data = arguments('submit_repair_impact')
    data.update({SECRET + str(index): SECRET * 5000 for index in range(100)})
    data['impacts'] = [dict(kind=SECRET, summary=SECRET * 1000, evidence_refs=[SECRET],
                            **{SECRET: SECRET}) for _ in range(20)]
    result = impact_input_failure('submit_repair_impact', data)
    encoded = json.dumps(result, ensure_ascii=False)
    assert 1 <= len(result['field_errors']) <= 6
    assert len(encoded.encode('utf-8')) < 8_000
    assert SECRET not in encoded
    extra_only = arguments('get_repair_impact')
    extra_only[SECRET] = SECRET
    result = impact_input_failure('get_repair_impact', extra_only)
    assert result['field_errors'][0]['field'] == '?'
    assert SECRET not in json.dumps(result)


def test_global_missing_workspace_has_its_own_field_hint():
    result = impact_input_failure('get_repair_impact', arguments('get_repair_impact'), require_workspace=True)
    assert result['field_errors'] == [dict(field='workspace_path', code='REQUIRED',
        correction='全局入口需要当前项目的绝对 workspace_path。')]


def test_global_validation_reports_contract_errors_before_resolving_a_workspace():
    # This sentinel has no workspace-routing methods. Invalid contract input
    # must be diagnosed without admitting a workspace or entering a child.
    server = create_global_server(workspaces=object())
    data = arguments('submit_repair_impact')
    data.update(workspace_path='C:/unresolved-project', coverage=SECRET)
    result = structured(asyncio.run(server.call_tool('submit_repair_impact', data)))
    assert result['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
    assert result['field_errors'][0]['field'] == 'coverage'
    assert set(result['field_errors'][0]['allowed_values']) == COVERAGES
    assert SECRET not in json.dumps(result)
    missing = structured(asyncio.run(server.call_tool('get_repair_impact', arguments('get_repair_impact'))))
    assert missing['field_errors'][0]['field'] == 'workspace_path'


def test_reversed_context_range_has_a_fixed_ordering_hint():
    data = arguments('read_repair_impact_context')
    data.update(start_line=5, end_line=4)
    result = impact_input_failure('read_repair_impact_context', data)
    assert result['field_errors'][0]['bounds']['minimum'] == 1
    assert 'start_line' in result['field_errors'][0]['correction']


def test_semantic_evidence_rejection_has_a_fixed_recovery_hint():
    result = impact_failure('REPAIR_IMPACT_EVIDENCE_INVALID')
    assert result['field_errors'][0]['field'] == 'evidence_refs'
    assert 'evidence_ref' in result['field_errors'][0]['correction']


def test_invalid_sdk_and_direct_inputs_are_rejected_before_service_side_effects(sample, monkeypatch):
    server = make_server(sample)
    before = snapshot(sample[0])
    calls = []
    monkeypatch.setattr('security_runtime.repair_impact.RepairImpactService.submit',
                        lambda *args, **kwargs: calls.append(kwargs))
    data = arguments('submit_repair_impact')
    data.update(workspace_path=str(sample[0]))
    data['impacts'][0]['kind'] = SECRET
    sdk = structured(asyncio.run(server.call_tool('submit_repair_impact', copy.deepcopy(data))))
    direct = call(server, 'submit_repair_impact', **data)
    for result in (sdk, direct):
        assert result['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
        assert result['field_errors'][0]['field'] == 'impacts[0].kind'
        assert set(result['field_errors'][0]['allowed_values']) == KINDS
        assert SECRET not in json.dumps(result)
        assert not result['repair_authorized'] and not result['source_modified']
    assert not calls and snapshot(sample[0]) == before


def test_generic_validation_fallback_does_not_expose_input_or_exception_context():
    data = arguments('get_repair_impact')
    data['limit'] = SECRET
    with pytest.raises(ValidationError) as error:
        validate_impact_request('get_repair_impact', data)
    result = impact_failure(error.value)
    assert SECRET not in json.dumps(result)
    assert result['field_errors'][0]['field'] == 'limit'

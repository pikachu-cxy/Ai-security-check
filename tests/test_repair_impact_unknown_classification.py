"""Unknown classification is evidence-bound, compatible and never repair consent."""
import asyncio
import copy
import json

import pytest
from pydantic import ValidationError

from security_runtime.global_mcp import create_global_server
from security_runtime.repair_impact import RepairImpactService
from security_runtime.repair_impact_contract import impact_input_failure
from security_runtime.repair_impact_models import (
    RepairImpactError, RepairImpactItem, RepairImpactUnknown, reasoning,
    validate_impact_request,
)
from summary_fixtures import sample, snapshot  # noqa: F401
from test_global_integration import structured
from test_repair_impact_mcp import call, make_server
from test_repair_impact_service import SOURCE, impact, prepared, proof  # noqa: F401


REF = 'ria1-' + 'a' * 32
EVIDENCE = 'ri-evidence-' + 'b' * 32
SECRET = 'private-source-token-must-not-appear-in-errors'
CLASSIFICATIONS = {'BLOCKING_CONTEXT', 'SCOPE_LIMITATION'}


def unknown(classification='SCOPE_LIMITATION', *, critical=False, **changes):
    value = dict(summary='The outer error presentation is outside the supplied code.',
        critical=critical, classification=classification,
        decision_basis='The selected local change reuses the existing member policy.',
        evidence_refs=[EVIDENCE])
    value.update(changes)
    return value


def effect(kind='EXPECTED_SECURITY_RESTRICTION', **changes):
    value = dict(kind=kind, summary='Reject users outside the existing member policy.',
                 evidence_refs=[EVIDENCE])
    value.update(changes)
    return value


def arguments(*, unknowns=None, impacts=None):
    return dict(assessment_ref=REF,
        impacts=[effect()] if impacts is None else impacts,
        unknowns=[] if unknowns is None else unknowns)


def invalid_unknowns():
    missing_basis = unknown()
    missing_basis.pop('decision_basis')
    missing_refs = unknown('BLOCKING_CONTEXT', critical=True)
    missing_refs.pop('evidence_refs')
    basis_without_classification = unknown()
    basis_without_classification.pop('classification')
    return [
        pytest.param(unknown(SECRET), id='unsupported-classification'),
        pytest.param(missing_basis, id='classified-basis-required'),
        pytest.param(unknown(decision_basis=None), id='classified-basis-cannot-be-null'),
        pytest.param(unknown(decision_basis=' \t '), id='blank-basis'),
        pytest.param(unknown(decision_basis=42), id='basis-is-strict-text'),
        pytest.param(unknown(decision_basis='x' * 801), id='bounded-basis'),
        pytest.param(basis_without_classification, id='orphan-basis'),
        pytest.param(unknown('SCOPE_LIMITATION', critical=True), id='scope-cannot-be-critical'),
        pytest.param(unknown('BLOCKING_CONTEXT', critical=False), id='blocker-must-be-critical'),
        pytest.param(unknown('BLOCKING_CONTEXT', critical=True, evidence_refs=[]),
                     id='blocker-evidence-required'),
        pytest.param(missing_refs, id='blocker-evidence-cannot-be-omitted'),
    ]


@pytest.mark.parametrize('value', [
    unknown(),
    unknown('BLOCKING_CONTEXT', critical=True),
    unknown(decision_basis='x' * 800),
    dict(summary='Legacy critical context is missing.', critical=True),
    dict(summary='Legacy scope is limited.', critical=False),
])
def test_classified_and_legacy_unknowns_keep_their_explicit_values(value):
    parsed = RepairImpactUnknown.model_validate(value)
    assert parsed.model_dump(exclude_unset=True) == value
    data = arguments(unknowns=[copy.deepcopy(value)])
    request = validate_impact_request('submit_repair_impact', data)
    assert request.unknowns[0].model_dump(exclude_unset=True) == value


@pytest.mark.parametrize('value', invalid_unknowns())
def test_unknown_classification_rejects_inconsistent_or_unexplained_input(value):
    with pytest.raises(ValidationError):
        RepairImpactUnknown.model_validate(value)
    with pytest.raises(ValidationError):
        validate_impact_request('submit_repair_impact', arguments(unknowns=[value]))


@pytest.mark.parametrize('value', invalid_unknowns())
def test_direct_reasoning_enforces_the_same_unknown_contract(value):
    with pytest.raises(RepairImpactError):
        reasoning([effect()], [value], {EVIDENCE: {}})


def test_direct_reasoning_keeps_classification_and_legacy_shape():
    legacy = dict(summary='Legacy unknown remains critical.', critical=True)
    classified = unknown()
    effects, unknowns = reasoning([effect()], [classified, legacy], {EVIDENCE: {}})
    assert effects == [effect()]
    assert unknowns[0] == classified
    assert unknowns[1]['critical'] is True
    assert 'classification' not in unknowns[1]
    assert 'decision_basis' not in unknowns[1]


@pytest.mark.parametrize('value', [
    effect('UNDETERMINED'),
    effect('UNDETERMINED', decision_basis='A required normal path cannot yet be determined.'),
    effect('UNDETERMINED', decision_basis=('Normal operation depends on the missing fact.\n' * 19)[:799] + '.'),
])
def test_undetermined_basis_is_optional_for_legacy_submissions(value):
    assert RepairImpactItem.model_validate(value).model_dump(exclude_unset=True) == value
    result, _ = reasoning([value], [], {EVIDENCE: {}})
    assert result == [value]


@pytest.mark.parametrize('value', [
    effect('EXPECTED_SECURITY_RESTRICTION', decision_basis='This is not an undetermined effect.'),
    effect('NO_ADDITIONAL_CHANGE_IDENTIFIED', decision_basis='This is not an undetermined effect.'),
    effect('BUSINESS_BEHAVIOR_CHANGE', decision_basis='This is not an undetermined effect.'),
    effect('UNDETERMINED', decision_basis=' \t '),
    effect('UNDETERMINED', decision_basis=42),
    effect('UNDETERMINED', decision_basis='x' * 801),
])
def test_effect_basis_cannot_be_misplaced_or_unbounded(value):
    with pytest.raises(ValidationError):
        RepairImpactItem.model_validate(value)
    with pytest.raises(RepairImpactError):
        reasoning([value], [], {EVIDENCE: {}})


def _schema_values(schema, key):
    values = []
    if isinstance(schema, dict):
        if key in schema:
            values.append(schema[key])
        for value in schema.values():
            values.extend(_schema_values(value, key))
    elif isinstance(schema, list):
        for value in schema:
            values.extend(_schema_values(value, key))
    return values


def test_public_schema_describes_additive_classification_without_forcing_legacy_upgrade(sample):
    server = make_server(sample)
    schema = server._tool_manager.get_tool('submit_repair_impact').parameters
    unknown_schema = schema['$defs']['RepairImpactUnknown']
    properties = unknown_schema['properties']
    assert set().union(*map(set, _schema_values(properties['classification'], 'enum'))) == CLASSIFICATIONS
    assert 800 in _schema_values(properties['decision_basis'], 'maxLength')
    assert {'classification', 'decision_basis'}.isdisjoint(unknown_schema['required'])
    item = schema['$defs']['RepairImpactItem']
    assert 'decision_basis' in item['properties']
    assert 'decision_basis' not in item['required']
    assert 800 in _schema_values(item['properties']['decision_basis'], 'maxLength')


@pytest.mark.parametrize('change,field', [
    (dict(classification=SECRET), 'unknowns[0].classification'),
    (dict(decision_basis=SECRET * 100), 'unknowns[0].decision_basis'),
])
def test_classification_field_diagnostics_are_bounded_and_do_not_echo_input(change, field):
    value = unknown(summary=SECRET)
    value.update(change)
    result = impact_input_failure('submit_repair_impact', arguments(unknowns=[value]))
    assert result['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
    detail = next(row for row in result['field_errors'] if row['field'] == field)
    assert detail['correction']
    if field.endswith('.classification'):
        assert set(detail['allowed_values']) == CLASSIFICATIONS
    encoded = json.dumps(result, ensure_ascii=False)
    assert SECRET not in encoded
    assert len(encoded.encode('utf-8')) < 8_000
    assert result['repair_authorized'] is result['source_modified'] is False


@pytest.mark.parametrize('route', ['local-direct', 'local-sdk', 'global-sdk'])
@pytest.mark.parametrize('value', [
    unknown(SECRET, summary=SECRET),
    unknown(summary=SECRET, decision_basis=SECRET * 100),
    unknown('SCOPE_LIMITATION', critical=True, summary=SECRET, decision_basis=SECRET),
])
def test_local_and_global_reject_bad_classification_before_service_or_workspace_side_effects(
        sample, monkeypatch, route, value):
    calls = []
    monkeypatch.setattr(RepairImpactService, 'submit', lambda *args, **kwargs: calls.append(kwargs))
    before = snapshot(sample[0])
    data = arguments(unknowns=[copy.deepcopy(value)])
    data['workspace_path'] = str(sample[0])
    if route == 'global-sdk':
        # No routing API is present: invalid parameters must fail before admission.
        server = create_global_server(workspaces=object())
        result = structured(asyncio.run(server.call_tool('submit_repair_impact', data)))
    else:
        server = make_server(sample)
        if route == 'local-direct':
            result = call(server, 'submit_repair_impact', **data)
        else:
            result = structured(asyncio.run(server.call_tool('submit_repair_impact', data)))
    assert result['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
    assert result['field_errors']
    assert any(row['field'].startswith('unknowns[0]') for row in result['field_errors'])
    assert all(row['correction'] for row in result['field_errors'])
    assert SECRET not in json.dumps(result)
    assert result['repair_authorized'] is result['source_modified'] is False
    assert not calls
    assert snapshot(sample[0]) == before


def _saved(service, ref):
    with service.store.connect() as db:
        record = service.store.load(db, 'assessments', ref)
        cycle = service.store.load(db, 'cycles', record['cycle_id'])
    return record, cycle


@pytest.mark.parametrize('kind,value,gate', [
    ('NO_ADDITIONAL_CHANGE_IDENTIFIED', unknown(), 'READY_FOR_EXISTING_AUTH'),
    ('NO_ADDITIONAL_CHANGE_IDENTIFIED', unknown('BLOCKING_CONTEXT', critical=True),
     'CRITICAL_CONTEXT_MISSING'),
    ('UNDETERMINED', unknown(), 'CRITICAL_CONTEXT_MISSING'),
])
def test_classification_does_not_override_undetermined_or_grant_repair(impact, kind, value, gate):
    service, root, _, _, _, _ = impact
    before_source = (root / 'app.py').read_bytes()
    packet = prepared(impact)
    effects = proof(service, packet, kind=kind)
    if kind == 'UNDETERMINED':
        effects[0]['decision_basis'] = 'A concrete normal path is unresolved in the read evidence.'
    value = dict(value, evidence_refs=effects[0]['evidence_refs'])
    result = service.submit(packet['assessment_ref'], effects, [value])
    assert result['gate'] == gate
    assert result['unknowns'][0]['classification'] == value['classification']
    assert result['unknowns'][0]['decision_basis'] == value['decision_basis']
    if kind == 'UNDETERMINED':
        assert result['impacts'][0]['decision_basis'] == effects[0]['decision_basis']
    assert result['repair_authorized'] is result['automatic_execution'] is False
    assert result['scanner_run'] is result['source_modified'] is False
    assert service.validate_for_fix(packet['assessment_ref'], SOURCE)['gate'] == gate
    assert (root / 'app.py').read_bytes() == before_source


@pytest.mark.parametrize('kind,legacy_unknowns,gate', [
    ('NO_ADDITIONAL_CHANGE_IDENTIFIED', [dict(summary='Legacy critical fact.', critical=True)],
     'CRITICAL_CONTEXT_MISSING'),
    ('NO_ADDITIONAL_CHANGE_IDENTIFIED', [dict(summary='Legacy bounded scope.', critical=False)],
     'READY_FOR_EXISTING_AUTH'),
    ('UNDETERMINED', [], 'CRITICAL_CONTEXT_MISSING'),
])
def test_legacy_history_get_never_reclassifies_migrates_or_renews_authority(
        impact, kind, legacy_unknowns, gate):
    service, root, clock, _, _, resolve = impact
    packet = prepared(impact)
    ref = packet['assessment_ref']
    effects = proof(service, packet, kind=kind)
    service.submit(ref, effects, legacy_unknowns)
    # Emulate the persisted pre-classification shape, signed through the real store.
    with service.store.connect(write=True) as db:
        record = service.store.load(db, 'assessments', ref)
        for row in record['unknowns']:
            row.pop('classification', None)
            row.pop('decision_basis', None)
        for row in record['impacts']:
            row.pop('decision_basis', None)
        service.store.save(db, 'assessments', ref, record, cycle_id=record['cycle_id'])
    before = _saved(service, ref)
    source = (root / 'app.py').read_bytes()
    outsider = RepairImpactService(root, service.store.directory,
        dict(host='codex', session='read-only-history'), resolve, now=lambda: clock[0])
    for reader in (service, outsider):
        view = reader.get(ref, offset=0, limit=10)
        assert view['gate'] == gate
        assert view['repair_authorized'] is view['automatic_execution'] is False
        assert view['scanner_run'] is view['source_modified'] is False
        assert all('classification' not in row and 'decision_basis' not in row
                   for row in view['unknowns'])
        assert all('decision_basis' not in row for row in view['impacts'])
    assert view['owner_matches'] is False
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_OWNER_MISMATCH'):
        outsider.validate_for_fix(ref, SOURCE)
    assert _saved(service, ref) == before
    assert (root / 'app.py').read_bytes() == source


@pytest.mark.parametrize('invalid', [
    unknown('SCOPE_LIMITATION', critical=True),
    unknown('BLOCKING_CONTEXT', critical=True, evidence_refs=['ri-evidence-' + 'f' * 32]),
])
def test_rejected_reclassification_preserves_prior_analysis_and_progress(impact, invalid):
    service, root, _, _, _, _ = impact
    packet = prepared(impact)
    ref = packet['assessment_ref']
    effects = proof(service, packet)
    service.submit(ref, effects, [])
    invalid = copy.deepcopy(invalid)
    if invalid['classification'] == 'SCOPE_LIMITATION':
        # Exercise the contradictory classification itself, not a missing receipt.
        invalid['evidence_refs'] = effects[0]['evidence_refs']
    before = _saved(service, ref)
    source = (root / 'app.py').read_bytes()
    with pytest.raises(RepairImpactError):
        service.submit(ref, effects, [invalid])
    assert _saved(service, ref) == before
    assert service.get(ref)['gate'] == 'READY_FOR_EXISTING_AUTH'
    assert service.get(ref)['repair_authorized'] is False
    assert (root / 'app.py').read_bytes() == source


@pytest.mark.parametrize('condition,gate', [
    ('partial', 'CRITICAL_CONTEXT_MISSING'),
    ('changed-source', 'REASSESS_REQUIRED'),
])
def test_scope_limitation_cannot_bypass_coverage_or_source_freshness(impact, condition, gate):
    service, root, _, _, _, _ = impact
    packet = prepared(impact)
    effects = proof(service, packet)
    value = unknown(evidence_refs=effects[0]['evidence_refs'])
    if condition == 'changed-source':
        (root / 'app.py').write_text('changed = True\n', encoding='utf8')
    result = service.submit(packet['assessment_ref'], effects, [value], coverage='PARTIAL')
    assert result['gate'] == gate
    assert not result['repair_authorized']


@pytest.mark.parametrize('kind,value', [
    ('NO_ADDITIONAL_CHANGE_IDENTIFIED', unknown('BLOCKING_CONTEXT', critical=True,
        summary='Only a scope limitation; this text does not cancel explicit blocking classification.')),
    ('UNDETERMINED', unknown(summary='All prose says ordinary external unknown.')),
])
def test_prose_keywords_never_automatically_downgrade_a_blocker(impact, kind, value):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    effects = proof(service, packet, kind=kind)
    value = dict(value, evidence_refs=effects[0]['evidence_refs'])
    result = service.submit(packet['assessment_ref'], effects, [value])
    assert result['gate'] == 'CRITICAL_CONTEXT_MISSING'
    assert result['repair_authorized'] is False

"""The real-host controller must not give its quality oracle to either model."""
import importlib.util
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('real_host_cases',
    Path(__file__).parents[1] / 'scripts' / 'real_host_cases.py')
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)


def normalized(surface, **overrides):
    return dict(category=surface['category_family'], **surface['locations'][0], **overrides)


def test_same_replay_has_three_bounded_cases_without_oracle_or_waits():
    rows = cases.development_cases()
    assert len(rows) == 3
    for row in rows:
        assert set(row) == {'id', 'title', 'development_task', 'filesinitial', 'steps'}
        assert len(row['filesinitial']) == 3 and len(row['steps']) == 2
        for step in row['steps']:
            assert set(step) == {'checkpoint_key', 'task', 'changes'}
            assert set(step['changes']) <= set(row['filesinitial'])
        serialized = json.dumps(row)
        assert 'expected_findings' not in serialized
        assert 'negative_surfaces' not in serialized
        assert 'sleep' not in serialized
    rows[0]['filesinitial'].clear()
    rows[0]['steps'][0]['changes'].clear()
    assert cases.development_cases()[0]['filesinitial']
    assert cases.development_cases()[0]['steps'][0]['changes']


def test_transient_code_execution_exists_only_before_the_final_numeric_revision():
    before = cases.oracle_for('calculator-input', 'batch1')
    final = cases.oracle_for('calculator-input')
    assert len(before['expected_findings']) == 1
    assert final['expected_findings'] == []
    assert {row['id'] for row in final['negative_surfaces']} == {
        'calculator-final-numeric', 'count-numeric-conversion'}
    trace = next(row for row in cases.development_cases() if row['id'] == 'calculator-input')
    assert 'new Function' in trace['steps'][0]['changes']['calculator.js']
    assert 'new Function' not in trace['steps'][1]['changes']['calculator.js']


def test_cross_batch_raw_reader_needs_the_new_untrusted_caller():
    first = cases.oracle_for('report-download', 'batch1')
    final = cases.oracle_for('report-download')
    assert first['expected_findings'] == []
    assert len(final['expected_findings']) == 1
    expected_paths = {row['file_path'] for row in final['expected_findings'][0]['locations']}
    assert expected_paths == {'file_service.js', 'download_route.js'}


@pytest.mark.parametrize('case_id', ['order-summary', 'report-download'])
def test_location_and_category_match_even_if_title_is_arbitrary(case_id):
    surface = cases.oracle_for(case_id)['expected_findings'][0]
    finding = normalized(surface)
    finding['title'] = 'Completely unrelated wording'
    verdict = cases.evaluate_findings(case_id, [finding])
    assert verdict['screened_expected_match_count'] == 1
    assert verdict['manual_adjudication_required']
    finding['file_path'] = 'unrelated.js'
    finding['title'] = surface['reason']
    mismatch = cases.evaluate_findings(case_id, [finding])
    assert mismatch['screened_expected_match_count'] == 0
    assert mismatch['unmatched_finding_indices'] == [0]


def test_duplicate_evidence_and_safe_controls_are_reported_separately():
    oracle = cases.oracle_for('order-summary')
    positive = normalized(oracle['expected_findings'][0])
    negative = normalized(oracle['negative_surfaces'][0])
    result = cases.evaluate_findings('order-summary', [positive, dict(positive), negative])
    assert result['screened_expected_match_count'] == 1
    assert result['duplicate_finding_indices'] == [1]
    assert result['negative_control_matches'] == [dict(
        finding_index=2, surface_ids=['receipt-owner-scoped'])]


def test_unknown_category_and_unrelated_findings_require_adjudication():
    oracle = cases.oracle_for('order-summary')
    candidate = normalized(oracle['expected_findings'][0])
    candidate['category'] = 'needs context'
    result = cases.evaluate_findings('order-summary', [candidate])
    assert result['screened_expected_match_count'] == 0
    assert result['unmatched_finding_indices'] == [0]
    assert 'false_positive' not in result


@pytest.mark.parametrize('location', [
    {'file_path': '../outside.js', 'line_start': 1},
    {'file_path': 'C:\\outside.js', 'line_start': 1},
    {'file_path': '/outside.js', 'line_start': 1},
    {'file_path': 'order_route.js', 'line_start': True},
    {'file_path': 'order_route.js', 'line_start': 0},
    {'file_path': 'order_route.js', 'line_start': 5, 'line_end': 3},
    {'primary_evidence': 'unresolved-evidence-id'},
])
def test_rejects_unresolved_or_unbounded_locations(location):
    result = cases.evaluate_findings('order-summary', [dict(category='authorization', **location)])
    assert result['malformed_finding_indices'] == [0]
    assert result['screened_expected_match_count'] == 0


@pytest.mark.parametrize('category', ['IDOR', 'broken-access-control', 'CWE-639'])
def test_common_category_aliases_are_normalized(category):
    surface = cases.oracle_for('order-summary')['expected_findings'][0]
    candidate = normalized(surface)
    candidate['category'] = category
    assert cases.evaluate_findings('order-summary', [candidate])['screened_expected_match_count'] == 1


@pytest.mark.parametrize('case_id,stage', [('unknown', 'final'), ('order-summary', 'unknown')])
def test_unknown_case_or_stage_is_rejected(case_id, stage):
    with pytest.raises(ValueError):
        cases.oracle_for(case_id, stage)

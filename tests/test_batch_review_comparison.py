"""Comparison verdicts must reject missing/parity-breaking execution evidence."""
import copy
import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('batch_comparison',
    Path(__file__).parents[1]/'scripts/compare_batch_review.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


@pytest.fixture
def pair():
    row = dict(final_files={'routes.js':'a', 'dynamic.js':'b'}, rules_identity='same',
        scan_count=3, current_version=True, final_review_status='COMPLETE',
        static_final=dict(status='PARTIAL', coverage='PARTIAL', finding_count=1),
        hooks=[dict(scanner_run=True), dict(scanner_run=True)], batches=[],
        scans=[dict(stage='hook_edit_1', scope=['routes.js'], rules=[], scanner_runs=[dict(status='SUCCESS')]),
            dict(stage='hook_edit_2', scope=['dynamic.js'], rules=['ai-security.javascript.dynamic-function'],
                scanner_runs=[dict(status='SUCCESS')]),
            dict(stage='task_finish', scope=['dynamic.js','routes.js'], rules=['ai-security.javascript.dynamic-function'],
                scanner_runs=[dict(status='SUCCESS')])])
    before, after = copy.deepcopy(row), copy.deepcopy(row)
    after['batches'] = [dict(prepare_scanner_calls=0)]
    after['final_integration'] = dict(validation='HOST_REPORTED_NOT_SCANNER_PROOF')
    return before, after


def test_compatible_execution_passes_without_claiming_model_performance(pair):
    result = comparison.assess(*pair)
    assert result['passed']
    assert all(result['checks'].values())
    assert not any('accuracy' in key or 'speedup' in key for key in result['checks'])


@pytest.mark.parametrize('change', ['files','rules','count','scope','finding','async_hook',
    'extra_batch_scan','stale','incomplete','missing_run','failed_run','missing_native_candidate',
    'stage','coverage','missing_integration'])
def test_comparison_rejects_invalid_or_unequal_evidence(pair, change):
    before, after = pair
    if change == 'files': after['final_files']['routes.js'] = 'other'
    elif change == 'rules': after['rules_identity'] = 'other'
    elif change == 'count': after['scan_count'] += 1
    elif change == 'stage': after['scans'][0]['stage'] = 'background_scan'
    elif change == 'coverage': after['static_final']['coverage'] = 'UNKNOWN'
    elif change == 'missing_integration': after['final_integration'] = None
    elif change == 'scope': after['scans'][0]['scope'] = ['auth.js']
    elif change == 'finding': after['scans'][0]['rules'] = ['unexpected-rule']
    elif change == 'async_hook': after['hooks'][0]['scanner_run'] = False
    elif change == 'extra_batch_scan': after['batches'][0]['prepare_scanner_calls'] = 1
    elif change == 'stale': after['current_version'] = False
    elif change == 'incomplete': after['final_review_status'] = 'REVIEWING'
    elif change == 'missing_run': after['scans'][0]['scanner_runs'] = []
    elif change == 'failed_run': after['scans'][0]['scanner_runs'][0]['status'] = 'UNAVAILABLE'
    elif change == 'missing_native_candidate':
        for row in (before, after):
            for scan in row['scans']: scan['rules'] = []
    assert not comparison.assess(before, after)['passed']


def test_fixture_inputs_are_identical_except_for_explicit_edit_sequence():
    assert set(path for path, _ in comparison.EDITS) <= set(comparison.FILES)
    assert len(comparison.EDITS) == 2
    assert 'new Function' not in comparison.FILES['dynamic.js']
    assert 'new Function' in comparison.EDITS[1][1]
    assert 'fixture' in comparison.FIXTURE_LIMITATION.lower()

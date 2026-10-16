"""A changed corpus or truth must never appear as a scanner improvement."""
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('comparison', Path(__file__).resolve().parents[1] / 'scripts/compare_rule_quality.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


def evaluation(path, outcome, *, risk=True, digest='a', complete=True):
    path.mkdir()
    for name, value in {'summary': {'complete': complete}, 'inventory': {'source_hashes': {'case.py': digest}},
        'cases': [{'case_id': 'one', 'relative_file': 'case.py', 'risk': risk, 'group': 'sqli',
                   'cwe': '89', 'split': 'train', 'outcome': outcome}]}.items():
        (path / (name + '.json')).write_text(json.dumps(value))
    return path


def test_comparison_tracks_new_detection(tmp_path):
    before = evaluation(tmp_path / 'before', 'FN')
    after = evaluation(tmp_path / 'after', 'TP')
    result = comparison.compare([before], [after])
    assert result['groups']['sqli']['changed_cases'] == [{'case_id': 'one', 'before': 'FN', 'after': 'TP'}]


@pytest.mark.parametrize('kwargs', [{'risk': False}, {'digest': 'b'}, {'complete': False}])
def test_comparison_rejects_changed_truth_source_or_missing_proof(tmp_path, kwargs):
    before = evaluation(tmp_path / 'before', 'FN')
    after = evaluation(tmp_path / 'after', 'TP', **kwargs)
    with pytest.raises(ValueError): comparison.compare([before], [after])

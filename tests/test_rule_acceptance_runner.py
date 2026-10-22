"""The acceptance gate rejects changed inputs and quality/counting regressions."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('rule_acceptance', Path(__file__).resolve().parents[1]/'scripts/run_rule_acceptance.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def finding(path='risk.py', line=3, category='sql-injection', rule='sql'):
    return dict(file_path=path, line_start=line, category=category, technical_details={'rule_id': rule})


def test_combined_scoring_deduplicates_case_and_category_not_finding_count():
    labels = [dict(case='r', path='risk.py', group='sqli', risk=True),
              dict(case='s', path='safe.py', group='sqli', risk=False)]
    result = gate.score(labels, [finding(), finding(rule='native-sql'), finding(category='xss', path='safe.py')])
    assert result == dict(cases={'r': 'TP', 's': 'TN'}, metrics={'TP': 1, 'FP': 0, 'FN': 0, 'TN': 1})


def test_quality_rejects_lost_tp_even_when_new_tp_keeps_total_constant():
    result = gate.compare_cases({'old': 'TP', 'new': 'FN'}, {'old': 'FN', 'new': 'TP'})
    assert result['lost_true_positives'] == ['old']


def test_quality_rejects_relocated_fp_even_when_fp_count_is_unchanged():
    result = gate.compare_cases({'old': 'FP', 'new': 'TN'}, {'old': 'TN', 'new': 'FP'})
    assert result['added_false_positives'] == ['new']


def test_removed_known_false_positive_is_allowed_without_relaxing_tp():
    project = dict(labels=[dict(case='r', path='risk.py', group='sqli', risk=True),
                           dict(case='s', path='safe.py', group='sqli', risk=False)])
    expected = dict(identities={'semgrep': [['sql', 'risk.py', 3], ['sql', 'safe.py', 3]]},
                    semgrep_cases={'r': 'TP', 's': 'FP'}, combined_cases={'r': 'TP', 's': 'FP'})
    assert gate.compare_quality(project, expected, {'semgrep': [finding()]})['status'] == 'PASS'
    assert gate.compare_quality(project, expected, {'semgrep': []})['status'] == 'FAIL'


def test_unlabelled_new_findings_require_review_not_assumed_true():
    result = gate.compare_quality({}, {'identities': {'semgrep': []}}, {'semgrep': [finding()]})
    assert result['errors'][0]['reason'] == 'UNREVIEWED_NEW_FINDINGS'


def inventory(root):
    (root/'a.py').write_text('x = 1\n')
    (root/'helper.py').write_text('value = 1\n')
    return dict(name='demo', revision='a'*40, files=['a.py'],
        source_hashes={'a.py': hashlib.sha256((root/'a.py').read_bytes()).hexdigest()},
        context_hashes={'helper.py': hashlib.sha256((root/'helper.py').read_bytes()).hexdigest()})


def test_helper_change_cannot_hide_behind_unchanged_target_or_git_revision(tmp_path, monkeypatch):
    manifest = inventory(tmp_path)
    monkeypatch.setattr(gate.subprocess, 'check_output', lambda *a, **k: 'a'*40)
    gate.check_inputs(manifest, tmp_path)
    (tmp_path/'helper.py').write_text('value = request.args\n')
    with pytest.raises(ValueError, match='Corpus bytes changed'):
        gate.check_inputs(manifest, tmp_path)


def test_revision_change_is_not_accepted_with_matching_file_bytes(tmp_path, monkeypatch):
    manifest = inventory(tmp_path)
    monkeypatch.setattr(gate.subprocess, 'check_output', lambda *a, **k: 'b'*40)
    with pytest.raises(ValueError, match='revision changed'):
        gate.check_inputs(manifest, tmp_path)


def test_escaping_context_path_is_rejected(tmp_path, monkeypatch):
    manifest = inventory(tmp_path)
    manifest['context_hashes'] = {'../outside.py': 'a'*64}
    monkeypatch.setattr(gate.subprocess, 'check_output', lambda *a, **k: 'a'*40)
    with pytest.raises(ValueError, match='escapes'):
        gate.check_inputs(manifest, tmp_path)


def timing(seconds, samples=5):
    return dict(status='PASS', manifest_sha256='a', execution={'batch_size': 40},
        projects={'p': {'runs': [{'engine': 'semgrep'}], 'timing': {'semgrep': {
            'median_seconds': seconds, 'version': '1', 'samples': samples}}}})


@pytest.mark.parametrize('changed', ['manifest_sha256', 'execution', 'status'])
def test_performance_refuses_different_inputs_or_incomplete_runs(changed):
    old, new = timing(10), timing(10)
    new[changed] = 'different'
    with pytest.raises(ValueError):
        gate.compare_performance(old, new)


def test_performance_keeps_absolute_and_relative_change_and_sample_limit():
    assert not gate.compare_performance(timing(1), timing(1.2))[0]['review_required']
    assert gate.compare_performance(timing(10, 1), timing(9, 1))[0]['review_required']
    result = gate.compare_performance(timing(10, 3), timing(12, 3))[0]
    assert result['review_required'] and not result['sufficient_samples']
    assert result['delta_seconds'] == 2

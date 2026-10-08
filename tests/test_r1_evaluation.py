"""Evaluation correctness: independent labels, complete coverage and scoring units."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('r1_evaluation', Path(__file__).resolve().parents[1] / 'scripts/r1_evaluation.py')
r1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r1)
PROGRAM = r1.RulePackManager().resolve().program


def finding(cid, line=10):
    return {'id': cid + str(line), 'file_path': 'Case.java', 'line_start': line, 'line_end': line,
            'technical_details': {'capability_id': cid}}


def reference(risk=True, group='JAVA_SQL_INJECTION', **extras):
    return {'case_id': 'known-case', 'relative_file': 'Case.java', 'reference_risk': risk,
            'evaluation_group': group, 'ground_truth_source': {'kind': 'INDEPENDENT_REFERENCE'}, **extras}


def execution(status='SUCCESS', coverage='EXECUTED', rule_ids=None):
    return {'status': status, 'rule_coverage': {'status': coverage, 'scope_files': ['Case.java'],
        'per_language': {'java': {'executed_rule_ids': rule_ids if rule_ids is not None else
            [rid for c in PROGRAM.capabilities for rid in c.underlying_rule_ids]}}}}


@pytest.mark.parametrize('risk,detected,outcome', [(True, True, 'TRUE_POSITIVE'),
    (True, False, 'FALSE_NEGATIVE'), (False, True, 'FALSE_POSITIVE'), (False, False, 'TRUE_NEGATIVE')])
def test_independent_risk_versus_detection(risk, detected, outcome):
    result = r1.match_labels([reference(risk)], [finding('JAVA_SQL_INJECTION')] if detected else [], execution(), PROGRAM)
    assert result[0]['ground_truth_label'] == outcome


@pytest.mark.parametrize('run', [execution('FAILED'), execution(coverage='PARTIAL'), execution(rule_ids=[])])
def test_incomplete_scan_never_becomes_fn_or_tn(run):
    assert r1.match_labels([reference()], [], run, PROGRAM)[0]['ground_truth_label'] == 'UNCERTAIN'


def test_other_capability_is_not_tp_and_synthetic_coordinates_do_not_mask_fn():
    assert r1.match_labels([reference()], [finding('JAVA_SSRF')], execution(), PROGRAM)[0]['ground_truth_label'] == 'FALSE_NEGATIVE'
    assert r1.match_labels([reference(sink_line=30)], [finding('JAVA_SQL_INJECTION', 10)], execution(), PROGRAM)[0]['ground_truth_label'] == 'FALSE_NEGATIVE'


def test_java_sqli_absence_does_not_require_xml_rule_execution():
    java_rules = [rid for c in PROGRAM.capabilities for rid in c.underlying_rule_ids if rid != 'ai-security.java.mybatis-xml']
    assert r1.match_labels([reference()], [], execution(rule_ids=java_rules), PROGRAM)[0]['ground_truth_label'] == 'FALSE_NEGATIVE'


def test_unlabelled_sink_sweep_never_claims_known_fn(tmp_path):
    (tmp_path / 'App.java').write_text('class App { void helper(String url) { new URL(url).openConnection(); }}')
    rows, counts = r1.sink_review_candidates(tmp_path, ['App.java'], [])
    assert counts['JAVA_SSRF'] == 1
    assert rows[0]['ground_truth_label'] == 'GROUND_TRUTH_UNAVAILABLE'
    assert rows[0]['review_status'] == 'UNREVIEWED'


def test_spring_configuration_placeholders_are_not_sql_review_candidates(tmp_path):
    (tmp_path / 'Config.java').write_text('class Config { @Value("${config.endpoint}") String value; }')
    rows, counts = r1.sink_review_candidates(tmp_path, ['Config.java'], [])
    assert rows == [] and not counts


def test_historical_cause_review_never_overwrites_new_outcome():
    case = {'case_id': 'BenchmarkTest00135', 'ground_truth_label': 'TRUE_NEGATIVE',
            'ground_truth_source': {'verified_against_commit': 'b06d6efaebd577a327514364951916e7df3290b4'}}
    document = r1.apply_cause_reviews([case], [])
    assert document['cases'] == []
    assert document['previous_failures_not_reproduced'][0]['current_outcome'] == 'TRUE_NEGATIVE'
    assert case['ground_truth_label'] == 'TRUE_NEGATIVE'


def test_path_primary_and_related_score_one_reference_case():
    rows = [finding('JAVA_ARBITRARY_FILE_READ'), finding('JAVA_PATH_TRAVERSAL')]
    cases = r1.match_labels([reference(group=r1.PATH_GROUP)], rows, execution(), PROGRAM)
    assert r1.metrics(cases)['TP'] == 1
    assert len(cases[0]['matched_findings']) == 2


def test_zero_denominator_is_unknown_and_tiny_sample_explicit():
    assert r1.metrics([])['precision'] is None
    assert r1.metrics([])['recall'] is None
    assert r1.metrics([{'ground_truth_label': 'TRUE_POSITIVE'}])['sample_status'] == 'INSUFFICIENT_SAMPLE'


def test_evidence_hints_never_prove_safety_and_context_is_bounded():
    text = '\n'.join(['ignored'] * 50 + ['if (path.startsWith(base)) sink(path);'] + ['ignored'] * 50)
    hint = r1.evidence(text, r1.GUARD)
    assert not hint['flow_or_safety_proven']
    assert r1.window(text, 51)['end_line'] - r1.window(text, 51)['start_line'] == 6


def test_unsafe_corpus_paths_rejected(tmp_path):
    with pytest.raises(ValueError, match='Unsafe corpus path'):
        r1.safe_file(tmp_path, '../escape.java')

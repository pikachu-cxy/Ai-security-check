"""Evaluation must not turn missing proof, labels or independent scope into success."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('rule_quality', Path(__file__).resolve().parents[1] /
                                               'scripts/rule_quality_evaluation.py')
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)

RULE = SimpleNamespace(rule_id='sql', category='sql-injection', target_extensions=('.py',))
ROW = {'case_id': 'case', 'relative_file': 'testcode/Case.py', 'risk': True, 'group': 'sqli'}
RUN = {'status': 'SUCCESS', 'rule_coverage': {'status': 'EXECUTED',
       'scope_files': ['testcode/Case.py'], 'per_language': {'python': {'executed_rule_ids': ['sql']}}}}


@pytest.mark.parametrize('risk,hit,expected', [(True, True, 'TP'), (True, False, 'FN'),
                                              (False, True, 'FP'), (False, False, 'TN')])
def test_only_same_category_and_file_is_scored(risk, hit, expected):
    findings = [{'file_path': 'testcode/Case.py', 'technical_details': {'rule_id': 'sql'}}] if hit else []
    findings += [{'file_path': 'other.py', 'rule_id': 'sql'},
                 {'file_path': 'testcode/Case.py', 'rule_id': 'unrelated'}]
    assert evaluation.classify(dict(ROW, risk=risk), findings, RUN, [RULE]) == expected


def test_worker_limit_preserves_explicit_file_scope(tmp_path):
    request=SimpleNamespace(rule_pack=SimpleNamespace(path=tmp_path),config_path=tmp_path/'rules.yml',
                            scan_scope=('one.py','two.py'))
    command=evaluation.CappedEvaluationEngine(2).command('semgrep',request)
    assert command[command.index('--jobs')+1]=='2'
    assert command[command.index('--no-git-ignore')+1:]==['one.py','two.py']
    with pytest.raises(ValueError): evaluation.CappedEvaluationEngine(0)


@pytest.mark.parametrize('run,rules', [({'status': 'FAILED'}, [RULE]),
    ({'status': 'SUCCESS', 'rule_coverage': {'status': 'PARTIAL'}}, [RULE]),
    ({'status': 'SUCCESS', 'rule_coverage': {'status': 'EXECUTED', 'scope_files': [],
      'per_language': {'python': {'executed_rule_ids': ['sql']}}}}, [RULE]), (RUN, [])])
def test_unexecuted_or_unscoped_checks_are_uncertain(run, rules):
    assert evaluation.classify(ROW, [], run, rules) == 'UNCERTAIN'


def test_holdout_is_result_independent_and_disjoint():
    ids = [f'BenchmarkTest{i:05d}' for i in range(1, 101)]
    train = {key for key in ids if evaluation.split(key) == 'train'}
    holdout = {key for key in ids if evaluation.split(key) == 'holdout'}
    assert train and holdout and not train & holdout and train | holdout == set(ids)
    assert [evaluation.split(key) for key in ids] == [evaluation.split(key) for key in ids]


def test_invalid_or_duplicate_reference_labels_are_rejected(tmp_path):
    path = tmp_path / 'expectedresults-0.1.csv'
    path.write_text('BenchmarkTest00001,sqli,true,89\nBenchmarkTest00001,sqli,false,89\n')
    with pytest.raises(ValueError, match='duplicate'):
        evaluation.labels(tmp_path, 'python')


def test_escape_is_rejected_and_unknowns_do_not_improve_recall(tmp_path):
    with pytest.raises(ValueError, match='escapes'):
        evaluation.source(tmp_path, '../outside.py')
    result = evaluation.metrics([{'outcome': 'UNCERTAIN'}])
    assert result['UNCERTAIN'] == 1 and result['recall'] is None and result['precision'] is None


def test_reference_reads_are_pinned_to_initial_commit(tmp_path, monkeypatch):
    (tmp_path / 'case.py').write_bytes(b'code\r\n')
    calls = []

    def git(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=b'fixed-revision\n' if 'rev-parse' in argv else b'abc blob 5\ncode\n\n')

    monkeypatch.setattr(evaluation.subprocess, 'run', git)
    assert evaluation.verify_reference(tmp_path, tmp_path, ['case.py']) == 'fixed-revision'
    assert calls[-1][-2:] == ['cat-file', '--batch']


def test_native_flow_requires_source_sink_hash_bound_trace():
    digest = 'a' * 64
    native = {'file_path': ROW['relative_file'], 'scanner_sources': ['native-dataflow'],
        'category': 'sql-injection', 'technical_details': {
            'rule_id': 'ai-security.dataflow.python.sql-injection',
            'analysis_basis': 'BOUNDED_AST_ABSTRACT_INTERPRETATION',
            'context_hashes': {ROW['relative_file']: digest},
            'evidence_locator': {'file_sha256': digest},
            'dataflow_trace': [{'file': ROW['relative_file'], 'line': 1, 'kind': kind} for kind in ('SOURCE', 'SINK')]}}
    assert evaluation.classify(ROW, [native], RUN, [RULE]) == 'TP'
    native['technical_details']['dataflow_trace'].pop()
    assert evaluation.classify(ROW, [native], RUN, [RULE]) == 'FN'

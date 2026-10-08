"""Real Semgrep regression pairs; known FP/FN stay visible as strict xfails."""
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.rulepacks import RulePackManager
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests/corpus/r1/phase2'
CASES = json.loads((CORPUS / 'cases.json').read_text(encoding='utf-8'))['cases']
REVIEWS = {r['case_id']: r for r in json.loads((CORPUS / 'cause-reviews.json').read_text(encoding='utf-8'))['reviews']}
spec = importlib.util.spec_from_file_location('phase2_evaluator', ROOT / 'scripts/r1_evaluation.py')
evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)


@pytest.fixture(scope='module')
def observed():
    manager = RulePackManager()
    context = ScanContext(str(CORPUS), ScanMode.RELEASE, tuple(c['relative_file'] for c in CASES))
    with local_recheck():
        findings, run = SemgrepAdapter(rule_packs=manager).scan(context, FindingNormalizer(CORPUS))
    assert run.status == 'SUCCESS', asdict(run)
    assert run.rule_coverage['status'] == 'EXECUTED', run.rule_coverage
    rows = evaluator.match_labels(CASES, [asdict(f) for f in findings], asdict(run), manager.resolve().program)
    # Required regressions fail the suite if execution or coverage is incomplete.
    assert all(r['ground_truth_label'] != 'UNCERTAIN' for r in rows)
    return {r['case_id']: r for r in rows}


def parameter(case):
    marks = []
    if case['disposition'] == 'KNOWN_ANALYSIS_LIMITATION':
        marks.append(pytest.mark.xfail(strict=True, raises=AssertionError, reason=REVIEWS[case['case_id']]['reason']))
    return pytest.param(case, id=case['case_id'], marks=marks)


@pytest.mark.parametrize('case', [parameter(c) for c in CASES])
def test_source_semantics_against_real_scanner(case, observed):
    expected = 'TRUE_POSITIVE' if case['reference_risk'] else 'TRUE_NEGATIVE'
    assert observed[case['case_id']]['ground_truth_label'] == expected


@pytest.mark.parametrize('changed', ['none', 'root', 'scope', 'bytes'])
def test_phase2_replay_rejects_changed_reference_corpus(tmp_path, monkeypatch, changed):
    from scripts import r1_phase2 as phase2
    root = tmp_path / 'corpus'
    root.mkdir()
    source = root / 'Case.java'
    source.write_text('class Case {}', encoding='utf-8')
    before = tmp_path / 'before'
    before.mkdir()
    saved = {'project_root': str(root.resolve()), 'source_hashes': {'Case.java': evaluator.digest(source)}}
    (before / 'example-scan.json').write_text(json.dumps(saved), encoding='utf-8')
    monkeypatch.setattr(phase2, 'BASE', tmp_path)
    names = ['Case.java']
    if changed == 'root': root = tmp_path
    if changed == 'scope': names = []
    if changed == 'bytes': source.write_text('class Changed {}', encoding='utf-8')
    if changed == 'none':
        phase2.verify_sources(root, names, 'example')
    else:
        with pytest.raises(ValueError): phase2.verify_sources(root, names, 'example')

"""Phase 2 real-engine regression evidence; labels remain independent of results."""
from __future__ import annotations
import argparse
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import sys

if __package__:
    from .r1_evaluation import ROOT, FOCUS, match_labels, metrics, write_json, digest, safe_file, scan
else:
    from r1_evaluation import ROOT, FOCUS, match_labels, metrics, write_json, digest, safe_file, scan
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.rulepacks import RulePackManager, BundledRulePackProvider
from security_runtime.scanners import SemgrepAdapter
from security_runtime.rule_coverage import plan_rules
from security_runtime.verification_policy import local_recheck

BASE = ROOT / 'artifacts/r1/phase2'
CORPUS = ROOT / 'tests/corpus/r1/phase2'


def snapshot():
    target = BASE / 'before'
    if target.exists():
        raise ValueError('Phase 2 before snapshot already exists; never overwrite baseline')
    target.mkdir(parents=True)
    for path in (ROOT / 'artifacts/r1').iterdir():
        if path.is_file(): shutil.copy2(path, target / path.name)
    shutil.copytree(ROOT / 'src/security_runtime/rules', target / 'rules')
    write_json(target / 'snapshot.json', {'rule_pack_checksum': RulePackManager().resolve().checksum,
        'capabilities_sha256': digest(ROOT / 'src/security_runtime/rules/capabilities.json'),
        'purpose': 'Immutable Phase 1 observations and original execution rules; no source changes.'})


def evaluate(tag, pack_path=None):
    output = BASE / tag
    output.mkdir(parents=True, exist_ok=True)
    manager = RulePackManager(BundledRulePackProvider(pack_path)) if pack_path else RulePackManager()
    pack = manager.resolve()
    labels = json.loads((CORPUS / 'cases.json').read_text(encoding='utf-8'))['cases']
    for row in labels:
        row['ground_truth_source'] = {'kind': 'AUTHOR_DECLARED_SYNTHETIC', 'file': 'tests/corpus/r1/phase2/cases.json',
                                     'independent_of_runtime_scanner': True, 'independent_human_review': False}
    context = ScanContext(str(CORPUS), ScanMode.RELEASE, tuple(row['relative_file'] for row in labels))
    with local_recheck():
        findings, run = SemgrepAdapter(rule_packs=manager).scan(context, FindingNormalizer(CORPUS))
    rows, execution = [asdict(f) for f in findings], asdict(run)
    if run.status != 'SUCCESS' or run.rule_coverage['status'] != 'EXECUTED':
        write_json(output / 'scan-failure.json', execution)
        raise ValueError('Regression scanner coverage incomplete')
    results = match_labels(labels, rows, execution, pack.program)
    # Characterizations retain truthful risk labels even when a safe case is an
    # acknowledged engine limitation. They are never relabelled as vulnerable.
    failures = [r for r in results if (r['reference_risk'] and r['ground_truth_label'] != 'TRUE_POSITIVE')
                or (not r['reference_risk'] and r['ground_truth_label'] != 'TRUE_NEGATIVE')]
    unexpected = [r for r in failures if r.get('disposition') != 'KNOWN_ANALYSIS_LIMITATION']
    report = {'tag': tag, 'metrics': {**metrics(results), 'scope': 'SYNTHETIC_PHASE2_REGRESSION',
                                   'unit': 'SYNTHETIC_REGRESSION_CASE'},
              'cases': results, 'scanner_run': execution, 'findings': rows,
              'rule_pack_checksum': pack.checksum, 'unexpected_failures': [r['case_id'] for r in unexpected],
              'known_limitations_observed': [r['case_id'] for r in failures if r.get('disposition') == 'KNOWN_ANALYSIS_LIMITATION']}
    write_json(output / 'minimal-regressions.json', report)
    print(json.dumps({'tag': tag, 'metrics': report['metrics'], 'unexpected_failures': report['unexpected_failures'],
                      'known_limitations_observed': report['known_limitations_observed']}, indent=2), flush=True)
    return report


def benchmark(tag, pack_path=None):
    output = BASE / tag
    output.mkdir(parents=True, exist_ok=True)
    inventory = json.loads((BASE / 'before/inventory.json').read_text(encoding='utf-8'))
    project = next(p for p in inventory['projects'] if p['project_id'] == 'owasp-benchmark')
    root = Path(project['root'])
    labels = json.loads((BASE / 'before/reference-labels.json').read_text(encoding='utf-8'))
    for row in labels:
        if digest(safe_file(root, row['relative_file'])) != row['source_sha256']:
            raise ValueError('Benchmark reference source changed')
    names = [r['relative_file'] for r in labels] + [p for p in project['files'] if '/testcode/' not in p and p.endswith('.java')]
    verify_sources(root, names, 'owasp-benchmark')
    if digest(root / labels[0]['ground_truth_source']['file']) != labels[0]['ground_truth_source']['sha256']:
        raise ValueError('Benchmark CSV changed since Phase 1')
    manager = RulePackManager(BundledRulePackProvider(pack_path)) if pack_path else RulePackManager()
    pack = manager.resolve()
    plan = plan_rules(pack, tuple(names))
    plan = replace(plan, rules=tuple(r for r in plan.rules if pack.program.capability(r.rule_id)
                                    and pack.program.capability(r.rule_id).capability_id in FOCUS))
    context = ScanContext(str(root), ScanMode.RELEASE, tuple(names), rule_plan=plan)
    with local_recheck():
        findings, run = SemgrepAdapter(rule_packs=manager).scan(context, FindingNormalizer(root))
    rows, execution = [asdict(f) for f in findings], asdict(run)
    verify_sources(root, names, 'owasp-benchmark')
    if run.status != 'SUCCESS' or run.rule_coverage['status'] != 'EXECUTED':
        write_json(output / 'benchmark-failure.json', execution)
        raise ValueError('Benchmark execution incomplete')
    results = match_labels(labels, rows, execution, pack.program)
    per = {g: metrics([c for c in results if c['evaluation_group'] == g]) for g in sorted({r['evaluation_group'] for r in labels})}
    old = json.loads((BASE / 'before/case-evaluation.json').read_text(encoding='utf-8'))
    old_map = {c['case_id']: c for c in old}
    changes = [{'case_id': c['case_id'], 'group': c['evaluation_group'], 'before': old_map[c['case_id']]['ground_truth_label'],
                'after': c['ground_truth_label']} for c in results if c['ground_truth_label'] != old_map[c['case_id']]['ground_truth_label']]
    before_metrics = json.loads((BASE / 'before/summary.json').read_text(encoding='utf-8'))['benchmark_metrics']
    delta = {g: {k: per[g][k] - before_metrics[g][k] for k in ('TP', 'FP', 'FN', 'TN')} for g in per}
    report = {'tag': tag, 'rule_pack_checksum': pack.checksum, 'metrics': per, 'delta': delta,
              'changed_cases': changes, 'new_false_positives': [c for c in changes if c['after'] == 'FALSE_POSITIVE'],
              'cases': results, 'findings': rows, 'scanner_run': execution}
    write_json(output / 'benchmark-replay.json', report)
    print(json.dumps({k: report[k] for k in ('tag', 'metrics', 'delta', 'changed_cases', 'new_false_positives')}, indent=2), flush=True)
    return report


def verify_sources(root, names, project):
    saved = json.loads((BASE / 'before' / (project + '-scan.json')).read_text(encoding='utf-8'))
    if saved['project_root'] != str(root.resolve()) or saved['source_hashes'] != {
            name: digest(safe_file(root, name)) for name in names}:
        raise ValueError('Phase 1 corpus root, scope or source bytes changed: ' + project)


def other_projects(tag):
    output = BASE / tag
    output.mkdir(parents=True, exist_ok=True)
    inventory = json.loads((BASE / 'before/inventory.json').read_text(encoding='utf-8'))
    report = {}
    for project in ('jeepay', 'java-benchmarks'):
        entry = next(p for p in inventory['projects'] if p['project_id'] == project)
        root, names = Path(entry['root']), entry['files']
        verify_sources(root, names, project)
        findings, run = scan(root, names, output, project)
        verify_sources(root, names, project)
        report[project] = {'findings': len(findings), 'scanned_files': len(names),
                           'ground_truth': 'UNAVAILABLE' if project == 'jeepay' else 'AUTHOR_DECLARED_SYNTHETIC'}
        if project == 'java-benchmarks':
            labels = json.loads((ROOT / 'tests/corpus/r1/controls.json').read_text(encoding='utf-8'))['cases']
            results = match_labels(labels, findings, run, RulePackManager().resolve().program)
            report[project]['metrics'] = {**metrics(results), 'unit': 'SYNTHETIC_CONTROL_CASE', 'scope': 'SYNTHETIC_CONTROLS'}
            write_json(output / 'synthetic-control-evaluation.json', results)
    write_json(output / 'other-projects.json', report)
    print(json.dumps(report, indent=2), flush=True)
    return report


if __name__ == '__main__':
    if sys.version_info[:2] != (3, 12): raise SystemExit('Use explicit project Python 3.12')
    os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', action='store_true')
    parser.add_argument('--tag', default='minimal-after')
    parser.add_argument('--pack', type=Path)
    parser.add_argument('--benchmark', action='store_true')
    parser.add_argument('--other-projects', action='store_true')
    args = parser.parse_args()
    if args.snapshot: snapshot()
    elif args.other_projects: other_projects(args.tag)
    elif args.benchmark: benchmark(args.tag, args.pack)
    else: evaluate(args.tag, args.pack)

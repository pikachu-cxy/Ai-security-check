"""Reproduce pinned, static-only rule acceptance without executing corpus code.

The manifest contains upstream revisions, source hashes and labels, not sources.
Missing corpora fail preflight; this command never downloads or starts targets.
Use an explicit PYTHONPATH to select the source tree being tested.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time


GROUPS = {
    'sqli': {'sql-injection'},
    'pathtraver': {'path-traversal', 'arbitrary-file-read', 'arbitrary-file-write'},
    'cmdi': {'command-injection'}, 'codeinj': {'code-injection'}, 'xss': {'xss'},
}
BASE = Path(__file__).resolve().parents[1]


def fingerprint(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path.suffix in {'.py', '.yml', '.yaml', '.json'}:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def check_inputs(project, root):
    files = project['files']
    if not files or len(files) > 10000 or len(files) != len(set(files)):
        raise ValueError('Invalid or duplicate corpus targets')
    if set(files) != set(project['source_hashes']):
        raise ValueError('Corpus hash inventory differs from target list')
    if not root.is_dir():
        raise ValueError(f"Missing corpus: {project['name']} ({root})")
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'],
        text=True, timeout=15).strip()
    if revision != project['revision']:
        raise ValueError(f"Corpus revision changed: {project['name']}")
    pinned = {**project.get('context_hashes', {}), **project['source_hashes']}
    for name, expected_hash in pinned.items():
        relative = Path(name)
        path = (root / relative).resolve()
        if relative.is_absolute() or '..' in relative.parts or not path.is_relative_to(root):
            raise ValueError('Corpus target escapes its root')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f"Corpus bytes changed: {project['name']}/{name}")
    labels = project.get('labels', [])
    if len({c['case'] for c in labels}) != len(labels):
        raise ValueError('Duplicate case labels')
    if any(c['path'] not in files or type(c['risk']) is not bool or c['group'] not in GROUPS for c in labels):
        raise ValueError('Invalid case labels')


def identities(findings):
    return {(f['technical_details']['rule_id'], f['file_path'].replace('\\', '/'), f['line_start']) for f in findings}


def score(labels, findings):
    cases = {}
    for case in labels:
        hit = any(f['file_path'].replace('\\', '/') == case['path'] and f['category'] in GROUPS[case['group']]
                  for f in findings)
        cases[case['case']] = ('TP' if case['risk'] else 'FP') if hit else ('FN' if case['risk'] else 'TN')
    return dict(cases=cases, metrics={key: Counter(cases.values())[key] for key in ('TP', 'FP', 'FN', 'TN')})


def compare_cases(before, after):
    if before.keys() != after.keys():
        raise ValueError('Labelled cohort changed')
    return dict(lost_true_positives=sorted(k for k in before if before[k] == 'TP' and after[k] != 'TP'),
                added_false_positives=sorted(k for k in after if after[k] == 'FP' and before[k] != 'FP'))


def compare_quality(project, expected, engines):
    errors = []
    safe_paths = {c['path'] for c in project.get('labels', []) if not c['risk']}
    for name, found in engines.items():
        old, new = {tuple(i) for i in expected['identities'][name]}, identities(found)
        removed = sorted(i for i in old - new if i[1] not in safe_paths)
        if removed:
            errors.append(dict(engine=name, reason='LOST_BASELINE_FINDINGS', identities=removed))
        # Unlabelled project changes require deliberate review, not an assumed TP.
        if not project.get('labels') and new - old:
            errors.append(dict(engine=name, reason='UNREVIEWED_NEW_FINDINGS', identities=sorted(new - old)))
    scores = {}
    if project.get('labels'):
        for name, found in [('semgrep', engines['semgrep']), ('combined', sum(engines.values(), []))]:
            scores[name] = score(project['labels'], found)
            delta = compare_cases(expected[name + '_cases'], scores[name]['cases'])
            if any(delta.values()):
                errors.append(dict(scope=name, reason='QUALITY_REGRESSION', **delta))
    return dict(status='FAIL' if errors else 'PASS', errors=errors, scores=scores)


def compare_performance(before, after):
    """Only compare the same corpus/engines/batching; cold starts stay included."""
    if before['manifest_sha256'] != after['manifest_sha256'] or before['execution'] != after['execution']:
        raise ValueError('Performance inputs or execution settings differ')
    if before['status'] != 'PASS' or after['status'] != 'PASS':
        raise ValueError('Incomplete or failing runs cannot pass performance comparison')
    rows = []
    for name, current in after['projects'].items():
        prior = before['projects'][name]
        if {r['engine'] for r in prior['runs']} != {r['engine'] for r in current['runs']}:
            raise ValueError('Performance engine scope changed')
        for engine in current['timing']:
            old, new = prior['timing'][engine], current['timing'][engine]
            if old['version'] != new['version']:
                # Native model versions can intentionally change; report separately.
                engine_changed = True
            else:
                engine_changed = False
            delta = new['median_seconds'] - old['median_seconds']
            ratio = new['median_seconds'] / old['median_seconds'] - 1 if old['median_seconds'] else None
            enough = old['samples'] >= 5 and new['samples'] >= 5
            rows.append(dict(project=name, engine=engine, before=old, after=new,
                delta_seconds=delta, delta_percent=None if ratio is None else ratio*100,
                engine_version_changed=engine_changed, sufficient_samples=enough,
                review_required=not enough or (ratio is not None and ratio > .10 and delta > 1),
                scope='OBSERVED_WALL_TIME; NOT_ALL_ENGINE_END_TO_END'))
    return rows


def execute(args):
    import security_runtime
    from security_runtime.dataflow import BoundedDataflowScanner
    from security_runtime.dynamic_function import NativeFunctionScanner
    from security_runtime.findings import FindingNormalizer
    from security_runtime.go_sql import GoSQLScanner
    from security_runtime.models import ScanContext, ScanMode
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.scanners import SemgrepAdapter
    from security_runtime.verification_policy import local_recheck

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = json.loads(args.expected.read_bytes())
    if manifest['schema_version'] != 1 or expected['schema_version'] != 1:
        raise ValueError('Unsupported acceptance schema')
    projects = manifest['projects']
    if args.project:
        projects = [p for p in projects if p['name'] in args.project]
        if {p['name'] for p in projects} != set(args.project):
            raise ValueError('Unknown project selection')
    source = Path(security_runtime.__file__).parent
    started_source = fingerprint(source)
    pack = RulePackManager().resolve()
    result = dict(schema_version=1, status='RUNNING', manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        expected_sha256=hashlib.sha256(args.expected.read_bytes()).hexdigest(), source_sha256=started_source,
        rule_pack=dict(version=pack.descriptor.version, checksum=pack.checksum),
        execution=dict(mode='release', batch_size=40, results_reused=False,
                       selected_projects=[p['name'] for p in projects], targets_executed=False), projects={})
    args.output_dir.mkdir(parents=True, exist_ok=False)
    def save():
        (args.output_dir/'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    save()
    try:
        for project in projects:
            check_inputs(project, (args.workspace/project['root']).resolve())
        factories = {'semgrep': SemgrepAdapter, 'native-go-sql': GoSQLScanner,
            'native-js-function': NativeFunctionScanner, 'native-dataflow': lambda: BoundedDataflowScanner(cache=False)}
        for project in projects:
            root = (args.workspace/project['root']).resolve()
            entry = result['projects'][project['name']] = dict(revision=project['revision'], files=len(project['files']), runs=[])
            for index in range(args.repeat):
                engines = {}
                for engine in project['engines']:
                    with local_recheck():
                        start = time.perf_counter()
                        findings, receipt = factories[engine]().scan(
                            ScanContext(str(root), ScanMode.RELEASE, tuple(project['files'])), FindingNormalizer(root))
                        elapsed = time.perf_counter() - start
                    found = [asdict(f) for f in findings]
                    run = dict(engine=engine, repetition=index+1, seconds=elapsed, findings=found, receipt=asdict(receipt))
                    entry['runs'].append(run)
                    save()
                    if receipt.status not in {'SUCCESS', 'PARTIAL'} or (engine == 'semgrep' and receipt.rule_coverage.get('status') != 'EXECUTED'):
                        raise ValueError(f"Incomplete engine execution: {project['name']}/{engine}/{receipt.status}")
                    if receipt.scanner_diagnostics.get('scope', {}).get('scanner_results_reused'):
                        raise ValueError('Unexpected result reuse')
                    baseline_execution = expected['projects'][project['name']].get('execution', {}).get(engine, {})
                    if baseline_execution.get('status') == 'SUCCESS' and receipt.status != 'SUCCESS':
                        raise ValueError('Previously complete engine is now partial')
                    minimum = baseline_execution.get('minimum_parsed_files')
                    if minimum is not None and receipt.scanner_diagnostics.get('parsed_files', 0) < minimum:
                        raise ValueError('Native parsed scope decreased')
                    if receipt.scanner_diagnostics.get('source_stable') is False:
                        raise ValueError('Native source proof changed during analysis')
                    if index and identities(found) != identities(next(r['findings'] for r in entry['runs'] if r['engine'] == engine)):
                        raise ValueError('Finding identities differ between repetitions')
                    engines[engine] = found
                    print(f"{project['name']} {engine} {index+1}/{args.repeat}: {len(found)} findings, {elapsed:.3f}s, {receipt.status}", flush=True)
                entry['quality'] = compare_quality(project, expected['projects'][project['name']], engines)
                if entry['quality']['status'] != 'PASS':
                    raise ValueError(f"Quality regression: {project['name']}")
                check_inputs(project, root)
            entry['timing'] = {}
            for engine in project['engines']:
                runs = [r for r in entry['runs'] if r['engine'] == engine]
                times = [r['seconds'] for r in runs]
                entry['timing'][engine] = dict(samples=len(times), median_seconds=statistics.median(times),
                    minimum_seconds=min(times), maximum_seconds=max(times), version=runs[0]['receipt']['version'])
            save()
        if fingerprint(source) != started_source:
            raise ValueError('Scanner source changed during acceptance; rerun a fixed source tree')
        result['status'] = 'PASS'
        if args.compare:
            result['performance_comparison'] = compare_performance(json.loads(args.compare.read_bytes()), result)
            if any(r['review_required'] for r in result['performance_comparison']):
                result['status'] = 'PERFORMANCE_REVIEW_REQUIRED'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        save()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=BASE/'tests/benchmarks/rule_acceptance.json')
    parser.add_argument('--expected', type=Path, default=BASE/'tests/benchmarks/rule_acceptance_expected.json')
    parser.add_argument('--workspace', type=Path, default=BASE)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--repeat', type=int, choices=range(1, 11), default=1)
    parser.add_argument('--project', action='append')
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args(argv)
    result = execute(args)
    print(json.dumps(dict(status=result['status'], output=str(args.output_dir), error=result.get('error')), ensure_ascii=False))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Read-only corpus evaluation; upstream labels and scanner proof stay separate.

Only the output directory is written. Target applications are never imported,
built or run. Splits are frozen by case identity before any scanner result.
Unlabelled applications produce observations, never precision/recall estimates.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import shutil

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import FIRST_PARTY_RULE_PACK, RulePackManager
from security_runtime.scanners import SemgrepAdapter
from security_runtime.sast import SemgrepEngineProvider
from security_runtime.verification_policy import local_recheck


GROUPS = {
    'sqli': {'sql-injection'}, 'cmdi': {'command-injection'},
    'pathtraver': {'path-traversal', 'arbitrary-file-read', 'arbitrary-file-write'},
    'xss': {'xss'}, 'codeinj': {'code-injection'},
    'deserialization': {'unsafe-deserialization'}, 'xxe': {'xxe'},
    'ssrf': {'ssrf'},
}
SPLIT_VERSION = 'sha256-case-id-mod5-v1'
IGNORED = {'.git', 'node_modules', 'vendor', 'dist', 'build', '__pycache__', 'assets'}


class CappedEvaluationEngine(SemgrepEngineProvider):
    """Bound evaluator CPU concurrency without changing product defaults."""
    def __init__(self, jobs=2):
        if type(jobs) is not int or not 1 <= jobs <= 4: raise ValueError('Invalid evaluator worker limit')
        self.jobs=jobs

    def command(self, executable, request):
        command=super().command(executable,request)
        index=command.index('--no-git-ignore')
        return command[:index]+['--jobs',str(self.jobs)]+command[index:]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split(case_id):
    value = hashlib.sha256(('rule-quality-v1:' + case_id).encode()).digest()
    return 'holdout' if int.from_bytes(value[:8], 'big') % 5 == 0 else 'train'


def source(root, relative):
    path = root / relative
    if (Path(relative).is_absolute() or '..' in Path(relative).parts or
            not path.resolve().is_relative_to(root.resolve()) or
            any(p.is_symlink() or p.is_junction() for p in (path, *path.parents) if p != root and p.is_relative_to(root))):
        raise ValueError('Corpus path escapes root or traverses a link')
    if not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError('Corpus file missing or oversized: ' + relative)
    return path


def labels(root, kind):
    filename = 'expectedresults-0.1.csv' if kind == 'python' else 'expectedresults-1.2.csv'
    rows, seen = [], set()
    for row in csv.reader(source(root, filename).read_text(encoding='utf-8').splitlines()):
        if not row or row[0].startswith('#'):
            continue
        if (len(row) < 4 or not re.fullmatch(r'BenchmarkTest\d{5}', row[0]) or
                row[2] not in {'true', 'false'} or row[0] in seen):
            raise ValueError('Invalid or duplicate upstream label')
        seen.add(row[0])
        name = ('testcode/' + row[0] + '.py' if kind == 'python' else
                'src/main/java/org/owasp/benchmark/testcode/' + row[0] + '.java')
        rows.append({'case_id': row[0], 'relative_file': name, 'group': row[1],
                     'risk': row[2] == 'true', 'cwe': row[3], 'split': split(row[0])})
    return rows, filename


def verify_reference(root, reference, names):
    revision = subprocess.run(['git', '-C', str(reference), 'rev-parse', 'HEAD'],
                              capture_output=True, check=True, timeout=30).stdout.decode().strip()
    # Batch object reads avoid hundreds of process launches on Windows while
    # retaining byte-for-byte comparison against the same pinned revision.
    for start in range(0, len(names), 80):
        batch = names[start:start + 80]
        for name in batch:
            source(root, name)
            if '\n' in name or '\r' in name: raise ValueError('Invalid reference path')
        request = ''.join(revision + ':' + name + '\n' for name in batch).encode()
        raw = subprocess.run(['git', '-C', str(reference), 'cat-file', '--batch'], input=request,
                             capture_output=True, check=True, timeout=30).stdout
        stream = io.BytesIO(raw)
        for name in batch:
            header = stream.readline(256).split()
            if len(header) != 3 or header[1] != b'blob' or not header[2].isdigit() or int(header[2]) > 1_000_000:
                raise ValueError('Missing or oversized pinned Git blob: ' + name)
            expected = stream.read(int(header[2]))
            if stream.read(1) != b'\n' or expected.replace(b'\r\n', b'\n') != source(root, name).read_bytes().replace(b'\r\n', b'\n'):
                raise ValueError('Corpus differs from pinned Git reference: ' + name)
        if stream.read(): raise ValueError('Unexpected Git batch output')
    return revision


def classify(row, findings, run, rules):
    coverage = run.get('rule_coverage', {})
    required = {r.rule_id for r in rules if r.category in GROUPS[row['group']] and
                Path(row['relative_file']).suffix in r.target_extensions}
    executed = {rid for lang in coverage.get('per_language', {}).values()
                for rid in lang.get('executed_rule_ids', [])}
    if (not required or run.get('status') != 'SUCCESS' or coverage.get('status') != 'EXECUTED' or
            row['relative_file'] not in coverage.get('scope_files', []) or not required <= executed):
        return 'UNCERTAIN'
    detected = any(f['file_path'].replace('\\', '/') == row['relative_file'] and
                   (f.get('rule_id', f.get('technical_details', {}).get('rule_id')) in required or
                    valid_flow_finding(row, f))
                   for f in findings)
    return ('TP' if row['risk'] else 'FP') if detected else ('FN' if row['risk'] else 'TN')


def valid_flow_finding(row, finding):
    details = finding.get('technical_details', {})
    trace, hashes = details.get('dataflow_trace', []), details.get('context_hashes', {})
    language = 'java' if row['relative_file'].endswith('.java') else 'python'
    category = finding.get('category')
    return bool(finding.get('scanner_sources') == ['native-dataflow'] and category in GROUPS[row['group']] and
        details.get('analysis_basis') == 'BOUNDED_AST_ABSTRACT_INTERPRETATION' and
        details.get('rule_id') == f'ai-security.dataflow.{language}.{category}' and
        {'SOURCE', 'SINK'} <= {step.get('kind') for step in trace} and
        all(type(step.get('line')) is int and step['line'] > 0 and
            re.fullmatch('[a-f0-9]{64}', hashes.get(step.get('file'), '')) for step in trace) and
        re.fullmatch('[a-f0-9]{64}', hashes.get(row['relative_file'], '')) and
        details.get('evidence_locator', {}).get('file_sha256') == hashes[row['relative_file']])


def metrics(rows):
    count = Counter(r['outcome'] for r in rows)
    result = {key: count[key] for key in ('TP', 'FP', 'FN', 'TN', 'UNCERTAIN')}
    result['precision'] = count['TP'] / (count['TP'] + count['FP']) if count['TP'] + count['FP'] else None
    result['recall'] = count['TP'] / (count['TP'] + count['FN']) if count['TP'] + count['FN'] else None
    return result


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class SnapshotProvider:
    """Validate a retained first-party pack at its own original version."""
    def __init__(self, path):
        self.path = path.resolve()

    def resolve(self, rule_pack_id):
        metadata = json.loads((self.path / 'catalog.json').read_text(encoding='utf-8'))
        if rule_pack_id != FIRST_PARTY_RULE_PACK.rule_pack_id or metadata['rule_pack'] != rule_pack_id:
            raise ValueError('Snapshot pack identity mismatch')
        return RulePackManager._validate(replace(FIRST_PARTY_RULE_PACK, version=metadata['version']), self.path)

    def discover(self):
        return [self.resolve(FIRST_PARTY_RULE_PACK.rule_pack_id)]


def run(args):
    root, output = args.root.resolve(), args.output.resolve()
    if args.kind != 'unlabelled' and getattr(args, 'file_list', None):
        raise ValueError('An explicit file list cannot override an upstream labelled cohort')
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError('Output and external corpus must be separate trees')
    # Existing evidence is immutable: every iteration must use a fresh output.
    output.mkdir(parents=True, exist_ok=False)
    # Concurrent evaluations must never share or repair user-level settings.
    # These environment values live only in this evaluator and its children.
    settings = output / 'semgrep-settings.yml'
    settings.write_text('{}\n', encoding='utf-8')
    os.environ['SEMGREP_SETTINGS_FILE'] = str(settings)
    os.environ['SEMGREP_LOG_FILE'] = str(output / 'semgrep.log')
    manager = RulePackManager(SnapshotProvider(args.pack)) if args.pack else RulePackManager()
    pack = manager.resolve()
    flow_checksum = None
    if args.dataflow:
        from security_runtime import dataflow as dataflow_module
        flow_checksum = dataflow_module.rule_pack().checksum
        implementation = output / 'dataflow-implementation'
        implementation.mkdir()
        for name in ('dataflow.py', 'flow_core.py', 'flow_java.py', 'flow_python.py', 'flow_cache.py'):
            if not (Path(dataflow_module.__file__).parent / name).is_file(): continue
            shutil.copyfile(Path(dataflow_module.__file__).parent / name, implementation / name)
    all_labels, selected = [], []
    if args.kind != 'unlabelled':
        all_labels, csv_name = labels(root, args.kind)
        selected = [r for r in all_labels if r['group'] in args.groups and
                    (args.split == 'all' or r['split'] == args.split)]
        if not selected:
            raise ValueError('No labelled cases selected')
        names = [r['relative_file'] for r in selected]
        revision = verify_reference(root, (args.reference or root).resolve(), [csv_name, *names])
        write(output / 'split-manifest.json', {'version': SPLIT_VERSION, 'upstream_commit': revision,
              'split_unit': 'CASE_ID', 'template_independence': 'NOT_ESTABLISHED',
              'csv_sha256': sha(source(root, csv_name)), 'all_labels': all_labels})
    else:
        file_list = getattr(args, 'file_list', None)
        if file_list:
            names = json.loads(Path(file_list).read_text(encoding='utf-8'))
            if (not isinstance(names, list) or not names or len(names) > 20_000 or
                    not all(isinstance(n, str) and n and '\n' not in n and '\r' not in n for n in names) or
                    len(names) != len(set(names))):
                raise ValueError('Invalid explicit corpus file list')
            names = sorted(names)
        else:
            names = sorted(p.relative_to(root).as_posix() for p in root.rglob('*')
                           if p.suffix in {'.java', '.xml', '.py', '.js', '.jsx', '.ts', '.tsx'} and p.is_file()
                           and not set(p.relative_to(root).parts) & IGNORED)
        for name in names:
            source(root, name)
        revision = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                  capture_output=True, timeout=30).stdout.decode().strip()
    if not names:
        raise ValueError('No eligible corpus files; no successful evaluation can be claimed')
    hashes = {name: sha(source(root, name)) for name in names}
    write(output / 'inventory.json', {'root': str(root), 'commit': revision, 'source_hashes': hashes,
          'kind': args.kind, 'split': args.split, 'rule_pack_version': pack.descriptor.version,
          'rule_pack_checksum': pack.checksum, 'dataflow_checksum': flow_checksum,
          'dataflow_experimental': args.dataflow_experimental, 'target_execution': False,
          'scope_selection': 'EXPLICIT_FILE_LIST' if getattr(args, 'file_list', None) else 'DEFAULT_KIND_SCOPE'})
    adapter, outcomes, observations = SemgrepAdapter(rule_packs=manager,engine_provider=CappedEvaluationEngine(getattr(args,'jobs',2))), [], []
    for start in range(0, len(names), args.batch_size):
        batch = names[start:start + args.batch_size]
        plan = plan_rules(pack, batch)
        if selected:
            categories = set().union(*(GROUPS[r['group']] for r in selected))
            plan = replace(plan, rules=tuple(r for r in plan.rules if r.category in categories))
        context = ScanContext(str(root), ScanMode.RELEASE, tuple(batch), rule_plan=plan)
        with local_recheck():
            found, receipt = adapter.scan(context, FindingNormalizer(root))
        findings, execution = [asdict(f) for f in found], asdict(receipt)
        dataflow = None
        if args.dataflow and any(Path(n).suffix in {'.java', '.py'} for n in batch):
            from security_runtime.dataflow import BoundedDataflowScanner
            flow_found, flow_run = BoundedDataflowScanner(experimental=args.dataflow_experimental).scan(replace(context, rule_plan=None), FindingNormalizer(root))
            dataflow = {'findings': [asdict(f) for f in flow_found], 'run': asdict(flow_run)}
            findings.extend(dataflow['findings'])
        native = None
        if args.kind == 'unlabelled' and any(Path(n).suffix in {'.js', '.ts', '.jsx', '.tsx'} for n in batch):
            native_found, native_run = NativeFunctionScanner().scan(
                replace(context, rule_plan=None), FindingNormalizer(root))
            native = {'findings': [asdict(f) for f in native_found], 'run': asdict(native_run)}
        write(output / f'batch-{start // args.batch_size:03d}.json',
              {'scanner_run': execution, 'findings': findings, 'native_dynamic_code': native, 'bounded_dataflow': dataflow})
        observations.append({'status': receipt.status, 'duration_ms': receipt.duration_ms,
                             'files': len(batch), 'findings': len(findings),
                             'coverage': receipt.rule_coverage.get('status'),
                             'native_status': native['run']['status'] if native else None,
                             'native_findings': len(native['findings']) if native else 0,
                             'dataflow_status': dataflow['run']['status'] if dataflow else None,
                             'dataflow_duration_ms': dataflow['run']['duration_ms'] if dataflow else 0,
                             'dataflow_findings': len(dataflow['findings']) if dataflow else 0})
        outcomes.extend(dict(r, outcome='UNCERTAIN' if dataflow and r['relative_file'] in dataflow['run']['rule_coverage']['failed_files']
                             else classify(r, findings, execution, plan.rules))
                        for r in selected if r['relative_file'] in batch)
        print(json.dumps(observations[-1]), flush=True)
    if hashes != {name: sha(source(root, name)) for name in names}:
        raise ValueError('Corpus mutated during evaluation; results cannot be accepted')
    if args.dataflow and flow_checksum != dataflow_module.rule_pack().checksum:
        raise ValueError('Dataflow implementation changed during evaluation; results cannot be accepted')
    summary = {'kind': args.kind, 'split': args.split, 'files': len(names), 'batches': observations,
               'truth': 'UPSTREAM_BENCHMARK_LABELS' if selected else 'UNAVAILABLE',
               'metrics_unit': 'FILE_AND_VULNERABILITY_CATEGORY; NOT_SINK_OR_PRODUCTION_ACCURACY',
               'limitations': ['Case-ID holdout can share generated templates with development cases.',
                               'Upstream labels retain upstream platform and application assumptions.',
                               'Unlabelled applications cannot establish precision or recall.'],
               'unselected_upstream_categories': dict(Counter(r['group'] for r in all_labels
                                                               if r['group'] not in args.groups)),
               'groups': {group: metrics([r for r in outcomes if r['group'] == group])
                          for group in sorted({r['group'] for r in outcomes})},
               'complete': all(b['status'] == 'SUCCESS' and b['coverage'] == 'EXECUTED' and
                               b['native_status'] in {None, 'SUCCESS'} and
                               b['dataflow_status'] in {None, 'SUCCESS'} for b in observations)}
    write(output / 'cases.json', outcomes)
    write(output / 'summary.json', summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if summary['complete'] else 2


if __name__ == '__main__':
    os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--file-list', type=Path, help='Frozen source-only file list for an unlabelled cohort')
    parser.add_argument('--pack', type=Path, help='Retained validated local first-party rule snapshot')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--kind', choices=('python', 'java', 'unlabelled'), required=True)
    parser.add_argument('--split', choices=('train', 'holdout', 'all'), default='train')
    parser.add_argument('--groups', nargs='+', choices=tuple(GROUPS), default=['sqli', 'pathtraver'])
    parser.add_argument('--batch-size', type=int, default=80)
    parser.add_argument('--jobs',type=int,choices=range(1,5),default=2,help='Evaluator-only Semgrep worker limit')
    parser.add_argument('--dataflow', action='store_true', help='Also execute bounded Java/Python AST analysis')
    parser.add_argument('--dataflow-experimental', action='store_true', help='Include unpromoted command/path candidates for evaluation only')
    arguments = parser.parse_args()
    if not 1 <= arguments.batch_size <= 200:
        parser.error('batch-size must be between 1 and 200')
    raise SystemExit(run(arguments))

"""Offline R1 evaluation tooling. Scanner observations never create reference labels.

Run with Python 3.12 and current checkout on PYTHONPATH. External projects are
read-only; only the requested artifact directory is written. No project builds,
downloads, maturity changes, host integration, or rule edits are performed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, replace
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.rulepacks import RulePackManager
from security_runtime.rule_coverage import plan_rules
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck

ROOT = Path(__file__).resolve().parents[1]
FOCUS = (
    'JAVA_SQL_INJECTION', 'JAVA_COMMAND_INJECTION', 'JAVA_SSRF',
    'JAVA_PATH_TRAVERSAL', 'JAVA_ARBITRARY_FILE_READ', 'JAVA_ARBITRARY_FILE_WRITE',
)
PATH_GROUP = 'PATH_FILE_ACCESS'
GROUPS = {'sqli': 'JAVA_SQL_INJECTION', 'cmdi': 'JAVA_COMMAND_INJECTION', 'pathtraver': PATH_GROUP}
LABELS = {'TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'TRUE_NEGATIVE',
          'UNCERTAIN', 'UNREVIEWED', 'GROUND_TRUTH_UNAVAILABLE'}
TAXONOMY = (
    'CROSS_FUNCTION_FLOW', 'CROSS_FILE_FLOW', 'CUSTOM_WRAPPER', 'UNKNOWN_SANITIZER',
    'FRAMEWORK_ABSTRACTION', 'SOURCE_NOT_MODELED', 'SINK_NOT_MODELED',
    'TYPE_INFORMATION_MISSING', 'CONSTANT_PROPAGATION', 'BUILDER_FLOW',
    'DTO_PROPAGATION', 'PATH_CONTAINMENT', 'DUPLICATE_CAPABILITY_OVERLAP',
    'UNSUPPORTED_LANGUAGE_PATTERN', 'OTHER',
)
SOURCE = re.compile(r'getParameter|getHeader|getCookies|getParameterMap|getParameterValues|getRequestURI|@RequestParam|@RequestBody|@PathVariable')
SINK = re.compile(r'\.execute(?:Query|Update)?\(|prepareCall\(|prepareStatement\(|\.exec\(|ProcessBuilder\(|openConnection\(|getForObject\(|\.exchange\(|FileInputStream\(|FileOutputStream\(|FileReader\(|FileWriter\(|Files\.(?:read|write|delete)|new (?:java\.io\.)?File\(')
GUARD = re.compile(r'startsWith\(|normalize\(|allowlist|allowList|isAllowed|setString\(|encodeForSQL|encodeForOS|validate', re.I)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=30)
    return result.stdout.decode('utf-8', errors='replace').strip() if result.returncode == 0 else ''


def files(root):
    # rg is used for bounded inventory; external trees are never edited.
    result = subprocess.run(['rg', '--files', str(root), '-g', '*.java', '-g', '*.xml'],
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    if result.returncode not in (0, 1):
        raise ValueError('Corpus inventory failed: ' + str(root))
    return sorted(Path(p).relative_to(root).as_posix() for p in result.stdout.splitlines())


def safe_file(root, relative):
    path = root / relative
    if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Unsafe corpus path')
    if not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError('Missing or oversized corpus file')
    return path


def inventory_entry(project, root, source_type, framework, truth, capabilities, note=''):
    names = files(root)
    return {'project_id': project, 'root': str(root), 'source_type': source_type,
            'provenance': {'remote': git(root, 'remote', 'get-url', 'origin'),
                           'head': git(root, 'rev-parse', 'HEAD'),
                           'working_tree_change_count': len(git(root, 'status', '--porcelain').splitlines())},
            'framework': framework, 'java_files': sum(p.endswith('.java') for p in names),
            'xml_files': sum(p.endswith('.xml') for p in names), 'known_ground_truth': truth,
            'capabilities': capabilities, 'note': note, 'files': names}


def benchmark_labels(root, per_class):
    csv_path = root / 'expectedresults-1.2.csv'
    buckets = defaultdict(list)
    for row in csv.reader(csv_path.read_text(encoding='utf-8').splitlines()):
        if not row or row[0].startswith('#') or row[1] not in GROUPS:
            continue
        if row[2] not in ('true', 'false') or not re.fullmatch(r'BenchmarkTest\d{5}', row[0]):
            raise ValueError('Invalid Benchmark reference label')
        relative = 'src/main/java/org/owasp/benchmark/testcode/' + row[0] + '.java'
        path = safe_file(root, relative)
        text = path.read_text(encoding='utf-8')
        if 'class ' + row[0] not in text or '"/' + row[1] + '-' not in text:
            raise ValueError('Reference label/source identity mismatch')
        buckets[(row[1], row[2])].append({'case_id': row[0], 'relative_file': relative,
            'evaluation_group': GROUPS[row[1]], 'reference_risk': row[2] == 'true',
            'reference_cwe': row[3], 'source_sha256': digest(path),
            'ground_truth_source': {'kind': 'UPSTREAM_BENCHMARK_CSV', 'file': csv_path.name,
                                    'sha256': digest(csv_path), 'test_name': row[0],
                                    'independent_of_runtime_scanner': True}})
    selected = []
    for key in sorted(buckets):
        bucket = sorted(buckets[key], key=lambda row: row['case_id'])
        n = min(per_class, len(bucket))
        # Deterministic evenly spaced sampling within each category/risk stratum.
        indices = [round(i * (len(bucket) - 1) / (n - 1)) for i in range(n)] if n > 1 else [0]
        selected.extend(bucket[i] for i in indices)
    return selected, {category + ':' + risk: len(rows) for (category, risk), rows in buckets.items()}


def covered(run, relative, rules):
    cov = run.get('rule_coverage', {})
    executed = {rid for lang in cov.get('per_language', {}).values() for rid in lang.get('executed_rule_ids', [])}
    return (run.get('status') == 'SUCCESS' and cov.get('status') == 'EXECUTED'
            and relative in cov.get('scope_files', []) and set(rules) <= executed)


def match_labels(labels, findings, run, program):
    """Benchmark scores one declared case, never sums unrelated findings per file.

    pathtraver labels describe CWE-22, not independently labelled CWE-200/write
    occurrences. Score their combined group once, preserving primary capabilities
    on scanner records. No per-read/write recall is fabricated.
    """
    cases = []
    catalog = {r.rule_id: r for r in RulePackManager().resolve().catalog}
    for label in labels:
        group = label['evaluation_group']
        caps = set(FOCUS[3:]) if group == PATH_GROUP else {group}
        matched = [f for f in findings if f['file_path'] == label['relative_file']
                   and ('sink_line' not in label or f['line_start'] <= label['sink_line'] <= f['line_end'])
                   and (f['technical_details'].get('capability_id') in caps
                        or caps.intersection(f['technical_details'].get('related_capabilities', [])))]
        extension = Path(label['relative_file']).suffix.lower()
        rules = [rid for c in program.capabilities if c.capability_id in caps for rid in c.underlying_rule_ids
                 if rid in catalog and extension in catalog[rid].target_extensions]
        if not rules or not covered(run, label['relative_file'], rules):
            outcome = 'UNCERTAIN'
        else:
            outcome = ('TRUE_POSITIVE' if matched else 'FALSE_NEGATIVE') if label['reference_risk'] else (
                'FALSE_POSITIVE' if matched else 'TRUE_NEGATIVE')
        cases.append({**label, 'ground_truth_label': outcome, 'matched_findings': [f['id'] for f in matched],
                      'evaluation_unit': 'UPSTREAM_TEST_CASE',
                      'review_status': 'AUTOMATED_REFERENCE_MAPPING' if outcome != 'UNCERTAIN' else 'COVERAGE_INCOMPLETE',
                      'review_reason': 'Independent reference risk versus observed capability group; benchmark-only evidence.',
                      'failure_taxonomy': [], 'taxonomy_status': 'PENDING_CAUSE_REVIEW'})
    return cases


def window(text, line, radius=3):
    lines = text.splitlines()
    start, end = max(1, line - radius), min(len(lines), line + radius)
    # Context is intentionally small and redacted, never an entire source file.
    from security_runtime.diagnostics import sanitize
    return {'start_line': start, 'end_line': end,
            'text': sanitize('\n'.join(f'{i}: {lines[i-1]}' for i in range(start, end + 1)), 1600)}


def evidence(text, pattern):
    from security_runtime.diagnostics import sanitize
    hits = [{'line': n, 'text': sanitize(line.strip(), 220)} for n, line in enumerate(text.splitlines(), 1)
            if pattern.search(line) and not line.lstrip().startswith(('//', '*', 'import '))]
    return {'basis': 'LEXICAL_REVIEW_HINT_ONLY', 'locations': hits[:3], 'truncated': len(hits) > 3,
            'flow_or_safety_proven': False}


def taxonomy_hints(text, outcome):
    # Hints support stratified review; never claim a proven failure root cause.
    tags = []
    if re.search(r'getCookies|getParameterMap|getParameterValues|getRequestURI', text): tags.append('SOURCE_NOT_MODELED')
    if re.search(r'prepareCall|prepareStatement|FileReader|FileWriter|new (?:java\.io\.)?File\(|\.command\(|HttpUtil\.|HttpRequest\.', text): tags.append('SINK_NOT_MODELED')
    if re.search(r'DatabaseHelper\.|doSomething\(|new Test|\.doSomething\(', text): tags += ['CUSTOM_WRAPPER', 'CROSS_FUNCTION_FLOW']
    if re.search(r'(?:helpers|service|dao)\.[\w.]+\(', text, re.I): tags.append('CROSS_FILE_FLOW')
    if re.search(r'StringBuilder|StringBuffer|\.append\(|valuesList\.', text): tags.append('BUILDER_FLOW')
    if re.search(r'getSqlConnection|JdbcTemplate|MyBatis|QueryWrapper|\.lambdaQuery\(', text): tags.append('FRAMEWORK_ABSTRACTION')
    if re.search(r'encodeForSQL|encodeForOS|isAllowed|allowlist', text, re.I): tags.append('UNKNOWN_SANITIZER')
    if re.search(r'startsWith\(|normalize\(', text): tags.append('PATH_CONTAINMENT')
    if outcome == 'FALSE_POSITIVE' and re.search(r'bar\s*=\s*"|param\s*=\s*"|switch\s*\(', text): tags.append('CONSTANT_PROPAGATION')
    return list(dict.fromkeys(tags)) or ['OTHER']


def candidate(root, project, source_type, finding, case=None):
    relative = finding['file_path']
    text = safe_file(root, relative).read_text(encoding='utf-8', errors='replace')
    details = finding['technical_details']
    line = finding['line_start']
    label = case['ground_truth_label'] if case else 'GROUND_TRUTH_UNAVAILABLE'
    return {'case_id': project + ':' + (case['case_id'] if case else finding['id']),
            'project_id': project, 'source_type': source_type, 'relative_file': relative,
            'source_sha256': digest(root / relative), 'record_kind': 'SCANNER_FINDING',
            'capability_id': details.get('capability_id'), 'scanner_rule_id': details.get('rule_id'),
            'scanner_finding_id': finding['id'], 'family_id': finding.get('equivalence_key'),
            'framework': details.get('framework', ''),
            'finding_location': {'start_line': line, 'end_line': finding['line_end']},
            'source_evidence': evidence(text, SOURCE), 'sink_evidence': evidence(text, SINK),
            'sanitizer_evidence': evidence(text, GUARD),
            'dataflow_scope': details.get('detection_evidence', {}).get('dataflow_scope', 'UNKNOWN'),
            'scanner_reason': finding['description'], 'ground_truth_label': label,
            'review_status': case['review_status'] if case else 'UNREVIEWED',
            'review_reason': case['review_reason'] if case else 'No independent real-project label; no TP/FP/recall attribution.',
            'ground_truth_source': case['ground_truth_source'] if case else {'kind': 'UNAVAILABLE'},
            'related_capabilities': details.get('related_capabilities', []),
            'supporting_rule_ids': details.get('supporting_rule_ids', []),
            'code_window': window(text, line),
            'possible_unsafe_basis': 'Scanner match / lexical sources require source-to-sink review.',
            'possible_safe_basis': 'Local guard/binding/constant hints require validation; absence of a hint is not a vulnerability.',
            'provisional_assessment': 'REFERENCE_' + label if case else 'REQUIRES_REVIEW',
            'failure_taxonomy': taxonomy_hints(text, label), 'taxonomy_status': 'PROVISIONAL_LEXICAL_HINTS'}


def missing_candidate(root, project, case):
    text = safe_file(root, case['relative_file']).read_text(encoding='utf-8')
    sinks = evidence(text, SINK)['locations']
    line = sinks[-1]['line'] if sinks else 1
    return {'case_id': project + ':' + case['case_id'], 'project_id': project, 'source_type': 'BENCHMARK',
            'relative_file': case['relative_file'], 'source_sha256': case['source_sha256'], 'record_kind': 'REFERENCE_CASE_WITHOUT_MATCH',
            'capability_id': case['evaluation_group'], 'scanner_rule_id': None,
            'framework': 'Servlet/JDBC/JDK', 'finding_location': None,
            'review_location': {'line': line, 'basis': 'LEXICAL_SINK_HINT'},
            'source_evidence': evidence(text, SOURCE), 'sink_evidence': evidence(text, SINK),
            'sanitizer_evidence': evidence(text, GUARD), 'dataflow_scope': 'NOT_OBSERVED',
            'scanner_reason': 'No capability-group match at the independent reference case/location.',
            'ground_truth_label': case['ground_truth_label'], 'review_status': case['review_status'],
            'review_reason': case['review_reason'], 'ground_truth_source': case['ground_truth_source'],
            'code_window': window(text, line), 'provisional_assessment': 'REFERENCE_' + case['ground_truth_label'],
            'possible_safe_basis': 'Benchmark reference must be challenged independently if disputed.',
            'possible_unsafe_basis': 'Independent reference risk: ' + str(case['reference_risk']),
            'failure_taxonomy': taxonomy_hints(text, case['ground_truth_label']),
            'taxonomy_status': 'PROVISIONAL_LEXICAL_HINTS'}


def metrics(cases):
    counts = Counter(c['ground_truth_label'] for c in cases)
    tp, fp, fn, tn = (counts[k] for k in ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'TRUE_NEGATIVE'))
    return {'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn, 'UNCERTAIN': counts['UNCERTAIN'],
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'unit': 'UPSTREAM_TEST_CASE', 'scope': 'SAMPLED_BENCHMARK_ONLY',
            'sample_status': 'INSUFFICIENT_SAMPLE' if min(tp + fp, tp + fn, fp + tn) < 100 else 'BENCHMARK_ONLY',
            'production_accuracy': 'NOT_ESTABLISHED'}


def apply_cause_reviews(cases, review):
    path = ROOT / 'tests/corpus/r1/cause_reviews.json'
    document = json.loads(path.read_text(encoding='utf-8'))
    by_id = {c['case_id']: c for c in cases}
    applicable, not_sampled, changed = [], [], []
    for cause in document['cases']:
        case = by_id.get(cause['case_id'])
        if case is None:
            not_sampled.append(cause['case_id'])
            continue
        if case['ground_truth_source']['verified_against_commit'] != document['benchmark_reference_commit']:
            raise ValueError('Cause review reference commit mismatch')
        if case['ground_truth_label'] != cause['expected_outcome']:
            changed.append({'case_id': cause['case_id'], 'previous_outcome': cause['expected_outcome'],
                            'current_outcome': case['ground_truth_label']})
            continue
        if set(cause['taxonomy']) - set(TAXONOMY): raise ValueError('Unknown failure taxonomy')
        applicable.append(cause)
        case['failure_taxonomy'] = cause['taxonomy']
        case['taxonomy_status'] = 'SOURCE_REVIEWED_CONTRIBUTING_BOUNDARIES; NOT_ISOLATED_CAUSAL_PROOF'
        for row in review:
            if row['case_id'] == 'owasp-benchmark:' + cause['case_id']:
                row['cause_review'] = {**cause, 'reviewer': document['reviewer'], 'review_method': document['review_method']}
                row['failure_taxonomy'] = cause['taxonomy']
                row['taxonomy_status'] = case['taxonomy_status']
    return {**document, 'cases': applicable, 'not_sampled_case_ids': not_sampled,
            'previous_failures_not_reproduced': changed}


def sink_review_candidates(root, names, findings):
    """Independent lexical sweep of unlabelled OSS. These are NOT known FNs."""
    patterns = {
        'JAVA_SQL_INJECTION': re.compile(r'\$\{[^}]+\}|\.last\(|\.apply\(|\.executeQuery\('),
        'JAVA_COMMAND_INJECTION': re.compile(r'\.exec\(|ProcessBuilder\('),
        'JAVA_SSRF': re.compile(r'openConnection\(|HttpRequest\.|HttpUtil\.|RestTemplate|WebClient|doPostJson\('),
        PATH_GROUP: re.compile(r'FileInputStream\(|FileOutputStream\(|Files\.(?:read|write|delete)'),
    }
    rows, counts, signatures = [], Counter(), set()
    for name in names:
        text = safe_file(root, name).read_text(encoding='utf-8', errors='replace')
        for group, pattern in patterns.items():
            if group == 'JAVA_SQL_INJECTION' and name.endswith('.java'):
                # Spring @Value placeholders are configuration, not SQL sinks.
                pattern = re.compile(r'\.last\(|\.apply\(|\.executeQuery\(|\.executeUpdate\(|\.prepareCall\(')
            hits = [(n, line) for n, line in enumerate(text.splitlines(), 1) if pattern.search(line)
                    and not line.lstrip().startswith(('//', '*', 'import '))
                    and (group != 'JAVA_SQL_INJECTION' or '<mapper' in text or name.endswith('.java'))]
            for line, code in hits:
                if any(f['file_path'] == name and f['line_start'] <= line <= f['line_end'] for f in findings): continue
                counts[group] += 1
                if sum(r['capability_id'] == group for r in rows) >= 3: continue
                api = ('HUTOOL_HTTP' if re.search(r'HttpUtil\.|HttpRequest\.', code) else
                       'HTTP_WRAPPER' if 'doPostJson(' in code else 'JDK_URL' if 'openConnection(' in code else
                       'INHERITED_REQUEST_PATH' if 'getRequestURI' in text else
                       'CONFIG_FILE_READ' if 'getPrivateKeyPath' in code else 'OTHER')
                if (group, api) in signatures: continue
                signatures.add((group, api))
                rows.append({'case_id': f'jeepay:sink-review:{group}:{name}:{line}', 'project_id': 'jeepay',
                    'source_type': 'OSS_UNLABELED', 'relative_file': name, 'source_sha256': digest(root / name),
                    'record_kind': 'UNMATCHED_SINK_REVIEW_CANDIDATE', 'capability_id': group, 'scanner_rule_id': None,
                    'framework': 'Spring / MyBatis-Plus / Hutool / JDK', 'finding_location': None,
                    'review_location': {'line': line, 'basis': 'LEXICAL_SINK_HINT'},
                    'source_evidence': evidence(text, SOURCE), 'sink_evidence': evidence(text, pattern),
                    'sanitizer_evidence': evidence(text, GUARD), 'dataflow_scope': 'NOT_OBSERVED',
                    'scanner_reason': 'No scanner match; selected independently by bounded sink/helper sweep.',
                    'ground_truth_label': 'GROUND_TRUTH_UNAVAILABLE', 'review_status': 'UNREVIEWED',
                    'review_reason': 'Source control and sink reachability must be reviewed; do not count as known FN or safe.',
                    'ground_truth_source': {'kind': 'UNAVAILABLE'}, 'code_window': window(text, line),
                    'possible_unsafe_basis': 'Potential dynamic sink/helper. Input control is not established.',
                    'possible_safe_basis': 'Trusted configuration/fixed endpoint/ORM binding may supply counterevidence.',
                    'provisional_assessment': 'REQUIRES_REVIEW', 'failure_taxonomy': taxonomy_hints(text, 'UNREVIEWED'),
                    'taxonomy_status': 'PROVISIONAL_LEXICAL_HINTS'})
    return rows, dict(counts)


def scan(root, names, output, project):
    source_hashes = {name: digest(safe_file(root, name)) for name in names}
    adapter = SemgrepAdapter()
    context = ScanContext(str(root), ScanMode.RELEASE, tuple(names))
    plan = plan_rules(RulePackManager().resolve(), context.files)
    plan = replace(plan, rules=tuple(r for r in plan.rules if plan.pack.program.capability(r.rule_id)
                                    and plan.pack.program.capability(r.rule_id).capability_id in FOCUS))
    context = replace(context, rule_plan=plan)
    print(f'Scanning {project}: {len(names)} files, {len(plan.rules)} focused rules', flush=True)
    with local_recheck():
        findings, run = adapter.scan(context, FindingNormalizer(root))
    rows, execution = [asdict(f) for f in findings], asdict(run)
    if any(digest(safe_file(root, name)) != value for name, value in source_hashes.items()):
        raise ValueError('Corpus changed during scanner execution')
    write_json(output / (project + '-scan.json'), {'project_root': str(root.resolve()), 'source_hashes': source_hashes,
                                                 'scanner_run': execution, 'findings': rows})
    print(f'{project}: {run.status}, {len(rows)} findings, {run.duration_ms} ms, coverage {run.rule_coverage.get("status")}', flush=True)
    if run.status != 'SUCCESS' or run.rule_coverage.get('status') != 'EXECUTED':
        raise ValueError('Incomplete corpus execution; artifacts retained without completion claim: ' + project)
    return rows, execution


def run(args):
    output = args.output.resolve()
    if any(output.is_relative_to(p.resolve()) for p in (args.jeepay, args.benchmark, args.benchmark_reference)):
        raise ValueError('Outputs must not modify external corpora')
    output.mkdir(parents=True, exist_ok=True)
    pack = RulePackManager().resolve()
    entries = [
        inventory_entry('jeepay', args.jeepay, 'OSS_UNLABELED', 'Spring MVC / MyBatis-Plus / Hutool',
                        'UNAVAILABLE', list(FOCUS), 'Real OSS; no imported synthetic triage labels.'),
        inventory_entry('owasp-benchmark', args.benchmark, 'BENCHMARK', 'Servlet / JDBC / JDK',
                        'expectedresults-1.2.csv', list(GROUPS.values()), 'No SSRF labels. Stratified first-round sample.'),
        inventory_entry('benchmark-reference', args.benchmark_reference, 'BENCHMARK', 'Servlet / JDBC / JDK',
                        'expectedresults-1.2.csv', list(GROUPS.values()), 'Inventory only: local upstream Git reference; no modification.'),
        inventory_entry('java-benchmarks', ROOT / 'samples/java-benchmarks', 'SYNTHETIC', 'JDBC / Spring MVC',
                        'Author annotations; not independent', list(FOCUS), 'Control corpus; not production accuracy.'),
        inventory_entry('rule-program', ROOT / 'tests/rule_program', 'SYNTHETIC', 'JDK / Spring / MyBatis',
                        'corpus.json; author-declared', list(FOCUS), 'Existing R0 regression control.'),
        inventory_entry('triage-jeepay', ROOT / 'tests/triage/fixtures/jeepay', 'SYNTHETIC', 'Reconstructed snippets',
                        'LIKELY_* labels; outside focused capabilities', [], 'Inventory only: no physical Java/XML files.'),
    ]
    labels, available = benchmark_labels(args.benchmark, args.per_class)
    # Verify archive labels and selected sources against locally stored upstream
    # Git objects, without restoring/moving/modifying the Desktop checkout.
    expected = subprocess.run(['git', '-C', str(args.benchmark_reference), 'show', 'HEAD:expectedresults-1.2.csv'],
                              capture_output=True, timeout=30)
    csv_bytes = (args.benchmark / 'expectedresults-1.2.csv').read_bytes()
    normalize = lambda value: value.replace(b'\r\n', b'\n')
    if expected.returncode or normalize(expected.stdout) != normalize(csv_bytes):
        raise ValueError('Archive Benchmark labels do not match local upstream reference')
    for label in labels:
        value = subprocess.run(['git', '-C', str(args.benchmark_reference), 'show', 'HEAD:' + label['relative_file']],
                               capture_output=True, timeout=30)
        if value.returncode or normalize(value.stdout) != normalize((args.benchmark / label['relative_file']).read_bytes()):
            raise ValueError('Selected Benchmark source differs from local upstream: ' + label['case_id'])
        label['ground_truth_source']['verified_against_commit'] = git(args.benchmark_reference, 'rev-parse', 'HEAD')
    inventory = {'schema_version': 'r1-inventory-v1', 'projects': entries,
                 'benchmark_available_labels': available, 'benchmark_selected_cases': len(labels),
                 'sampling': {'method': 'EVENLY_SPACED_WITHIN_CATEGORY_AND_RISK', 'per_stratum': args.per_class},
                 'runtime_head': git(ROOT, 'rev-parse', 'HEAD'), 'rule_pack_checksum': pack.checksum,
                 'python_version': sys.version, 'python_executable': sys.executable}
    write_json(output / 'inventory.json', inventory)
    write_json(output / 'reference-labels.json', labels)
    print(json.dumps([{k: row[k] for k in ('project_id', 'source_type', 'java_files', 'xml_files', 'known_ground_truth')} for row in entries], indent=2), flush=True)
    if args.inventory_only:
        return
    selected = [c['relative_file'] for c in labels]
    # Keep helpers visible to the scanner; they do not become labelled test cases.
    selected += [p for p in entries[1]['files'] if '/testcode/' not in p and p.endswith('.java')]
    observations = {}
    for project, root, names in [('owasp-benchmark', args.benchmark, selected),
                                 ('jeepay', args.jeepay, entries[0]['files']),
                                 ('java-benchmarks', ROOT / 'samples/java-benchmarks', entries[3]['files'])]:
        if args.analysis_only:
            saved = json.loads((output / (project + '-scan.json')).read_text(encoding='utf-8'))
            execution = saved['scanner_run']
            if (execution['status'] != 'SUCCESS' or execution['rule_coverage']['status'] != 'EXECUTED'
                    or set(execution['rule_coverage']['scope_files']) != set(names)
                    or execution['rule_coverage']['rule_pack_checksum'] != pack.checksum
                    or saved.get('project_root') != str(root.resolve())
                    or saved.get('source_hashes') != {name: digest(safe_file(root, name)) for name in names}):
                raise ValueError('Saved scanner scope/version/coverage cannot be replayed')
            observations[project] = saved['findings'], execution
        else:
            observations[project] = scan(root, names, output, project)
    for label in labels:
        if digest(args.benchmark / label['relative_file']) != label['source_sha256']:
            raise ValueError('Benchmark source changed during evaluation')
    findings, execution = observations['owasp-benchmark']
    cases = match_labels(labels, findings, execution, pack.program)
    write_json(output / 'case-evaluation.json', cases)
    control_path = ROOT / 'tests/corpus/r1/controls.json'
    controls = json.loads(control_path.read_text(encoding='utf-8'))['cases']
    for control in controls:
        control['ground_truth_source'] = {'kind': 'AUTHOR_DECLARED_SYNTHETIC', 'file': 'tests/corpus/r1/controls.json',
                                          'sha256': digest(control_path), 'independent_of_runtime_scanner': True,
                                          'independent_human_review': False}
    control_cases = match_labels(controls, observations['java-benchmarks'][0], observations['java-benchmarks'][1], pack.program)
    write_json(output / 'synthetic-control-evaluation.json', control_cases)
    case_map = {c['relative_file']: c for c in cases}
    review = []
    for project, root, kind in [('owasp-benchmark', args.benchmark, 'BENCHMARK'),
                               ('jeepay', args.jeepay, 'OSS_UNLABELED'),
                               ('java-benchmarks', ROOT / 'samples/java-benchmarks', 'SYNTHETIC')]:
        for f in observations[project][0]:
            mapped = case_map.get(f['file_path']) if project == 'owasp-benchmark' else next((c for c in control_cases
                if f['id'] in c['matched_findings']), None) if project == 'java-benchmarks' else None
            # Only map findings in the independently declared capability group.
            if mapped and f['id'] not in mapped['matched_findings']:
                mapped = None
            review.append(candidate(root, project, kind, f, mapped))
    for case in cases:
        if not case['matched_findings']: review.append(missing_candidate(args.benchmark, 'owasp-benchmark', case))
    sink_candidates, sink_counts = sink_review_candidates(args.jeepay, entries[0]['files'], observations['jeepay'][0])
    review.extend(sink_candidates)
    cause_document = apply_cause_reviews(cases, review)
    write_json(output / 'case-evaluation.json', cases)
    write_json(output / 'cause-reviews.json', cause_document)
    (output / 'review-dataset.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in review), encoding='utf-8')
    summary = {'status': 'R1 CORPUS EVALUATION COMPLETE', 'maturity_changes': False, 'rules_modified_by_evaluator': False,
               'benchmark_metrics': {g: metrics([c for c in cases if c['evaluation_group'] == g]) for g in GROUPS.values()},
               'synthetic_control_metrics': {**metrics(control_cases), 'unit': 'AUTHOR_LABELLED_SINK', 'scope': 'SYNTHETIC_CONTROL_ONLY'},
               'unmatched_oss_sink_hints': sink_counts,
               'scanner_counts': {}, 'per_capability': {}, 'unreviewed': sum(r['review_status'] == 'UNREVIEWED' for r in review),
               'uncertain_cases': sum(c['ground_truth_label'] == 'UNCERTAIN' for c in cases),
               'ground_truth_unavailable_records': sum(r['ground_truth_label'] == 'GROUND_TRUTH_UNAVAILABLE' for r in review),
               'source_reviewed_failure_cases': len(cause_document['cases']),
               'source_reviewed_taxonomy_frequency': dict(Counter(t for c in cause_document['cases'] for t in c['taxonomy'])),
               'overlap': {}, 'taxonomy_hint_frequency': {},
               'limits': ['Lexical taxonomy hints are not confirmed causal diagnoses.',
                          'Benchmark case counts and scanner occurrence counts are different units.',
                          'Path labels score a combined group, not independent read/write ground truth.',
                          'No OSS-unlabelled recall; synthetic controls excluded from real-world metrics; no SSRF benchmark recall.',
                          'Evenly spaced small benchmark sample is not production accuracy.',
                          'Scanner source locations are not exported; lexical hints are not observed dataflow.']}
    for project, (rows, run_row) in observations.items():
        summary['scanner_counts'][project] = dict(Counter(f['technical_details']['capability_id'] for f in rows))
        primary = [f for f in rows if f['technical_details'].get('related_capabilities')]
        duplicate = 0
        by_sink = defaultdict(list)
        for f in rows:
            if f['technical_details']['capability_id'] in FOCUS[3:]:
                by_sink[(f['file_path'], f['line_start'], f['line_end'])].append(f)
        duplicate = sum(len(v) - 1 for v in by_sink.values() if len(v) > 1)
        summary['overlap'][project] = {'primary_with_traversal_related': len(primary),
            'additional_primary_records_at_same_range': duplicate,
            'interpretation': 'Review distinct read/write operations before calling these duplicate noise.'}
    for cid in FOCUS:
        rows = [(p, f) for p, (fs, _) in observations.items() for f in fs if f['technical_details']['capability_id'] == cid]
        reviewed = [r for r in review if r['capability_id'] == cid and r['source_type'] != 'SYNTHETIC']
        summary['per_capability'][cid] = {'projects': len(observations), 'projects_with_findings': len({p for p, f in rows}),
            'files_scanned': sum(sum(Path(name).suffix.lower() == '.java' or cid == 'JAVA_SQL_INJECTION'
                                   for name in run['rule_coverage']['scope_files']) for _, run in observations.values()),
            'files_with_findings': len({(p, f['file_path']) for p, f in rows}), 'scanner_findings': len(rows),
            'unique_families': len({(p, f['equivalence_key']) for p, f in rows}),
            'reviewed_TP': sum(r['ground_truth_label'] == 'TRUE_POSITIVE' for r in reviewed),
            'reviewed_FP': sum(r['ground_truth_label'] == 'FALSE_POSITIVE' for r in reviewed),
            'review_method': 'UPSTREAM_REFERENCE_MAPPING; HUMAN_REVIEW_COUNT_ZERO',
            'UNREVIEWED': sum(r['review_status'] == 'UNREVIEWED' for r in reviewed),
            'UNCERTAIN': sum(r['ground_truth_label'] == 'UNCERTAIN' for r in reviewed),
            'known_FN': summary['benchmark_metrics'].get(cid, {}).get('FN'),
            'known_TN': summary['benchmark_metrics'].get(cid, {}).get('TN'),
            'precision_recall_evidence': 'SEE_BENCHMARK_CASE_METRICS' if cid in GROUPS.values() else 'GROUND_TRUTH_UNAVAILABLE_AT_CAPABILITY_LEVEL'}
    failures = [r for r in review if r['ground_truth_label'] in ('FALSE_POSITIVE', 'FALSE_NEGATIVE')
                and r['taxonomy_status'] == 'PROVISIONAL_LEXICAL_HINTS']
    summary['taxonomy_hint_frequency'] = dict(Counter(t for r in failures for t in r['failure_taxonomy']))
    write_json(output / 'summary.json', summary)
    # Select a small review queue per outcome/group/taxonomy signature.
    queues = defaultdict(list)
    for row in review:
        key = (row['project_id'], row['capability_id'], row['ground_truth_label'], tuple(row['failure_taxonomy']))
        queues[key].append(row)
    compact = []
    for key in sorted(queues):
        compact.extend(queues[key][:2])
    # A reviewer receives at most 24 initial records, balanced across projects,
    # capabilities and outcomes; the complete dataset stays machine-readable.
    strata = defaultdict(list)
    for row in compact:
        strata[(row['project_id'], row['capability_id'], row['ground_truth_label'])].append(row)
    compact = []
    while strata and len(compact) < 24:
        for key in sorted(list(strata)):
            compact.append(strata[key].pop(0))
            if not strata[key]: del strata[key]
            if len(compact) == 24: break
    write_json(output / 'review-queue.json', compact)
    text = ['# R1 corpus review queue', '',
            'Full machine dataset: review-dataset.jsonl. Initial queue: at most 24 balanced representative records.',
            'Ground truth and lexical hints remain separate. Benchmark outcomes are reference-mapped, not independent human review.', '']
    for row in compact:
        text += [f"## {row['case_id']} — {row['ground_truth_label']}", '',
                 f"{row['capability_id']} | {row['relative_file']} | {row['framework']}",
                 f"Taxonomy hints: {', '.join(row['failure_taxonomy'])}", '', '```java', row['code_window']['text'], '```', '',
                 row['review_reason'], '']
    (output / 'review-queue.md').write_text('\n'.join(text), encoding='utf-8')
    report = ['# R1 CORPUS EVALUATION COMPLETE', '',
        'Local offline evidence only. No production accuracy or maturity promotion.', '',
        '| Corpus | Type | Java | XML | Scanned files | SQLi | Command | SSRF | Path/File |',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for row in entries:
        project = row['project_id']
        fs, execution = observations.get(project, ([], {}))
        counts = summary['scanner_counts'].get(project, {})
        report.append(f"| {project} | {row['source_type']} | {row['java_files']} | {row['xml_files']} | "
            f"{execution.get('rule_coverage', {}).get('total_files', 'inventory only')} | "
            f"{counts.get(FOCUS[0], 0)} | {counts.get(FOCUS[1], 0)} | {counts.get(FOCUS[2], 0)} | {sum(counts.get(c, 0) for c in FOCUS[3:])} |")
    report += ['', 'Benchmark source and CSV labels verified against local reference commit ' + git(args.benchmark_reference, 'rev-parse', 'HEAD') + '.',
        f'Benchmark: {len(labels)} labelled cases + {len(selected)-len(labels)} Java helpers; up to {args.per_class} risky and {args.per_class} safe cases per SQLi, command and path group. No SSRF labels.',
        f"Jeepay: all {entries[0]['java_files']} Java + {entries[0]['xml_files']} XML files. Zero findings is not an absence/safety proof for unmodelled flows.", '',
        '| Benchmark group | TP | FP | FN | TN | UNCERTAIN | Precision | Recall |',
        '|---|---:|---:|---:|---:|---:|---|---|']
    for group, m in summary['benchmark_metrics'].items():
        report.append(f"| {group} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | {m['UNCERTAIN']} | "
            f"{m['TP']}/{m['TP']+m['FP']} | {m['TP']}/{m['TP']+m['FN']} |")
    report += ['', 'All groups: INSUFFICIENT_SAMPLE. These are independent upstream test-case labels, not production distributions or independent human reviews.',
        'Path/File is scored once per upstream CWE-22 case; read/write occurrence labels are not independently established.',
        'Synthetic controls are scored separately; see synthetic-control-evaluation.json. Existing R0 focused tests are regression controls only.', '',
        f"UNREVIEWED records: {summary['unreviewed']}. GROUND_TRUTH_UNAVAILABLE records: {summary['ground_truth_unavailable_records']}. "
        f"UNCERTAIN benchmark cases: {summary['uncertain_cases']}.",
        'Unmatched Jeepay sink hints were selected independently of findings; they are NOT known FNs. No fake Jeepay or SSRF recall is calculated.', '',
        '## Source-reviewed failure evidence', '',
        f"{len(cause_document['cases'])} representative failure cases have applicable source reviews by Codex. Historical reviews that no longer reproduce are recorded separately. These are contributing boundaries, not isolated engine-cause experiments.", '']
    for cause in cause_document['cases']:
        report.append(f"- {cause['case_id']} / {cause['expected_outcome']} / {', '.join(cause['taxonomy'])}: {cause['reason']}")
    report += ['', '## Wrapper and abstraction boundaries', '',
        'An argument-to-return taint assumption can report helpers that actually return constants or safe list elements. Conversely, interface factories and helper-declared types can break typed sink matching and inter-file flow. These are different problems and must not be treated as one broad wrapper rule.',
        'Jeepay AbstractCtrl injects request and routes parameter JSON through RequestKitBean. StaticController reads a path built from inherited request.getRequestURI. YsfHttpUtil accepts URLs through helpers. Deployment/path routing, input control and configuration allowlists remain unproven.',
        'MyBatis-Plus ew.sqlSegment is builder-generated SQL; interpolation alone does not establish user-controlled SQL injection. It stays GROUND_TRUTH_UNAVAILABLE.', '',
        '## Overlap and changes', '',
        f"Benchmark: {summary['overlap']['owasp-benchmark']['primary_with_traversal_related']} primary records retain traversal as related evidence; {summary['overlap']['owasp-benchmark']['additional_primary_records_at_same_range']} additional primaries share source ranges. Review distinct nested read/write operations before treating them as duplicate noise. Identity is unchanged by this evaluator.",
        'This evaluator does not modify detection rules, capability manifest maturity, host integrations or production Runtime logic. Evaluator tests cover independent labels, missing rules, file applicability, coordinate matching, denominator handling, bounded evidence and unlabelled sink candidates.', '',
        '## Follow-up discipline', '',
        'Precision first: source-review failures and pair minimal safe/unsafe regressions before changing a rule. Recheck accepted sink models with real-case replay. Review unsupported request sources and typed helper fields separately. SSRF needs trustworthy real-project labels before accuracy claims.',
        'Do not broaden taint propagation indiscriminately. Maturity stays frozen. Scan duration/rule/file counts are recorded without adding a daemon, worker or scanner cache.', '',
        'See inventory.json, summary.json, case-evaluation.json, cause-reviews.json, review-dataset.jsonl and the <=24-record review-queue.md.']
    (output / 'REPORT.md').write_text('\n'.join(report) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('R1 evaluation requires explicit Python 3.12 for this run')
    os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jeepay', type=Path, required=True)
    parser.add_argument('--benchmark', type=Path, required=True)
    parser.add_argument('--benchmark-reference', type=Path, required=True)
    parser.add_argument('--per-class', type=int, default=30)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/r1')
    parser.add_argument('--inventory-only', action='store_true')
    parser.add_argument('--analysis-only', action='store_true', help='Re-analyze saved successful scanner outputs; no new scanner execution')
    arguments = parser.parse_args()
    if not 1 <= arguments.per_class <= 100:
        parser.error('--per-class must be between 1 and 100')
    run(arguments)

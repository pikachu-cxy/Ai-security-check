"""Exercise Vue projections through the real local Semgrep product adapter.

Targets are temporary text fixtures and are never imported or executed. This
gate checks script-only coverage and local taint; it does not compile templates,
connect separate scripts, or infer arbitrary wrappers/cross-file flows.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck


BUILTIN_RULE = 'ai-security.javascript.browser-dom-xss'
# Source text, expected sink marker (unique last occurrence), supported blocks.
CASES = {
    'dual_positive.vue': (
        '<template><p>script scopes</p></template>\n'
        '<script>const shared = window.location.hash;</script>\n'
        '<script setup>\n'
        'function localFlow() { const localValue = location.search; element.innerHTML = localValue; }\n'
        'element.innerHTML = shared;\n</script>\n', b'localValue;', 2),
    'dual_isolated.vue': (
        '<script>const shared = location.hash;</script>\n'
        '<script setup>element.innerHTML = shared;</script>\n', None, 2),
    'template_text.vue': (
        '<template><pre>element.innerHTML = location.hash;</pre>'
        '<!-- element.innerHTML = location.hash; --></template>\n'
        '<style>.example { content: "element.innerHTML = location.hash;" }</style>\n'
        '<script setup>const fixed = "ordinary data";</script>\n', None, 1),
    'typescript_mapping.vue': (
        '<!-- 中文 -->\r\n<template><p>值</p></template>\r\n'
        '<script setup lang="ts">const label: string = "é"; '
        'const typedValue: string = location.hash; element.innerHTML = typedValue;</script>\r\n',
        b'typedValue;', 1),
    'safe_reset.vue': (
        '<script setup>let value = location.hash; value = "fixed"; element.innerHTML = value;</script>\n', None, 1),
    'html_only.vue': ('<template><p>{{ value }}</p></template>\n', None, 0),
    'external_script.vue': ('<script src="./not-read.js"></script>\n', None, 0),
    'unsupported_script.vue': ('<script lang="coffee">alert value</script>\n', None, 0),
}


def _scan(root, targets, rules_path=None):
    with local_recheck():
        findings, run = SemgrepAdapter().scan(
            ScanContext(str(root), ScanMode.RELEASE, tuple(targets),
                        rules_path=str(rules_path) if rules_path else None),
            FindingNormalizer(root))
    if run.status != 'SUCCESS':
        raise ValueError(f'Vue product scan incomplete: {run.status}, {run.error}')
    return findings, run


def _verify_position(finding, source, marker):
    raw = source.encode('utf-8')
    offset = raw.rindex(marker)
    expected_line = raw[:offset].count(b'\n') + 1
    expected_column = offset - raw.rfind(b'\n', 0, offset)
    locator = finding.technical_details.get('evidence_locator', {})
    if (finding.line_start != expected_line or locator.get('start_column') != expected_column
            or locator.get('file_sha256') != hashlib.sha256(raw).hexdigest()):
        raise ValueError(f'Vue original-source coordinates/hash mismatch: {finding.file_path}')
    return {'path': finding.file_path, 'line': finding.line_start,
            'column': locator['start_column'], 'original_hash_verified': True}


def _verify_coverage(run, cases):
    coverage = run.rule_coverage
    vue = coverage['per_language']['vue']
    expected_state = 'PARTIAL' if any(blocks for _, _, blocks in cases.values()) else 'NOT_COVERED'
    if coverage['status'] != expected_state or vue['status'] != expected_state:
        raise ValueError('Vue coverage incorrectly claims full execution or hides an uncovered file')
    if vue.get('template_status') != 'NOT_COVERED':
        raise ValueError('Vue template coverage must not be inferred from script execution')
    for name, (_, _, blocks) in cases.items():
        detail = vue['files'][name]
        state = 'PARTIAL' if blocks else 'NOT_COVERED'
        if detail['scanned_script_blocks'] != blocks or detail['status'] != state:
            raise ValueError(f'Vue block execution proof mismatch: {name}')
    if any(blocks for _, _, blocks in cases.values()) and (
            not vue['executed_rule_ids'] or not vue['scanned_files']):
        raise ValueError('Missing engine time.rules / paths.scanned execution proof')
    return {'status': coverage['status'], 'template_status': vue['template_status'],
            'executed_rule_ids': vue['executed_rule_ids'], 'scanned_files': vue['scanned_files'],
            'files': vue['files'], 'execution_evidence': coverage['execution_evidence']}


def check(case=None):
    cases = {case: CASES[case]} if case else CASES
    with tempfile.TemporaryDirectory(prefix='vue-script-quality-') as temporary:
        root = Path(temporary)
        for name, (source, _, _) in cases.items():
            # Preserve CRLF and Unicode bytes exactly for coordinate assertions.
            (root / name).write_bytes(source.encode('utf-8'))
        findings, run = _scan(root, cases)
        expected = {(name, BUILTIN_RULE) for name, (_, marker, _) in cases.items() if marker}
        actual = {(f.file_path, f.technical_details['rule_id']) for f in findings}
        if actual != expected or len(findings) != len(expected):
            raise ValueError(f'Vue gate: missing={sorted(expected-actual)}, unexpected={sorted(actual-expected)}, findings={len(findings)}')
        coordinates = [_verify_position(f, cases[f.file_path][0], cases[f.file_path][1]) for f in findings]
        coverage = _verify_coverage(run, cases)
        traces = []
        for finding in findings:
            support = finding.technical_details.get('dataflow_support', {})
            trace = finding.technical_details.get('scanner_evidence_metadata', {}).get('dataflow_trace')
            if (support.get('trace_status') != ('PROVIDED' if trace else 'NOT_PROVIDED')
                    or support.get('runtime_execution') is not False
                    or support.get('cross_file_expansion') is not False):
                raise ValueError('Vue taint evidence overstates trace availability or analysis scope')
            traces.append({'path': finding.file_path, **support})
        custom = None
        if case is None:
            custom_rules = root / 'local-rules'
            custom_rules.mkdir()
            (custom_rules / 'rules.yml').write_text('''rules:
- id: local.vue.custom-flow
  languages: [javascript, typescript]
  severity: WARNING
  message: Local custom rule fixture
  mode: taint
  pattern-sources:
  - pattern: localInput()
    exact: true
  pattern-sinks:
  - patterns:
    - pattern: localSink($VALUE)
    - focus-metavariable: $VALUE
''', encoding='utf-8')
            custom_cases = {
                'custom_positive.vue': ('<script setup>const customValue = localInput(); localSink(customValue);</script>', b'customValue);', 1),
                'custom_safe.vue': ('<script setup>const customValue = "fixed"; localSink(customValue);</script>', None, 1),
            }
            for name, (source, _, _) in custom_cases.items():
                (root / name).write_bytes(source.encode())
            custom_findings, custom_run = _scan(root, custom_cases, custom_rules)
            if {(f.file_path, f.technical_details['rule_id']) for f in custom_findings} != {
                    ('custom_positive.vue', 'local.vue.custom-flow')} or len(custom_findings) != 1:
                raise ValueError('User local-rule Vue positive/negative product gate failed')
            custom = {'cases': len(custom_cases), 'findings': len(custom_findings),
                'coordinate': _verify_position(custom_findings[0], custom_cases['custom_positive.vue'][0], b'customValue);'),
                'coverage': _verify_coverage(custom_run, custom_cases)}
        return {'status': 'PASS', 'builtin_cases': len(cases), 'builtin_findings': len(findings),
                'original_coordinates': coordinates, 'coverage': coverage, 'dataflow': traces,
                'custom_rules': custom,
                'scope': 'Static inline scripts only; separate script scopes; templates and external scripts are not covered.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--case', choices=tuple(CASES), help='Run one built-in fixture only; omit for the full gate.')
    args = parser.parse_args()
    result = check(args.case)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    print(text)

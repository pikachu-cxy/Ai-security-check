"""Product boundaries for Vue script projections and evidence remapping."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import WorkspaceReader
from security_runtime.models import ScanContext
from security_runtime.processes import ProcessResult
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import RulePackManager
from security_runtime.scanners import SemgrepAdapter
from security_runtime.vue_scan import VueProjection


def projection(tmp_path, source, *, name='App.vue', budget=None, path_filters=False):
    root = tmp_path / 'project'
    root.mkdir()
    (root / name).write_bytes(source if isinstance(source, bytes) else source.encode())
    plan = SimpleNamespace(skipped_files={}, embedded_coverage={})
    return root, plan, VueProjection(root, (name,), tmp_path / 'shadow', plan, budget, path_filters=path_filters)


def location(raw, offset):
    return {'line': raw[:offset].count(b'\n') + 1,
            'col': offset - raw.rfind(b'\n', 0, offset), 'offset': offset}


def match(path, raw, token=b'alert(value)', *, rule='test.vue'):
    start = raw.index(token)
    return {'check_id': rule, 'path': str(path), 'start': location(raw, start),
            'end': location(raw, start + len(token)),
            'extra': {'message': 'Static scan fixture', 'severity': 'WARNING',
                      'metadata': {'category': 'code'}, 'lines': token.decode()}}


def payload(paths, results=(), errors=(), skipped=(), rules=('test.vue',)):
    return {'results': list(results), 'errors': list(errors),
            'paths': {'scanned': list(paths), 'skipped': list(skipped)},
            'time': {'rules': list(rules)}}


@pytest.mark.parametrize('lang,extension', [('', '.js'), (' lang="ts"', '.ts')])
def test_projection_maps_original_path_and_utf8_coordinates(tmp_path, lang, extension):
    source = ('<!--中文--><template><p>值</p></template>\r\n'
              f'<script setup{lang}>const note = "é"; alert(value);</script>').encode()
    root, plan, prepared = projection(tmp_path, source)
    shadow, = prepared.scope
    raw = Path(shadow).read_bytes()
    assert Path(shadow).suffix == extension
    assert raw.index(b'alert(value)') == source.index(b'alert(value)')
    observed = prepared.finish([payload([shadow], [match(shadow, raw)])])
    finding, = observed['results']
    assert finding['path'] == 'App.vue'
    assert finding['start'] == location(source, source.index(b'alert(value)'))
    assert observed['paths']['scanned'] == ['App.vue']
    assert plan.embedded_coverage['App.vue']['status'] == 'PARTIAL'
    assert plan.embedded_coverage['App.vue']['template_status'] == 'NOT_COVERED'


def test_two_script_blocks_cannot_acquire_flow_by_concatenation(tmp_path):
    _, plan, prepared = projection(tmp_path,
        '<script>const value = location.hash;</script><script setup>alert(value);</script>')
    assert len(prepared.scope) == 2
    first, second = [Path(path).read_bytes() for path in prepared.scope]
    assert b'location.hash' in first and b'alert(value)' not in first
    assert b'alert(value)' in second and b'location.hash' not in second
    prepared.finish([payload(prepared.scope)])
    assert plan.embedded_coverage['App.vue']['script_blocks'] == 2
    assert plan.embedded_coverage['App.vue']['scanned_script_blocks'] == 2
    assert plan.embedded_coverage['App.vue']['scanned_languages'] == ['javascript']


def test_projection_records_exact_original_bytes_for_evidence_binding(tmp_path):
    source = '<!--中文-->\r\n<script setup lang="ts">alert(value);</script>'.encode()
    _, _, prepared = projection(tmp_path, source)
    assert prepared.fingerprints == {'App.vue': hashlib.sha256(source).hexdigest()}


@pytest.mark.parametrize('budget', [{'files': 64, 'bytes': 0}, {'files': 0, 'bytes': 4 * 1024 * 1024}])
def test_exhausted_vue_budgets_skip_without_reading_source(tmp_path, budget):
    with patch('security_runtime.vue_scan.WorkspaceReader.read', side_effect=AssertionError('must not read')):
        _, plan, prepared = projection(tmp_path, '<script>alert(value)</script>', budget=budget)
    assert not prepared.scope
    prepared.finish([])
    assert plan.embedded_coverage['App.vue']['issues'] == ['VUE_SCAN_BUDGET_EXCEEDED']
    assert plan.embedded_coverage['App.vue']['status'] == 'NOT_COVERED'


def test_vue_byte_budget_rejects_next_file_and_file_budget_is_shared_across_batches(tmp_path):
    budget = {'files': 63, 'bytes': 0}
    root, plan, first = projection(tmp_path, '<script>alert(value)</script>', budget=budget)
    assert len(first.scope) == 1 and budget['files'] == 64
    second = VueProjection(root, ('App.vue',), tmp_path / 'next', plan, budget)
    assert not second.scope and second.details['App.vue']['issues'] == ['VUE_SCAN_BUDGET_EXCEEDED']
    nearly_full = {'files': 0, 'bytes': 4 * 1024 * 1024 - 1}
    third = VueProjection(root, ('App.vue',), tmp_path / 'last', plan, nearly_full)
    assert not third.scope and nearly_full['bytes'] == 4 * 1024 * 1024 - 1
    assert third.details['App.vue']['issues'] == ['VUE_SCAN_BUDGET_EXCEEDED']


def test_remaining_byte_budget_is_applied_before_source_open(tmp_path):
    root, plan, _ = projection(tmp_path, '<script>alert(value)</script>')
    budget = {'files': 0, 'bytes': 4 * 1024 * 1024 - 7}
    real_read = WorkspaceReader.read
    with patch('security_runtime.vue_scan.WorkspaceReader.read', autospec=True, side_effect=real_read) as read, \
            patch('security_runtime.local_evidence.os.open', side_effect=AssertionError('file must not be opened')):
        prepared = VueProjection(root, ('App.vue',), tmp_path / 'bounded-read', plan, budget)
    assert read.call_args.kwargs['maximum'] == 7
    assert not prepared.scope and prepared.details['App.vue']['issues'] == ['VUE_SCAN_BUDGET_EXCEEDED']


def test_rule_path_filters_skip_vue_without_reading_and_leave_plain_paths_unchanged(tmp_path):
    with patch('security_runtime.vue_scan.WorkspaceReader.read', side_effect=AssertionError('must not read')):
        root, plan, prepared = projection(tmp_path, '<script>alert(value)</script>', path_filters=True)
        mixed = VueProjection(root, ('App.vue', 'plain.js'), tmp_path / 'mixed', plan, path_filters=True)
    assert prepared.scope == [] and mixed.scope == ['plain.js']
    prepared.finish([])
    assert plan.embedded_coverage['App.vue']['issues'] == ['VUE_RULE_PATH_FILTER_UNSUPPORTED']
    assert plan.embedded_coverage['App.vue']['status'] == 'NOT_COVERED'


@pytest.mark.parametrize('source,issue', [
    ('<template><p>only markup</p></template>', None),
    ('<script src="./external.js"/>', 'EXTERNAL_SCRIPT'),
    ('<script lang="coffee">alert value</script>', 'UNSUPPORTED_SCRIPT_LANGUAGE'),
    ('<template><div></template><script>alert(value)</script>', 'MALFORMED_SFC'),
])
def test_no_supported_script_is_not_covered(tmp_path, source, issue):
    _, plan, prepared = projection(tmp_path, source)
    assert prepared.scope == []
    observed = prepared.finish([])
    assert observed['results'] == [] and observed['paths']['scanned'] == []
    detail = plan.embedded_coverage['App.vue']
    assert detail['status'] == 'NOT_COVERED'
    assert plan.skipped_files['App.vue'] == 'VUE_NO_SUPPORTED_SCRIPT'
    if issue:
        assert issue in detail['issues']


def test_supported_and_unsupported_script_blocks_keep_partial_reason(tmp_path):
    _, plan, prepared = projection(tmp_path,
        '<script src="./external.js"></script><script setup>alert(value)</script>')
    shadow, = prepared.scope
    prepared.finish([payload([shadow])])
    detail = plan.embedded_coverage['App.vue']
    assert detail['status'] == 'PARTIAL' and detail['scanned_script_blocks'] == 1
    assert detail['issues'] == ['EXTERNAL_SCRIPT']


def test_all_structured_engine_paths_are_remapped_including_nested_trace(tmp_path):
    _, plan, prepared = projection(tmp_path, '<script>alert(value);</script>')
    shadow, = prepared.scope
    raw = Path(shadow).read_bytes()
    item = match(shadow, raw)
    item['extra']['dataflow_trace'] = {'taint_source': ['CliLoc', [
        {'path': shadow, 'start': item['start'], 'end': item['end']}, 'untrusted source text']]}
    item['extra']['metavars'] = {'$X': {'path': shadow, 'start': item['start'], 'end': item['end']}}
    observed = prepared.finish([payload([shadow], [item],
        errors=[{'path': shadow, 'type': 'ParseError'}],
        skipped=[{'path': shadow, 'reason': 'analysis_failed_parser_or_internal_error'}])])
    assert shadow not in json.dumps(observed)
    assert observed['errors'][0]['path'] == 'App.vue'
    assert observed['paths']['skipped'][0]['path'] == 'App.vue'
    assert observed['results'][0]['extra']['dataflow_trace']['taint_source'][1][0]['path'] == 'App.vue'
    assert plan.embedded_coverage['App.vue']['scanned_script_blocks'] == 0


@pytest.mark.parametrize('start,end', [(0, 1), (False, 15), (14, '15'), (14, 999999)])
def test_projection_rejects_engine_match_outside_original_script_body(tmp_path, start, end):
    _, _, prepared = projection(tmp_path, '<script>alert(value);</script>')
    shadow, = prepared.scope
    item = match(shadow, Path(shadow).read_bytes())
    item['start']['offset'], item['end']['offset'] = start, end
    observed = prepared.finish([payload([shadow], [item])])
    assert observed['results'] == []


def test_normalized_trace_never_exposes_shadow_or_outside_paths(tmp_path):
    root, _, prepared = projection(tmp_path, '<script>alert(value);</script>')
    shadow, = prepared.scope
    item = match(shadow, Path(shadow).read_bytes())
    outside = str((tmp_path / 'private-outside.py').resolve())
    item['extra']['dataflow_trace'] = {'source': {'path': shadow}, 'unknown_call': {'path': outside}}
    observed = prepared.finish([payload([shadow], [item])])
    finding, = SemgrepAdapter().normalize(observed, FindingNormalizer(root))
    metadata = finding.technical_details['scanner_evidence_metadata']
    assert metadata['dataflow_trace']['source']['path'] == 'App.vue'
    assert metadata['dataflow_trace']['unknown_call']['path'] == '[OUTSIDE_WORKSPACE]'
    assert shadow not in json.dumps(finding.technical_details)
    assert outside not in json.dumps(finding.technical_details)


def run_adapter(tmp_path, source, *, languages=('javascript', 'typescript'), include_match=True,
                projection_source=None, path_filter=None, fail_second_script=False):
    root = tmp_path / 'project'
    root.mkdir()
    original = source.encode('utf-8')
    (root / 'App.vue').write_bytes(original)
    rules = tmp_path / 'rules'
    rules.mkdir()
    definitions = [{'id': f'test.{language}', 'languages': [language], 'message': 'Fixture',
                    'severity': 'WARNING', 'pattern': 'alert(...)'} for language in languages]
    if path_filter is not None:
        for definition in definitions:
            definition['paths'] = path_filter
    (rules / 'rules.yml').write_text(yaml.safe_dump({'rules': definitions}), encoding='utf-8')
    pack = RulePackManager().resolve(user_path=rules)
    plan = plan_rules(pack, ('App.vue',))
    adapter, calls = SemgrepAdapter(), []
    context = ScanContext(str(root), 'release', ('App.vue',), rules_path=str(rules), rule_plan=plan)

    @contextmanager
    def artifacts(*args, **kwargs):
        folder = tmp_path / 'artifacts'
        folder.mkdir(exist_ok=True)
        yield folder

    def execute(args, cwd, timeout):
        paths = args[args.index('--no-git-ignore') + 1:]
        calls.append(paths)
        results, errors = [], []
        for index, path in enumerate(paths):
            assert Path(path).suffix in {'.js', '.ts'}
            if fail_second_script and index == 1:
                errors.append({'path': path, 'type': 'ParseError'})
                continue
            raw = Path(path).read_bytes()
            if include_match and b'alert(value)' in raw:
                results.append(match(path, raw, rule='test.typescript' if Path(path).suffix == '.ts' else 'test.javascript'))
        data = payload(paths, results, errors=errors, rules=tuple(rule['id'] for rule in definitions))
        return ProcessResult(0, json.dumps(data), '', 1)

    def make_projection(*args, **kwargs):
        if projection_source is None:
            return VueProjection(*args, **kwargs)
        # Simulate A -> B -> A between scanner fingerprints. The projected B
        # must not inherit A's evidence fingerprint merely because A returned.
        (root / 'App.vue').write_bytes(projection_source.encode('utf-8'))
        prepared = VueProjection(*args, **kwargs)
        (root / 'App.vue').write_bytes(original)
        return prepared

    with patch('security_runtime.scanners._execute', side_effect=execute), \
            patch('security_runtime.scanners._artifacts', artifacts), \
            patch('security_runtime.vue_scan.VueProjection', side_effect=make_projection):
        findings = adapter._scan('never-executed-semgrep', context, FindingNormalizer(root))
    return findings, plan.coverage('SUCCESS'), calls, original


@pytest.mark.parametrize('lang,extension', [('', '.js'), (' lang="ts"', '.ts')])
def test_adapter_preserves_original_vue_finding_path_hash_and_columns(tmp_path, lang, extension):
    source = f'<!--中文-->\r\n<template><p>值</p></template>\r\n<script setup{lang}>const note = "é"; alert(value);</script>'
    findings, coverage, calls, original = run_adapter(tmp_path, source)
    finding, = findings
    assert finding.file_path == 'App.vue' and finding.line_start == 3
    locator = finding.technical_details['evidence_locator']
    assert locator['file_sha256'] == hashlib.sha256(original).hexdigest()
    assert locator['start_column'] == location(original, original.index(b'alert(value)'))['col']
    assert calls and all(Path(path).suffix == extension for batch in calls for path in batch)
    vue = coverage['per_language']['vue']
    assert vue['status'] == 'PARTIAL' and vue['template_status'] == 'NOT_COVERED'
    assert vue['files']['App.vue']['scanned_script_blocks'] == 1
    assert finding.technical_details['embedded_source'] == {
        'format': 'VUE_SFC', 'scope': 'SCRIPT_BLOCKS_ONLY', 'template_status': 'NOT_COVERED'}


def test_projection_hash_prevents_false_original_evidence_binding_after_source_race(tmp_path):
    original = '<script>const note = "original"; alert(value);</script>'
    changed = '<script>const note = "modified"; alert(value);</script>'
    findings, _, _, _ = run_adapter(tmp_path, original, projection_source=changed)
    finding, = findings
    locator = finding.technical_details['evidence_locator']
    assert locator['file_sha256'] is None and locator['snapshot_reason'] == 'SCAN_FILE_CHANGED'


def test_adapter_does_not_start_engine_for_template_only_file(tmp_path):
    findings, coverage, calls, _ = run_adapter(tmp_path, '<template><p>hello</p></template>')
    assert findings == [] and calls == []
    assert coverage['status'] == 'NOT_COVERED'
    assert coverage['per_language']['vue']['status'] == 'NOT_COVERED'
    assert coverage['total_executed'] == 0


@pytest.mark.parametrize('lang,language', [('', 'javascript'), (' lang="ts"', 'typescript')])
def test_second_script_parse_error_preserves_first_script_execution_as_partial(tmp_path, lang, language):
    source = f'<script{lang}>alert(value);</script><script setup{lang}>const broken = ;</script>'
    findings, coverage, _, _ = run_adapter(tmp_path, source, fail_second_script=True)
    assert len(findings) == 1 and findings[0].file_path == 'App.vue'
    vue = coverage['per_language']['vue']
    assert coverage['status'] == vue['status'] == 'PARTIAL'
    assert vue['executed_rule_ids'] == ['test.' + language]
    assert vue['executed_rules'] == coverage['total_executed'] == 1
    detail = vue['files']['App.vue']
    assert detail['status'] == 'PARTIAL'
    assert detail['script_blocks'] == 2 and detail['scanned_script_blocks'] == 1
    assert detail['scanned_languages'] == [language]
    assert detail['template_status'] == 'NOT_COVERED'


@pytest.mark.parametrize('path_filter', [{'include': ['App.vue']}, {'exclude': ['App.vue']}])
def test_adapter_does_not_fake_execution_of_path_filtered_vue_rules(tmp_path, path_filter):
    findings, coverage, calls, _ = run_adapter(tmp_path, '<script>alert(value)</script>', path_filter=path_filter)
    assert not findings and not calls and coverage['status'] == 'NOT_COVERED'
    assert coverage['total_executed'] == 0
    assert coverage['per_language']['vue']['files']['App.vue']['issues'] == ['VUE_RULE_PATH_FILTER_UNSUPPORTED']


def test_zero_findings_after_script_execution_still_reports_template_gap(tmp_path):
    findings, coverage, calls, _ = run_adapter(tmp_path,
        '<template><p>{{ value }}</p></template><script setup>const value = "fixed";</script>', include_match=False)
    assert not findings and calls
    vue = coverage['per_language']['vue']
    assert vue['status'] == 'PARTIAL' and vue['files']['App.vue']['scanned_script_blocks'] == 1


def test_unrelated_typescript_rule_is_not_claimed_executed_for_js_only_script(tmp_path):
    _, coverage, _, _ = run_adapter(tmp_path, '<script setup>const value = "fixed";</script>', include_match=False)
    assert coverage['per_language']['vue']['executed_rule_ids'] == ['test.javascript']

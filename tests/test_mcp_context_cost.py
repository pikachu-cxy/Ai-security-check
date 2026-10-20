"""Default MCP output stays bounded without weakening review or full opt-in."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP

from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_tools.explicit_audit import register
from security_runtime.mcp_tools.presentation import _agent_result, selected_scope_summary
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.runtime import SecurityRuntime
from summary_fixtures import sample


def large_scan(size):
    files = [f'src/file-{index}.py' for index in range(size)]
    return ScanResult('bounded-scan', 'release', TargetProfile('/synthetic', files=files),
        'PARTIAL', [], [ScannerRun('synthetic', '1', 'FAILED', 12,
            error_code='OUTPUT_LIMIT_EXCEEDED', error_summary='Provider failed',
            remediation='Inspect the bounded error and retry explicitly.',
            coverage_contract='PARTIAL', coverage_notes=['Dependency graph is incomplete.'],
            rule_coverage=dict(status='PARTIAL', total_files=size, scope_files=files,
                total_selected=2, total_executed=1,
                per_language={'python': dict(status='PARTIAL', target_files=size,
                    scanned_files=size - 1, selected_rule_ids=['one', 'two'])}),
            dependency_inventory=dict(planned_manifests=size, confirmed_manifests=size-1,
                complete_dependency_graph_attested=False, package_coordinates=[
                    dict(package=f'unbounded-package-{index}', version='1') for index in range(size)],
                per_manifest={name: 1 for name in files}),
            scanner_diagnostics=dict(scope=dict(target_files=size, files=files),
                execution_binding=dict(files={name: 'a'*64 for name in files}),
                evidence=['RAW_SOURCE_SHOULD_NOT_APPEAR'] * size,
                failure=dict(stage='EXECUTION', reason='OUTPUT_LIMIT_EXCEEDED')))],
        'Some checks could not complete.', 'REVIEW', 12, coverage='PARTIAL',
        capability_results={'DEPENDENCY_VULN': 'PARTIAL'},
        capability_details={'DEPENDENCY_VULN': dict(status='PARTIAL', coverage='PARTIAL',
            coverage_notes=['Complete dependency graph was not attested.'])})


def registered(result, *, runtime=None):
    server = FastMCP('synthetic-context-cost')
    registry = MCPRegistry(server)
    calls = []
    def operation(*args, **kwargs):
        calls.append((args, kwargs))
        return result
    app = SimpleNamespace(bound_path=lambda path: path or '/synthetic', binding=None,
        scan=operation, scan_project=operation, scan_files=operation,
        scan_path_provider=lambda: runtime.store.path if runtime else None)
    register(server, registry, application=app, runtime_engine=lambda: runtime,
        hook_coordinator=None, remediation=None, include_functional_verification=False,
        check_scan=lambda scan_id: None, event=lambda *args, **kwargs: None)
    return registry, calls


def test_zero_finding_summary_does_not_scale_with_scanner_file_or_inventory_lists():
    small = _agent_result(large_scan(10), summary=True)
    large = _agent_result(large_scan(10_000), summary=True)
    small_bytes, large_bytes = (len(json.dumps(row).encode()) for row in (small, large))
    assert large_bytes < small_bytes + 200
    assert large_bytes < 8_000
    text = json.dumps(large)
    assert 'RAW_SOURCE_SHOULD_NOT_APPEAR' not in text
    assert 'file-9999.py' not in text and 'unbounded-package-' not in text
    run = large['scanner_runs'][0]
    assert run['dependency_inventory']['package_coordinates_count'] == 10_000
    assert run['dependency_inventory']['complete_dependency_graph_attested'] is False
    assert run['rule_coverage']['scope_files_count'] == 10_000
    assert run['status'] == 'FAILED' and run['error_code'] == 'OUTPUT_LIMIT_EXCEEDED'
    assert run['scanner_diagnostics']['failure']['stage'] == 'EXECUTION'
    assert large['coverage'] == 'PARTIAL' and large['finding_count'] == 0


def test_full_opt_in_retains_provider_detail_and_does_not_mutate_original():
    original = large_scan(10)
    before = copy.deepcopy(original)
    summary = _agent_result(original, summary=True)
    full = _agent_result(original, summary=False)
    assert len(full['scanner_runs'][0]['dependency_inventory']['package_coordinates']) == 10
    assert 'execution_binding' in full['scanner_runs'][0]['scanner_diagnostics']
    assert full['findings'] == [] and 'findings' not in summary
    assert original == before


def test_summary_keeps_execution_and_freshness_diagnostics_without_raw_evidence():
    scan = large_scan(1000)
    diagnostics = scan.scanner_runs[0].scanner_diagnostics
    diagnostics.update(source_stable=False, engine_process_observed=False,
        rule_execution='FRESH_LOCAL_LEXICAL_TRAVERSAL',
        context_gaps=[dict(file=f'gap-{index}.py', reason='INCOMPLETE_CONTEXT',
            source='RAW_SOURCE_SHOULD_NOT_APPEAR') for index in range(1000)])
    diagnostics['execution_binding'].update(contract='scanner-execution-binding-v1',
        verified=False, data_required=True, data_status='UNVERIFIABLE', tool='a'*64,
        data=dict(identity='private-hash', files=['private-source.py']))
    projected = _agent_result(scan, summary=True)['scanner_runs'][0]['scanner_diagnostics']
    assert projected['source_stable'] is False
    assert projected['engine_process_observed'] is False
    assert projected['rule_execution'] == 'FRESH_LOCAL_LEXICAL_TRAVERSAL'
    assert projected['context_gaps_count'] == 1000
    assert projected['context_gap_details_omitted'] is True
    assert projected['execution_binding'] == dict(contract='scanner-execution-binding-v1',
        verified=False, data_required=True, data_status='UNVERIFIABLE')
    rendered = json.dumps(projected)
    assert 'private-hash' not in rendered and 'private-source.py' not in rendered
    assert 'gap-999.py' not in rendered and 'RAW_SOURCE_SHOULD_NOT_APPEAR' not in rendered
    assert 'context_gaps' not in projected and 'files' not in projected['execution_binding']


def test_default_tool_schema_and_scan_behavior_are_compact_with_explicit_full_opt_in():
    registry, calls = registered(large_scan(1000))
    schemas = registry.schemas()
    for name in ('scan_project', 'scan_diff', 'scan_files'):
        assert schemas[name]['properties']['summary']['default'] is True
    for name in ('get_findings', 'get_triage'):
        assert schemas[name]['properties']['view']['default'] == 'summary'
    for name in ('prepare_triage', 'prepare_task_triage'):
        assert schemas[name]['properties']['limit']['default'] == 5
    assert schemas['prepare_task_triage']['properties']['include_existing_reviews']['default'] is False
    assert schemas['submit_triage']['properties']['compact']['default'] is True
    default = asyncio.run(registry.tool('scan_project').fn())
    full = asyncio.run(registry.tool('scan_project').fn(summary=False))
    assert default['finding_count'] == 0 and 'findings' not in default
    assert full['findings'] == []
    assert default['execution']['scanner_run'] is True
    assert default['execution']['host_review_completed'] is False
    assert default['execution']['repair_authorized'] is False
    assert default['timing']['host_analysis_ms'] is None
    assert len(calls) == 2


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_global_hosts_share_the_compact_defaults_from_the_same_registration(host):
    from security_runtime.global_mcp import create_global_server
    registry, _ = registered(large_scan(1))
    local = registry.schemas()
    routed = create_global_server(workspaces=object(), host=host)
    exported = {tool.name: tool.inputSchema for tool in asyncio.run(routed.list_tools())}
    defaults = [('scan_project', 'summary'), ('scan_diff', 'summary'), ('scan_files', 'summary'),
        ('get_findings', 'view'), ('get_triage', 'view'), ('prepare_triage', 'limit'),
        ('prepare_task_triage', 'limit'), ('prepare_task_triage', 'include_existing_reviews'),
        ('submit_triage', 'compact')]
    for tool, parameter in defaults:
        assert exported[tool]['properties'][parameter]['default'] == local[tool]['properties'][parameter]['default']


def test_selected_scope_keeps_requested_files_and_does_not_expand_or_attest_project():
    selected = selected_scope_summary(dict(contract='selected-file-scan-v1', kind='SELECTED_FILES',
        requested_files=['demo.py'], target_files=['demo.py'],
        context_files=[f'context-{index}' for index in range(1000)], excluded_files=[],
        full_project=False, expanded_to_project=False))
    assert selected['requested_files'] == selected['target_files'] == ['demo.py']
    assert selected['context_files_count'] == 1000
    assert selected['context_files_truncated'] is True and len(selected['context_files']) == 20
    assert selected['full_project'] is False and selected['expanded_to_project'] is False


def test_default_findings_and_triage_are_paged_and_full_is_still_explicit(sample, monkeypatch):
    root, scan, store = sample
    runtime = SecurityRuntime(store=store)
    original = runtime.get_findings(scan.scan_id)
    many = [dict(original[0], id=f'finding-{index}') for index in range(27)]
    monkeypatch.setattr(runtime, 'get_findings', lambda scan_id: many)
    rows = [dict(finding_id=item['id'], triage_status='PENDING', triage=None) for item in many]
    view = lambda self, scan_id: dict(scan_id=scan_id, findings=copy.deepcopy(rows),
        triage_coverage='NONE', dependency_groups=['large-group'])
    monkeypatch.setattr('security_runtime.triage.TriageService.view', view)
    monkeypatch.setattr('security_runtime.finding_feedback.FindingFeedbackService.status',
        lambda *args: dict(state='UNREVIEWED', folded=False))
    registry, _ = registered(scan, runtime=runtime)
    findings = registry.tool('get_findings').fn(scan.scan_id)
    assert len(findings['items']) == 20 and findings['total'] == 27
    assert findings['continuation']['arguments']['offset'] == 20
    assert 'technical_details' not in findings['items'][0]
    assert len(registry.tool('get_findings').fn(scan.scan_id, view='full')) == 27
    triage = registry.tool('get_triage').fn(scan.scan_id)
    assert len(triage['items']) == 20 and triage['continuation']['arguments']['offset'] == 20
    assert 'dependency_groups' not in triage and 'triage' not in triage['items'][0]
    assert len(registry.tool('get_triage').fn(scan.scan_id, view='full')['findings']) == 27


def test_handoff_and_submission_keep_context_binding_with_compact_default(monkeypatch):
    recorded = []
    def prepare(self, scan_id, finding_ids, categories, limit, **kwargs):
        recorded.append(('prepare', limit, kwargs))
        return dict(scan_id=scan_id, packets=[dict(finding_id='f1', context_hash='evidence-hash')])
    def submit(self, scan_id, results, compact=False):
        recorded.append(('submit', compact))
        return dict(accepted=len(results))
    monkeypatch.setattr('security_runtime.triage.TriageService.prepare', prepare)
    monkeypatch.setattr('security_runtime.triage.TriageService.submit', submit)
    registry, _ = registered(large_scan(1), runtime=SimpleNamespace(store=object()))
    packet = registry.tool('prepare_triage').fn('bounded-scan')
    result = registry.tool('submit_triage').fn('bounded-scan',
        [dict(finding_id='f1', context_hash='evidence-hash')], packet['triage_session'])
    assert recorded == [('prepare', 5, dict(pending_only=False, retry_failed=False)), ('submit', True)]
    assert result['accepted'] == 1 and result['handoff_remaining'] == 0
    assert result['continuation']['arguments']['pending_only'] is True
    with pytest.raises(ValueError, match='does not belong'):
        registry.tool('submit_triage').fn('bounded-scan',
            [dict(finding_id='f1', context_hash='wrong')], packet['triage_session'])

"""Bounded scanner projections shared by MCP handler groups."""
from collections import Counter
from dataclasses import asdict


def _fields(value, names, *, maximum=600):
    """Project declared scalar metadata; never walk arbitrary provider payloads."""
    if not isinstance(value, dict):
        return {}
    result = {}
    truncated = []
    for name in names:
        item = value.get(name)
        if name not in value or not isinstance(item, (str, int, float, bool, type(None))):
            continue
        if isinstance(item, str) and len(item) > maximum:
            item = item[:maximum]
            truncated.append(name)
        result[name] = item
    if truncated:
        result['truncated_fields'] = truncated
    return result


def _notes(value, key='coverage_notes'):
    rows = value.get(key, [])
    if not isinstance(rows, (list, tuple)):
        return {}
    return {key: [str(row)[:600] for row in rows[:5]],
            key + '_count': len(rows), key + '_truncated': len(rows) > 5 or
            any(len(str(row)) > 600 for row in rows[:5])}


def _inventory_summary(value):
    result = _fields(value, ('package_occurrences', 'unique_packages',
        'confirmed_package_occurrences', 'confirmed_manifests', 'planned_manifests',
        'complete_dependency_graph_attested', 'vulnerability_db_freshness',
        'inventory_truncated', 'native_duration_ms'))
    for name in ('unconfirmed_manifests', 'per_manifest', 'package_coordinates', 'python_declarations'):
        if isinstance(value.get(name), (dict, list, tuple)):
            result[name + '_count'] = len(value[name])
    return result


def _rule_summary(value, *, providers=True):
    result = _fields(value, ('engine', 'rule_pack_id', 'rule_pack_version',
        'rule_pack_checksum', 'status', 'total_available', 'total_selected',
        'total_executed', 'total_files', 'total_provider_selected', 'total_provider_executed',
        'engine_skipped_count', 'engine_skips_truncated', 'capability_program_version',
        'applicable_capabilities', 'coverage_scope', 'scope_notice', 'execution_evidence'))
    for name in ('scope_files', 'capabilities', 'detected_languages', 'deferred_providers'):
        if isinstance(value.get(name), (list, tuple)):
            result[name + '_count'] = len(value[name])
    result.update(_notes(value, 'limitations'))
    languages = value.get('per_language', {})
    if isinstance(languages, dict):
        result['per_language_count'] = len(languages)
        result['per_language_truncated'] = len(languages) > 20
        result['per_language'] = {str(name)[:80]: _fields(row, ('language', 'status',
            'available_rules', 'selected_rules', 'executed_rules', 'target_files', 'scanned_files'))
            for name, row in list(languages.items())[:20]}
    if isinstance(value.get('owasp_top10'), dict):
        # Preserve the explicit limitation, without sending rule IDs repeatedly.
        result['owasp_top10'] = _fields(value['owasp_top10'], ('edition', 'scope',
            'whole_program_reachability')) | {'manual_review': 'REQUIRED; NOT_ATTESTED_BY_RULE_EXECUTION'}
    if providers and isinstance(value.get('providers'), dict):
        rows = value['providers']
        result['providers_count'] = len(rows)
        result['providers_truncated'] = len(rows) > 20
        result['providers'] = {str(name)[:80]: _rule_summary(row, providers=False)
            for name, row in list(rows.items())[:20] if isinstance(row, dict)}
    return result


def _scanner_summary(run):
    result = _fields(run, ('scanner', 'version', 'status', 'duration_ms', 'finding_count',
        'error_code', 'error_summary', 'remediation', 'retry_after_seconds', 'provider',
        'provider_role', 'coverage_contract', 'error'))
    result.update(_notes(run))
    capabilities = run.get('capabilities', ())
    result['capabilities'] = [str(value)[:80] for value in capabilities[:20]]
    result['capabilities_truncated'] = len(capabilities) > 20
    if run.get('rule_coverage'):
        result['rule_coverage'] = _rule_summary(run['rule_coverage'])
    if run.get('dependency_inventory'):
        result['dependency_inventory'] = _inventory_summary(run['dependency_inventory'])
    diagnostics = run.get('scanner_diagnostics', {})
    result['scanner_diagnostics'] = _fields(diagnostics, ('invocation_count',
        'invocations_truncated', 'local_read_observed', 'engine_execution_observed',
        'engine_process_observed', 'rule_execution', 'source_stable'))
    if isinstance(diagnostics.get('context_gaps'), (list, tuple)):
        result['scanner_diagnostics']['context_gaps_count'] = len(diagnostics['context_gaps'])
        result['scanner_diagnostics']['context_gap_details_omitted'] = bool(diagnostics['context_gaps'])
    if isinstance(diagnostics.get('execution_binding'), dict):
        result['scanner_diagnostics']['execution_binding'] = _fields(
            diagnostics['execution_binding'], ('contract', 'verified', 'data_required', 'data_status'))
    if isinstance(diagnostics.get('failure'), dict):
        result['scanner_diagnostics']['failure'] = _fields(diagnostics['failure'],
            ('stage', 'reason', 'exception_type', 'error_code'))
    if isinstance(diagnostics.get('scope'), dict):
        result['scanner_diagnostics']['scope'] = _fields(diagnostics['scope'],
            ('target_files', 'kind', 'repository_discovery'))
    return result


def selected_scope_summary(scope):
    """Bound explicit selection metadata, never turn it into full-project proof."""
    result = _fields(scope, ('contract', 'kind', 'full_project', 'expanded_to_project',
        'context_purpose', 'notice'))
    for name in ('requested_files', 'target_files', 'context_files', 'excluded_files'):
        rows = scope.get(name, [])
        if not isinstance(rows, (list, tuple)):
            continue
        limit = 100 if name in {'requested_files', 'target_files'} else 20
        result[name + '_count'] = len(rows)
        result[name + '_truncated'] = len(rows) > limit
        result[name] = ([_fields(row, ('path', 'reason', 'source', 'size_bytes'), maximum=300)
            for row in rows[:limit]] if name == 'excluded_files' else
            [str(row)[:300] for row in rows[:limit]])
    return result

def _agent_finding(finding: dict) -> dict:
    from ..finding_quality import quality_finding
    result = {key: finding[key] for key in ("id", "category", "severity", "confidence", "plain_title", "file_path", "line_start", "line_end", "impact", "fix_advice", "technical_details", "triage_status", "verdict", "triage_confidence", "exploitability", "triage") if key in finding}
    try:
        result['quality'] = quality_finding(finding)
    except ValueError:
        # Never drop an existing scanner observation because a derived review
        # contract cannot safely represent its location.
        result['quality'] = None
        result['quality_diagnostic'] = 'INVALID_REVIEW_LOCATION'
    return result


def _agent_result(result, *, summary=False) -> dict:
    from ..target import selection_summary
    # Reuse retains the original saved record; never rebuild a fresh scan or
    # invent new scanner runs merely to use the same presentation adapter.
    value = result if isinstance(result, dict) else vars(result)
    data = {
        "scan_id": value['scan_id'],
        "workspace": value['target_profile']['path'] if isinstance(result, dict) else result.target_profile.path,
        "status": value['status'],
        "execution_state": value.get('execution_state', 'UNKNOWN'),
        "coverage_scope": value.get('coverage_scope', 'UNKNOWN'),
        "capability_results": value.get('capability_results', {}),
        "capability_details": value.get('capability_details', {}),
        "rule_coverage": {key:item for key,item in value.get('rule_coverage', {}).items() if key!='scope_files'},
        "background_preparation": value.get('background_preparation', {}),
        "coverage": value['coverage'],
        "summary": value['summary'],
        "findings": ([_agent_finding(f if isinstance(f, dict) else vars(f)) for f in value['findings']]
                     if not summary else []),
        "recommendation": value['release_status'],
        "duration_ms": value['duration_ms'],
        "scanner_runs": [run if isinstance(run, dict) else vars(run) if summary else asdict(run)
                         for run in value['scanner_runs']],
        "target_selection": selection_summary(value['target_profile']),
    }
    if not summary:
        return data
    data.pop('findings')
    data['finding_count'] = len(value['findings'])
    data['view'] = 'summary'
    data['findings_access'] = {'tool': 'get_findings', 'arguments': {
        'scan_id': data['scan_id'], 'view': 'summary', 'limit': 20}}
    data['detail_policy'] = 'Scan summary=false explicitly opts into full execution detail; finding detail uses get_findings(view=page or full).'
    data['scanner_runs_count'] = len(data['scanner_runs'])
    data['scanner_runs_status_counts'] = dict(Counter(run.get('status', 'UNKNOWN') for run in data['scanner_runs']))
    data['scanner_runs_truncated'] = len(data['scanner_runs']) > 20
    data['scanner_runs'] = [_scanner_summary(run) for run in data['scanner_runs'][:20]]
    data['rule_coverage'] = _rule_summary(data['rule_coverage'])
    details = data['capability_details']
    data['capability_details_count'] = len(details)
    data['capability_details_truncated'] = len(details) > 32
    data['capability_details'] = {str(name)[:80]: _fields(row, ('status', 'active_provider',
        'provider_role', 'coverage', 'primary_provider', 'primary_status', 'primary_error_code')) | _notes(row)
        for name, row in list(details.items())[:32] if isinstance(row, dict)}
    states = data['capability_results']
    data['capability_results_count'] = len(states)
    data['capability_results_truncated'] = len(states) > 32
    data['capability_results'] = {str(name)[:80]: str(state)[:80] for name, state in list(states.items())[:32]}
    data['background_preparation'] = _fields(data['background_preparation'], ('status', 'ready',
        'message', 'execution_policy', 'missing_checks', 'closeout_ref', 'background_registered',
        'pending_source_scan_id', 'pending_reason'))
    return data

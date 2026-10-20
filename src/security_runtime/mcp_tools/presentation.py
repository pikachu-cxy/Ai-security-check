"""Bounded scanner projections shared by MCP handler groups."""
from dataclasses import asdict

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


def _agent_result(result) -> dict:
    from ..target import selection_summary
    # Reuse retains the original saved record; never rebuild a fresh scan or
    # invent new scanner runs merely to use the same presentation adapter.
    value = result if isinstance(result, dict) else vars(result)
    return {
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
        "findings": [_agent_finding(f if isinstance(f, dict) else vars(f)) for f in value['findings']],
        "recommendation": value['release_status'],
        "duration_ms": value['duration_ms'],
        "scanner_runs": [run if isinstance(run, dict) else asdict(run) for run in value['scanner_runs']],
        "target_selection": selection_summary(value['target_profile']),
    }

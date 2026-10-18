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
    return {
        "scan_id": result.scan_id,
        "workspace": result.target_profile.path,
        "status": result.status,
        "execution_state": result.execution_state,
        "coverage_scope": result.coverage_scope,
        "capability_results": result.capability_results,
        "capability_details": result.capability_details,
        "rule_coverage": {key:value for key,value in result.rule_coverage.items() if key!='scope_files'},
        "background_preparation": result.background_preparation,
        "coverage": result.coverage,
        "summary": result.summary,
        "findings": [_agent_finding(f.__dict__) for f in result.findings],
        "recommendation": result.release_status,
        "duration_ms": result.duration_ms,
        "scanner_runs": [asdict(run) for run in result.scanner_runs],
        "target_selection": selection_summary(result.target_profile),
    }

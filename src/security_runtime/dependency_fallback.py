"""Explicit dependency-provider fallback policy and coverage contract."""
from .models import RunStatus

ELIGIBLE_ERRORS = frozenset({
    'MAVEN_RATE_LIMITED', 'NETWORK_TIMEOUT', 'DNS_RESOLUTION_FAILED',
    'PROXY_CONNECTION_FAILED', 'HTTP_5XX', 'DEPENDENCY_RESOLUTION_FAILED',
    'ENGINE_UNAVAILABLE', 'VULNERABILITY_DB_UNAVAILABLE',
    'OFFLINE_MODE',
})
BLOCKED_ERRORS = frozenset({
    'CHECKSUM_MISMATCH', 'LOCAL_IO_ERROR', 'SCANNER_OUTPUT_OR_CONFIG_ERROR',
    'OUTPUT_LIMIT_EXCEEDED', 'SECURITY_BOUNDARY_VIOLATION', 'INVARIANT_VIOLATION',
    'CONFIG_CORRUPTED', 'TLS_ERROR',
})


def should_fallback(run):
    if run.status not in {RunStatus.FAILED, RunStatus.UNAVAILABLE, RunStatus.TIMEOUT}:
        return False
    if run.error_code in BLOCKED_ERRORS:
        return False
    return run.error_code in ELIGIBLE_ERRORS or (run.status == RunStatus.UNAVAILABLE and run.error_code in {'', 'UNAVAILABLE'})


def dependency_status(runs):
    """A FULL successful provider satisfies the planned capability contract."""
    if any(run.status == RunStatus.SUCCESS and run.coverage_contract == 'FULL' for run in runs):
        return 'EXECUTED'
    if any(run.status == RunStatus.SUCCESS for run in runs):
        return 'PARTIAL'
    return 'UNAVAILABLE' if not runs or all(run.status == RunStatus.UNAVAILABLE for run in runs) else 'FAILED'


def capability_detail(runs, status):
    successful = [run for run in runs if run.status == RunStatus.SUCCESS]
    active = next((run for run in successful if run.coverage_contract == 'FULL'), None)
    active = active or (successful[-1] if successful else None)
    primary = next((run for run in runs if run.provider_role == 'PRIMARY'), None)
    return {
        'status': status, 'active_provider': active.provider if active else None,
        'provider_role': active.provider_role if active else None,
        'coverage': active.coverage_contract if active else 'NONE',
        'coverage_notes': active.coverage_notes if active else [],
        'primary_provider': primary.provider if primary else None,
        'primary_status': primary.status if primary else None,
        'primary_error_code': primary.error_code if primary else None,
    }

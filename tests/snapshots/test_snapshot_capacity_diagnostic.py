"""Typed page-store exhaustion must not echo source or claim a full capture."""
from security_runtime.snapshot_store import SnapshotStoreError
from security_runtime.tasks.diagnostics import capacity_failure


def test_snapshot_capacity_diagnostic_is_fixed_and_does_not_claim_scan_completion():
    cause = SnapshotStoreError('SNAPSHOT_WAITING_CAPACITY')
    wrapper = ValueError('private source details')
    wrapper.__cause__ = cause
    result = capacity_failure(wrapper)
    assert result['reason_code'] == 'SNAPSHOT_WAITING_CAPACITY'
    assert result['capacity']['state'] == 'WAITING_CAPACITY'
    assert result['prior_committed_evidence_preserved']
    assert not result['baseline_recreated'] and not result['source_modified']
    assert 'scanner_run' not in result
    assert 'private source' not in str(result)
    assert capacity_failure(SnapshotStoreError('SNAPSHOT_HISTORY_UNAVAILABLE')) is None

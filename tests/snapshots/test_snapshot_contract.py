"""L0 invariants prevent partial observations becoming full task evidence."""
from dataclasses import replace

import pytest

from security_runtime.snapshot_contract import (
    BaselineKind, CaptureBatchBudget, CaptureState, SnapshotCompleteness,
    SnapshotStatus, SourceConsistency, development_capabilities,
)


def full():
    return SnapshotCompleteness(1001, 1001, True, 1001, 1001, 1001)


def status(**changes):
    return replace(SnapshotStatus(BaselineKind.TASK_BEFORE_EDIT, CaptureState.SEALED,
        SourceConsistency.FROZEN_SOURCE, full(), True), **changes)


def test_sealed_product_observation_is_comparable_without_becoming_task_preimage():
    result = status(kind=BaselineKind.PRODUCT_COMPARISON,
                    consistency=SourceConsistency.OBSERVED_ONLY, captured_before_edit=False)
    assert result.comparison_available and result.complete
    assert not result.strict_task_preimage_eligible
    assert status().strict_task_preimage_eligible
    assert not status(consistency=SourceConsistency.OBSERVED_ONLY).strict_task_preimage_eligible
    assert not status(captured_before_edit=False).strict_task_preimage_eligible


@pytest.mark.parametrize('coverage', [
    SnapshotCompleteness(1000, 1001, False, 1000, 1000, 1000),
    SnapshotCompleteness(1001, 1001, True, 1000, 1001, 1000),
    SnapshotCompleteness(1001, 1001, True, 1001, 1001, 1000),
    SnapshotCompleteness(1001, None, False, 1001, 1001, 1001),
    replace(full(), gap_count=1),
])
def test_sealing_never_erases_missing_inventory_hashes_bodies_or_gaps(coverage):
    result = status(coverage=coverage)
    assert result.comparison_available
    assert not result.complete and not result.strict_task_preimage_eligible


@pytest.mark.parametrize('state', [s for s in CaptureState if s != CaptureState.SEALED])
def test_counts_cannot_publish_an_unsealed_or_failed_capture(state):
    result = status(state=state)
    assert not result.comparison_available and not result.complete
    assert not result.strict_task_preimage_eligible


@pytest.mark.parametrize('changes', [
    dict(expected_files=None), dict(expected_files=1002), dict(expected_files=999),
    dict(hashed_files=1002), dict(saved_bodies=1002), dict(required_bodies=1002),
    dict(hashed_files=1000), dict(observed_files=True), dict(gap_count=-1),
    dict(inventory_complete=1),
])
def test_invalid_or_overstated_counts_are_rejected(changes):
    with pytest.raises(ValueError):
        replace(full(), **changes)


def test_policy_excluded_original_bodies_have_a_separate_denominator():
    assert SnapshotCompleteness(1001, 1001, True, 1001, 1000, 1000).complete
    assert SnapshotCompleteness(0, 0, True, 0, 0, 0).complete
    assert not SnapshotCompleteness(0, None, False, 0, 0, 0).complete


def test_batch_yields_do_not_impose_a_total_file_limit():
    budget = CaptureBatchBudget()
    batches = [256, 256, 256, 233]
    assert sum(batches) == 1001
    assert [budget.reached(files=n, bytes=n*24, elapsed_ms=1) for n in batches] == [True]*3+[False]
    assert budget.reached(files=1, bytes=8_000_000, elapsed_ms=1)
    assert budget.reached(files=1, bytes=24, elapsed_ms=200)
    with pytest.raises(ValueError):
        CaptureBatchBudget(files=True)
    with pytest.raises(ValueError):
        CaptureBatchBudget(files=0)


@pytest.mark.parametrize('changes', [dict(kind='TASK_BEFORE_EDIT'), dict(state='SEALED'),
    dict(consistency='FROZEN_SOURCE'), dict(coverage={}), dict(captured_before_edit=1)])
def test_status_requires_explicit_typed_contract(changes):
    with pytest.raises(ValueError):
        status(**changes)


@pytest.mark.parametrize('value', [-1, True, 1.5, None])
def test_batch_usage_does_not_accept_invalid_counters(value):
    with pytest.raises(ValueError):
        CaptureBatchBudget().reached(files=value, bytes=0, elapsed_ms=0)


def test_capability_discovery_separates_implemented_adapters_from_host_guarantees():
    result = development_capabilities()
    assert result['stage'] == 'L1_L2_PARTIAL'
    for key in ('paged_capture', 'codex_home_worktree_admission',
                'readonly_binding_diagnostics', 'immutable_page_store', 'snapshot_page_gc'):
        assert result[key] is True
    assert result['paged_capture_scope'] == 'NEW_TASK_CLOSEOUT_RECORDS'
    assert result['readonly_binding_diagnostics_scope'] == 'GLOBAL_MCP_ONLY'
    assert result['snapshot_page_gc_scope'] == 'NEW_GC_CONTRACT_SEALED_CAPTURES_ONLY'
    assert result['task_page_write_contract'] == 'task-security-paged-gc-v1'
    from security_runtime.product_epoch_capture import platform_supported
    assert result['product_comparison_baseline'] == platform_supported()
    assert result['product_comparison_task_before_eligible'] is False
    assert result['product_comparison_consistency'] == 'OBSERVED_ONLY'
    for key in ('resumable_capture',
                'semantic_scan_partitioning', 'paged_review_storage',
                'cross_root_host_handshake', 'native_frozen_source',
                'host_write_barrier', 'os_write_sandbox', 'security_proof'):
        assert result[key] is False
    assert not {'trusted_current_session_identity', 'reliable_invocation_start_binding',
                'execution_root_attestation'} & result.keys()
    result['paged_capture'] = False
    assert development_capabilities()['paged_capture']


def test_real_discovery_exposes_only_contract_progress_without_creating_state(tmp_path, monkeypatch):
    from security_runtime.mcp_contracts import MCPRegistry
    from security_runtime.mcp_server import create_server

    absent = tmp_path / 'absent'
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(absent))
    registry = MCPRegistry(create_server(global_mode=False))
    for view in ('full', 'summary'):
        info = registry.tool('get_runtime_info').fn(view=view)
        assert info['features']['workspace_snapshot_development'] == development_capabilities()
        assert not absent.exists()
    assert 'get_workspace_binding_status' not in registry.names()

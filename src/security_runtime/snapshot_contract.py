"""L0 snapshot invariants; no capture, storage, routing or scanning authority.

Existing v3 records retain their original readers and quotas. New task captures
use the paged adapters advertised below; host guarantees remain independent.
"""
from dataclasses import dataclass
from enum import StrEnum


CONTRACT = 'workspace-snapshot-v2'


class BaselineKind(StrEnum):
    PRODUCT_COMPARISON = 'PRODUCT_COMPARISON'
    TASK_BEFORE_EDIT = 'TASK_BEFORE_EDIT'


class CaptureState(StrEnum):
    ALLOCATED = 'ALLOCATED'
    DISCOVERING = 'DISCOVERING'
    CAPTURING = 'CAPTURING'
    VERIFYING = 'VERIFYING'
    SEALED = 'SEALED'
    WAITING_CAPACITY = 'WAITING_CAPACITY'
    CAPTURE_CONFLICT = 'CAPTURE_CONFLICT'
    CANCELLED = 'CANCELLED'
    HISTORY_UNAVAILABLE = 'HISTORY_UNAVAILABLE'


class SourceConsistency(StrEnum):
    OBSERVED_ONLY = 'OBSERVED_ONLY'
    FROZEN_SOURCE = 'FROZEN_SOURCE'
    WRITE_BARRIER = 'WRITE_BARRIER'


def _count(value):
    if type(value) is not int or value < 0:
        raise ValueError('Invalid snapshot count')


@dataclass(frozen=True)
class SnapshotCompleteness:
    """Counts refer to one immutable source/policy/representation binding.

    A closed observation can have an unknown denominator. Required body count
    is separate because policy may forbid retaining some original contents.
    It is fixed by representation policy, never lowered to hide missing bodies.
    This object validates claims; it cannot establish that the counts are true.
    """

    observed_files: int
    expected_files: int | None
    inventory_complete: bool
    hashed_files: int
    required_bodies: int
    saved_bodies: int
    gap_count: int = 0

    def __post_init__(self):
        for value in (self.observed_files, self.hashed_files, self.required_bodies,
                      self.saved_bodies, self.gap_count):
            _count(value)
        if type(self.inventory_complete) is not bool:
            raise ValueError('Invalid inventory completeness')
        if self.expected_files is not None:
            _count(self.expected_files)
            if self.observed_files > self.expected_files:
                raise ValueError('Observed count exceeds expected inventory')
        if self.inventory_complete and self.expected_files != self.observed_files:
            raise ValueError('Complete inventory requires an exact denominator')
        if (self.hashed_files > self.observed_files
                or self.required_bodies > self.observed_files
                or self.saved_bodies > min(self.required_bodies, self.hashed_files)):
            raise ValueError('Inconsistent snapshot coverage counts')

    @property
    def complete(self):
        return (self.inventory_complete and self.gap_count == 0
                and self.hashed_files == self.expected_files
                and self.saved_bodies == self.required_bodies)


@dataclass(frozen=True)
class SnapshotStatus:
    kind: BaselineKind
    state: CaptureState
    consistency: SourceConsistency
    coverage: SnapshotCompleteness
    captured_before_edit: bool = False

    def __post_init__(self):
        if (not isinstance(self.kind, BaselineKind)
                or not isinstance(self.state, CaptureState)
                or not isinstance(self.consistency, SourceConsistency)
                or not isinstance(self.coverage, SnapshotCompleteness)
                or type(self.captured_before_edit) is not bool):
            raise ValueError('Invalid snapshot status contract')

    @property
    def comparison_available(self):
        # The sealed reference can be inspected, including empty/gapped sources.
        # This does not promise readable evidence for every (or any) path.
        return self.state == CaptureState.SEALED

    @property
    def complete(self):
        return self.comparison_available and self.coverage.complete

    @property
    def strict_task_preimage_eligible(self):
        # Only a prerequisite: caller still verifies owner, execution root,
        # directory identity, fixed version, time and actual host capabilities.
        return (self.complete and self.kind == BaselineKind.TASK_BEFORE_EDIT
                and self.captured_before_edit
                and self.consistency != SourceConsistency.OBSERVED_ONLY)


@dataclass(frozen=True)
class CaptureBatchBudget:
    """Scheduling boundaries, not total project admission limits.

    Finishing one batch never declares the inventory complete. Durable cursors,
    source continuity and machine disk/concurrency quotas are separate contracts.
    A single blocking file operation need not obey the elapsed-time target.
    """

    files: int = 256
    bytes: int = 8_000_000
    elapsed_ms: int = 200

    def __post_init__(self):
        for value in (self.files, self.bytes, self.elapsed_ms):
            _count(value)
            if value == 0:
                raise ValueError('Batch budget must be positive')

    def reached(self, *, files, bytes, elapsed_ms):
        for value in (files, bytes, elapsed_ms):
            _count(value)
        return files >= self.files or bytes >= self.bytes or elapsed_ms >= self.elapsed_ms


def development_capabilities():
    """Expose contract progress without advertising unimplemented execution."""
    from .product_epoch_capture import platform_supported
    return dict(contract=CONTRACT, stage='L1_L2_PARTIAL',
        paged_capture=True, resumable_capture=False, product_comparison_baseline=platform_supported(),
        product_comparison_contract='product-epoch-observed-v1',
        product_comparison_consistency='OBSERVED_ONLY',
        product_comparison_source_policy='HASH_ONLY',
        product_comparison_task_before_eligible=False,
        product_comparison_inventory='FINITE_OBSERVATION; PROJECT_DENOMINATOR_UNKNOWN',
        product_comparison_platform='POSIX_NOFOLLOW_DIRFD; OTHERS_UNSUPPORTED',
        product_comparison_resume='SAME_REF_CURSOR; OBSERVATION_INTERVALS; INTERRUPTED_FILE_MAX_3_ATTEMPTS',
        readonly_product_epoch_status='GLOBAL_MCP_ONLY; NO_ADMISSION_OR_STATE_CREATION',
        semantic_scan_partitioning=False, paged_review_storage=False,
        codex_home_worktree_admission=True, readonly_binding_diagnostics=True,
        readonly_binding_diagnostics_scope='GLOBAL_MCP_ONLY',
        paged_capture_scope='NEW_TASK_CLOSEOUT_RECORDS',
        immutable_page_store=True, snapshot_page_gc=True,
        snapshot_page_gc_scope='NEW_GC_CONTRACT_SEALED_CAPTURES_ONLY',
        task_page_write_contract='task-security-paged-gc-v1',
        legacy_page_gc='RETAIN_UNCHANGED',
        trusted_current_session_identity=False, reliable_invocation_start_binding=False,
        execution_root_attestation=False,
        cross_root_host_handshake=False, native_frozen_source=False,
        host_write_barrier=False, os_write_sandbox=False,
        existing_task_protocol='task-review-plan-v3', legacy_tasks='READ_WITH_ORIGINAL_CONTRACT',
        source_representation='PRESERVE_ORIGINAL_TASK_POLICY', security_proof=False)

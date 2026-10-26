"""Read-only preflight for product comparison state; no admission or keys."""
from .global_workspace import workspace_rejection, workspace_state
from .hook_state import HookStateStore


def inspect_product_epoch(pool, workspace_path):
    from .task_audit_mode import MODE, startup_baseline
    result = dict(contract='product-epoch-status-v1', path_status='UNKNOWN',
        reason_code=None, resolved_workspace=None, epoch_status=None,
        scanner_run=False, state_modified=False, source_modified=False,
        security_proof=False,
        strict_task_preimage_eligible=False, operating_mode=MODE,
        startup_comparison_baseline=startup_baseline())
    try:
        root = pool.root(workspace_path)
    except (ValueError, OSError, RuntimeError) as exc:
        result.update(path_status='REJECTED',
            reason_code=workspace_rejection(exc, 'RESOLVING_ROOT'))
        return result
    result.update(path_status='ALLOWED', resolved_workspace=str(root))
    try:
        from .product_epoch_service import ProductEpochService
        hooks = HookStateStore(workspace_state(root, pool.base)/'hooks')
        result['epoch_status'] = ProductEpochService(hooks, root).status()
    except (ValueError, OSError, RuntimeError):
        # Never expose exception text, source, private directory or another root.
        result['reason_code'] = 'PRODUCT_EPOCH_STATE_UNVERIFIED'
    return result

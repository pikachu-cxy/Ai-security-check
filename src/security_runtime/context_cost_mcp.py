"""Best-effort local measurements; never participate in tool authority or routing."""
from __future__ import annotations

import os
from time import monotonic, time


async def observe_response(call, request, *, connection_id, workspace=None):
    if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '1') == '0':
        return await call(request)
    try:
        from .context_cost import ContextCostStore, run_label
        store = ContextCostStore()
        setting = store.monitoring()
        label = run_label(setting.get('run'))
        arguments = getattr(getattr(request, 'params', None), 'arguments', None)
        # Read only the route selector, never retain the argument dictionary.
        claimed_workspace = arguments.get('workspace_path') if isinstance(arguments, dict) else None
        if not isinstance(claimed_workspace, str) or not os.path.isabs(claimed_workspace) or len(claimed_workspace) > 4096:
            claimed_workspace = None
        observed_workspace = workspace or claimed_workspace
    except Exception:
        return await call(request)
    if not isinstance(setting, dict) or setting.get('mode') not in {'basic', 'debug'}:
        return await call(request)
    started, started_at = monotonic(), time()
    result = None
    succeeded = False
    try:
        response = await call(request)
        try:
            result = getattr(response, 'root', response)
            succeeded = not bool(result.get('isError', False) if isinstance(result, dict) else getattr(result, 'isError', False))
        except Exception:
            result = None
        return response
    finally:
        try:
            store.record_call(
                request.params.name, result, elapsed_ms=int((monotonic() - started) * 1000),
                transport='mcp', connection_id=connection_id, workspace=observed_workspace,
                run_label=label,
                succeeded=succeeded, started_at=started_at, finished_at=time(), mode=setting['mode'])
        except Exception:
            # Metrics failure must preserve the original result, error and cancellation.
            pass

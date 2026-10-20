"""Best-effort local measurements; never participate in tool authority or routing."""
from __future__ import annotations

import os
from time import monotonic


async def observe_response(call, request, *, connection_id, workspace=None):
    if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '1') == '0':
        return await call(request)
    started = monotonic()
    result = None
    succeeded = False
    try:
        response = await call(request)
        result = getattr(response, 'root', response)
        succeeded = not bool(getattr(result, 'isError', False))
        return response
    finally:
        try:
            from .context_cost import ContextCostStore
            ContextCostStore().record_call(
                request.params.name, result, elapsed_ms=int((monotonic() - started) * 1000),
                transport='mcp', connection_id=connection_id, workspace=workspace,
                succeeded=succeeded)
        except Exception:
            # Metrics failure must preserve the original result, error and cancellation.
            pass

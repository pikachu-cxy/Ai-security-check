"""Optional bounded producer; tool completion never waits for monitor storage."""
from __future__ import annotations

import os
from time import monotonic, time

def bind_verified_chat(owner):
    # Compatibility for older embeddings; the product uses the inert port.
    try:
        from .observation import bind_chat
        bind_chat(owner)
    except Exception:
        pass


async def observe_response(call, request, *, connection_id, workspace=None, worker=None):
    # Security summaries promise not to initialize or mutate local state. The
    # optional observer must preserve that promise, including its own database.
    name = getattr(getattr(request, 'params', None), 'name', None)
    if (name == 'get_security_summary' or os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0'
            or os.getenv('SECURITY_RUNTIME_CONTEXT_MODE') == 'off'):
        return await call(request)
    try:
        from . import observation
        from .context_cost_worker import get_worker
        from .context_cost_capture import capture_response
        collector = None if observation.active() else worker if worker is not None else get_worker()
        setting = collector.snapshot_settings() if collector is not None else {}
        arguments = getattr(getattr(request, 'params', None), 'arguments', None)
        # Read only the route selector, never retain the argument dictionary.
        claimed_workspace = arguments.get('workspace_path') if isinstance(arguments, dict) else None
        if not isinstance(claimed_workspace, str) or not os.path.isabs(claimed_workspace) or len(claimed_workspace) > 4096:
            claimed_workspace = None
        observed_workspace = workspace or claimed_workspace
        capture, token = observation.begin_call() if setting.get('mode') in {'basic', 'debug'} else (None, None)
    except Exception:
        return await call(request)
    if capture is None:
        return await call(request)
    try:
        observation.bind_workspace(str(observed_workspace) if observed_workspace is not None else None)
    except Exception:
        pass
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
        finished_at, elapsed_ms = time(), int((monotonic() - started) * 1000)
        try:
            correlation = observation.end_call(capture, token)
            measurements, observations = capture_response(result, tool_name=name)
            collector.offer(dict(tool=name, transport='mcp', connection_id=connection_id,
                workspace=observed_workspace, run_label='unobserved-start-setting'
                if setting.get('source') == 'startup' else setting.get('run', 'default'),
                mode=setting['mode'], chat_owner=None if correlation['chat_conflict'] else capture.owner, succeeded=succeeded,
                elapsed_ms=elapsed_ms, started_at=started_at, finished_at=finished_at,
                measurements=measurements, observations=observations, correlation=correlation))
        except Exception:
            # Metrics failure must preserve the original result, error and cancellation.
            pass

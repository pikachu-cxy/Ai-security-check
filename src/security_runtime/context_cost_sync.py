"""Optional synchronous product boundary; no storage or shutdown waits."""
from functools import wraps
import os
import time


def observed(tool, *, transport='workspace'):
    def decorate(call):
        @wraps(call)
        def wrapper(*args, **kwargs):
            capture = None
            if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') != '0' and os.getenv('SECURITY_RUNTIME_CONTEXT_MODE') != 'off':
                try:
                    from . import observation
                    from .context_cost_worker import get_worker
                    collector = None if observation.active() else get_worker()
                    setting = collector.snapshot_settings() if collector is not None else {}
                    if setting.get('mode') in {'basic', 'debug'}:
                        capture, token = observation.begin_call()
                except Exception:
                    capture = None
            if capture is None:
                return call(*args, **kwargs)
            started, monotonic = time.time(), time.monotonic()
            result, succeeded = None, False
            try:
                result = call(*args, **kwargs)
                succeeded = True
                return result
            finally:
                try:
                    facts = observation.current_facts()
                    correlation = observation.end_call(capture, token)
                    from .context_cost_capture import capture_response
                    measurements, observations = capture_response(result, tool_name=tool)
                    collector.offer(dict(tool=tool, transport=transport,
                        workspace=facts.get('workspace'),
                        chat_owner=None if correlation.get('chat_conflict') else facts.get('owner'),
                        correlation=correlation, measurements=measurements, observations=observations,
                        succeeded=succeeded, started_at=started, finished_at=time.time(),
                        elapsed_ms=max(0, int((time.monotonic()-monotonic)*1000)), mode=setting['mode'],
                        run_label='unobserved-start-setting' if setting.get('source') == 'startup' else setting.get('run','default')))
                except Exception:
                    pass
        return wrapper
    return decorate

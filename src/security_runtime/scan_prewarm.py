"""Asynchronous preparation for observed development; never scans source."""
import logging
import threading

_lock = threading.Lock()
_requests = {}
logger = logging.getLogger(__name__)


def prepare(workspace, names=(), *, latest_names=None):
    from .scanners import OpenGrepAdapter
    from .scanner_cache import workspace_scope
    from .scanner_observation import observation
    from .scan_preferences import preferences
    from .rule_coverage import plan_rules
    with preferences(), workspace_scope(workspace), observation(str(workspace)):
        adapter = OpenGrepAdapter()
        pack = adapter.rule_packs.resolve()
        plan = plan_rules(pack, latest_names() if latest_names else names)
        if plan.rules:
            adapter.prepare_config(pack, plan.rules, workspace)
        # Publish config before probing the installed binary. The worker can
        # reuse it even when the bounded version probe is still running.
        adapter.tool_manager.resolve('opengrep')


def start(workspace, paths=(), *, batch=None):
    """Coalesce language hints. Return immediately without reading source."""
    from .sast_file_types import file_type
    names = {('target' + suffix if suffix else 'Dockerfile')
             for capability, suffix in map(file_type, paths) if capability is not None}
    key = (str(workspace), batch)
    with _lock:
        if key not in _requests:
            if len(_requests) >= 32:
                idle = next((k for k, v in _requests.items() if not v['running']), None)
                if idle is None:
                    return
                del _requests[idle]
            _requests[key] = dict(names=set(), prepared=None, running=False, failures=0)
        state = _requests[key]
        if names - state['names']:
            state['names'].update(names)
            state['failures'] = 0
        if state['running'] or state['prepared'] == state['names'] or state['failures'] >= 2:
            return
        state['running'] = True

    def work():
        while True:
            with _lock:
                selected = set(state['names'])
            def latest_names():
                nonlocal selected
                # New hints may arrive while the installed engine and rule pack
                # are being resolved. Plan once with the latest known types.
                with _lock:
                    selected = set(state['names'])
                return tuple(sorted(selected))

            try:
                from .performance_trace import span
                with span('scan.prewarm'):
                    prepare(workspace, latest_names=latest_names)
                success = True
            except Exception:
                success = False
                # Preparation is optional; closeout retains the normal path.
                logger.debug('Scan prewarming unavailable; closeout will prepare normally')
            with _lock:
                if success:
                    state['prepared'] = selected
                elif state['names'] == selected:
                    state['failures'] += 1
                if state['names'] == selected:
                    state['running'] = False
                    return
    thread = threading.Thread(target=work, daemon=True, name='scan-preparation')
    try:
        thread.start()
    except RuntimeError:
        with _lock:
            state['running'] = False

"""Asynchronous preparation for observed development; never scans source."""
import logging
from pathlib import Path
import threading

_lock = threading.Lock()
_requests = {}
logger = logging.getLogger(__name__)


def prepare(workspace, names=()):
    from .scanners import OpenGrepAdapter
    from .scanner_cache import workspace_scope
    from .scanner_observation import observation
    from .scan_preferences import preferences
    from .rule_coverage import plan_rules
    with preferences(), workspace_scope(workspace), observation(str(workspace)):
        adapter = OpenGrepAdapter()
        # Resolve installed tools only. Prewarming never installs or downloads.
        adapter.tool_manager.resolve('opengrep')
        pack = adapter.rule_packs.resolve()
        plan = plan_rules(pack, names)
        if plan.rules:
            adapter.prepare_config(pack, plan.rules, workspace)


def start(workspace, paths=()):
    """Coalesce language hints. Return immediately without reading source."""
    from .rule_catalog import EXTENSIONS
    extensions = {suffix for values in EXTENSIONS.values() for suffix in values}
    names = {('Dockerfile' if Path(name).name.lower() == 'dockerfile'
              else 'target' + Path(name).suffix.lower()) for name in paths
             if Path(name).suffix.lower() in extensions | {'.xml'}
             or Path(name).name.lower() == 'dockerfile'}
    key = str(workspace)
    with _lock:
        if key not in _requests:
            if len(_requests) >= 32:
                idle = next((k for k, v in _requests.items() if not v['running']), None)
                if idle is None:
                    return
                del _requests[idle]
            _requests[key] = dict(names=set(), prepared=None, running=False)
        state = _requests[key]
        state['names'].update(names)
        if state['running'] or state['prepared'] == state['names']:
            return
        state['running'] = True

    def work():
        while True:
            with _lock:
                selected = set(state['names'])
            try:
                prepare(workspace, tuple(sorted(selected)))
            except Exception:
                # Preparation is optional; closeout retains the normal path.
                logger.debug('Scan prewarming unavailable; closeout will prepare normally')
            with _lock:
                state['prepared'] = selected
                if state['names'] == selected:
                    state['running'] = False
                    return
    thread = threading.Thread(target=work, daemon=True, name='scan-preparation')
    try:
        thread.start()
    except RuntimeError:
        with _lock:
            state['running'] = False

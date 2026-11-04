"""Small adapter registry; unimplemented hosts have no normalized capabilities."""
from .host_events import HostCapabilities


def event_adapter(host):
    if host == 'codex':
        from .codex_event_adapter import CodexEventAdapter
        return CodexEventAdapter()
    if host == 'cursor':
        from .cursor_event_adapter import CursorHostEventAdapter
        return CursorHostEventAdapter()
    return None


def host_capabilities(host):
    adapter = event_adapter(host)
    return adapter.capabilities if adapter is not None else HostCapabilities()

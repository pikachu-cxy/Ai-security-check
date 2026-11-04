"""In-memory optional facts; never routing, authority or persistence.

Without an active capture every publisher is a no-op. References describe
relationships, not ownership; only existing validators may bind a chat.
"""
from contextvars import ContextVar
import re
from threading import Lock
from uuid import uuid4

_current = ContextVar('runtime_observation', default=None)
MAX_LINKS = 64
RELATIONS = frozenset({'TASK_RECORD_READ', 'TASK_CREATED', 'TASK_RESULT_RETURNED',
    'TASK_EVENT_TARGET', 'SCAN_PERSISTED', 'HOST_EVENT_CLAIMED',
    'HOST_EVENT_REUSED', 'HOST_EVENT_REFERENCED', 'HOST_EVENT_UNCONFIRMED', 'SCAN_RECORD_READ'})
_DIGEST = re.compile(r'[a-f0-9]{64}\Z')


class Capture:
    def __init__(self):
        self.call_id = uuid4().hex
        self.owner = None
        self.workspace = None
        self.host = None
        self.session_binding = None
        self.trigger_invocation_binding = None
        self.turn_binding = None
        self.links = []
        self.limited = False
        self.chat_conflict = False
        self.closed = False
        self.lock = Lock()

    def snapshot(self):
        return dict(call_id=self.call_id, host=self.host,
            session_binding=self.session_binding,
            trigger_invocation_binding=self.trigger_invocation_binding,
            turn_binding=self.turn_binding, links=[dict(row) for row in self.links],
            limited=self.limited, chat_conflict=self.chat_conflict)


def active():
    return _current.get() is not None


def begin_call():
    capture = Capture()
    return capture, _current.set(capture)


def current_facts():
    capture = _current.get()
    if capture is None or capture.closed:
        return {}
    if not capture.lock.acquire(blocking=False):
        return dict(correlation=dict(call_id=capture.call_id, links=[], limited=True, chat_conflict=True))
    try:
        return dict(correlation=capture.snapshot(), workspace=capture.workspace,
                    owner=dict(capture.owner) if capture.owner and not capture.chat_conflict else None)
    finally:
        capture.lock.release()


def bind_workspace(workspace):
    def update(capture):
        if type(workspace) is str and 0 < len(workspace) <= 4096:
            capture.workspace = workspace
    _update(update)


def end_call(capture, token):
    try:
        capture.closed = True
        if not capture.lock.acquire(blocking=False):
            # A late thread must not give the completed record half of a bind.
            return dict(call_id=capture.call_id, links=[], limited=True, chat_conflict=True)
        try:
            return capture.snapshot()
        finally:
            capture.lock.release()
    finally:
        _current.reset(token)


def _update(callback):
    capture = _current.get()
    if capture is None or capture.closed:
        return
    if not capture.lock.acquire(blocking=False):
        capture.limited = True
        return
    try:
        if not capture.closed:
            callback(capture)
    except Exception:
        capture.limited = True
    finally:
        capture.lock.release()


def bind_chat(owner):
    """Copy a previously verified owner; never grant authority here."""
    def update(capture):
        if (type(owner) is not dict or owner.get('host') not in {'codex', 'cursor'}
                or type(owner.get('session')) is not str
                or not _DIGEST.fullmatch(owner['session'])):
            return
        value = dict(host=owner['host'], session=owner['session'])
        if (capture.chat_conflict or capture.owner not in (None, value)
                or capture.host not in (None, value['host'])
                or capture.session_binding not in (None, value['session'])):
            capture.chat_conflict = True
            capture.owner = None
            capture.host = capture.session_binding = None
            capture.trigger_invocation_binding = capture.turn_binding = None
        else:
            capture.owner = value
            capture.host, capture.session_binding = value['host'], value['session']
    _update(update)


def bind_host(host, session_binding, invocation_binding=None, turn_binding=None):
    """The Hook's triggering tool is distinct from its carrying MCP call."""
    def update(capture):
        if capture.chat_conflict or host not in {'codex', 'cursor'}:
            return
        values = (session_binding, invocation_binding, turn_binding)
        if (type(session_binding) is not str or not _DIGEST.fullmatch(session_binding)
                or any(value is not None and (type(value) is not str or not _DIGEST.fullmatch(value))
                       for value in values)):
            return
        if ((capture.owner is not None and capture.owner != dict(host=host, session=session_binding))
                or capture.host not in (None, host)
                or capture.session_binding not in (None, session_binding)
                or invocation_binding is not None and capture.trigger_invocation_binding not in (None, invocation_binding)
                or turn_binding is not None and capture.turn_binding not in (None, turn_binding)):
            capture.chat_conflict = True
            capture.owner = None
            capture.host = capture.session_binding = None
            capture.trigger_invocation_binding = capture.turn_binding = None
            return
        capture.host, capture.session_binding = host, session_binding
        if invocation_binding is not None:
            capture.trigger_invocation_binding = invocation_binding
        if turn_binding is not None:
            capture.turn_binding = turn_binding
    _update(update)


def bind_product(kind, reference, *, relation):
    def update(capture):
        if (kind not in {'task', 'scan', 'host_event'} or relation not in RELATIONS
                or type(reference) is not str or not 0 < len(reference) <= 256
                or not re.fullmatch(r'[A-Za-z0-9_.:-]+', reference)):
            return
        row = dict(kind=kind, reference=reference, relation=relation)
        if row in capture.links:
            return
        if len(capture.links) >= MAX_LINKS:
            capture.limited = True
        else:
            capture.links.append(row)
    _update(update)

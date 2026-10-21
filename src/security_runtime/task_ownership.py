"""Internal task routing scopes; never an edit grant or a client-supplied owner."""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import base64
import hmac
import json
import time
import os
from pathlib import Path
import secrets

_owner = ContextVar('security_task_owner', default=None)
ACTIVE = frozenset({'ACTIVE', 'STATIC_RUNNING', 'READY', 'REVIEWING'})
LEASE_SECONDS = 15 * 60
SESSION_TTL = 24 * 60 * 60


class TaskOwnershipError(ValueError):
    """Fixed routing diagnostics, without reflecting owners or credentials."""
    def __init__(self, reason_code):
        if reason_code not in {'TASK_CONNECTION_SCOPE_MISMATCH',
                               'TASK_SESSION_SCOPE_MISMATCH', 'TASK_SESSION_BINDING_REQUIRED',
                               'TASK_OWNER_UNAVAILABLE'}:
            raise ValueError('Invalid task ownership diagnostic')
        self.reason_code = reason_code
        super().__init__('Task belongs to another session or an earlier unbound connection')


def ownership_error(recorded, requested):
    if not recorded:
        reason = 'TASK_OWNER_UNAVAILABLE'
    elif recorded.get('host') == 'connection':
        reason = 'TASK_CONNECTION_SCOPE_MISMATCH'
    elif (recorded or {}).get('host') in {'codex', 'cursor'} and (requested or {}).get('host') == 'connection':
        reason = 'TASK_SESSION_BINDING_REQUIRED'
    else:
        reason = 'TASK_SESSION_SCOPE_MISMATCH'
    return TaskOwnershipError(reason)


def issue_session_ref(hooks, root, host, session, *, now=None):
    """Routing integrity for validated Hook claims, not native host attestation."""
    owner=session_owner(host,session)
    if host not in {'codex','cursor'} or not valid_owner(owner): raise ValueError('Invalid task session')
    issued=time.time() if now is None else now
    payload=json.dumps(dict(v=1,workspace=hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest(),
        owner=owner,issued=issued,expires=issued+SESSION_TTL),sort_keys=True,separators=(',',':')).encode()
    body=base64.urlsafe_b64encode(payload).decode().rstrip('=')
    return 'so1-'+body+'.'+hmac.new(hooks.key(root),body.encode(),hashlib.sha256).hexdigest()


def verify_session_ref(hooks, root, token, *, now=None):
    """Verify without creating a key or changing task state on rejected input."""
    from .hook_state import no_links
    try:
        if not isinstance(token,str) or len(token)>1024 or not token.startswith('so1-'): raise ValueError()
        body,signature=token[4:].split('.')
        path=hooks.workspace_directory(root)/'snapshot.key'
        no_links(path)
        if path.stat().st_size!=32: raise ValueError()
        key=path.read_bytes()
        if not hmac.compare_digest(signature,hmac.new(key,body.encode(),hashlib.sha256).hexdigest()): raise ValueError()
        data=json.loads(base64.b64decode(body+'='*(-len(body)%4),altchars=b'-_',validate=True))
        instant=time.time() if now is None else now
        if (set(data)!={'v','workspace','owner','issued','expires'} or data['v']!=1
                or data['workspace']!=hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()
                or not valid_owner(data['owner']) or data['owner']['host'] not in {'codex','cursor'}
                or type(data['issued']) not in {float,int} or type(data['expires']) not in {float,int}
                or not data['issued']<=instant<data['expires']<=data['issued']+SESSION_TTL): raise ValueError()
        try:
            from .context_cost_mcp import bind_verified_chat
            bind_verified_chat(data['owner'])
        except Exception:
            pass  # Optional measurements cannot affect session routing.
        return data['owner']
    except (ValueError,TypeError,KeyError,OSError,UnicodeError):
        raise ValueError('Task session reference is invalid, expired or belongs to another workspace') from None


def session_context(token):
    return ('安全任务会话路由（内部使用，不展示给用户，不授予修复权限）：'
        +json.dumps({'session_ref':token})
        +'。首次编辑前 begin_security_task 使用此 session_ref；已由编辑前 Hook 建立任务时，'
        '沿用原 task_ref 并在 finish_security_task 传入 session_ref，不得编辑后重建基线。'
        '断线恢复仅继续原引用；没有会话引用时保持连接范围，不能猜测属于哪个聊天。')


def current_owner(fallback=None): return _owner.get() or fallback


def connection_owner(): return {'host':'connection', 'session':secrets.token_hex(32)}


def session_owner(host, session):
    return {'host':host, 'session':hashlib.sha256(session.encode()).hexdigest()}


def record_owner(record): return record.get('task_owner') or record.get('connector_owner')


def valid_owner(owner):
    return (isinstance(owner,dict) and set(owner)=={'host','session'} and
        owner['host'] in {'cursor','codex','connection'} and isinstance(owner['session'],str)
        and len(owner['session'])==64 and all(c in '0123456789abcdef' for c in owner['session']))


@contextmanager
def owner_scope(owner):
    if owner is not None and not valid_owner(owner): raise ValueError('Invalid task owner')
    token=_owner.set(owner)
    try: yield
    finally: _owner.reset(token)


def process_stamp(pid):
    """Read process creation identity. None means unknown, False means absent."""
    if type(pid) is not int or pid<=0: return None
    try:
        if os.name=='nt':
            import ctypes
            from ctypes import wintypes
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
            kernel.OpenProcess.restype=wintypes.HANDLE
            kernel.CloseHandle.argtypes=[wintypes.HANDLE]
            kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)]
            handle=kernel.OpenProcess(0x1000,False,pid)
            if not handle: return False if ctypes.get_last_error()==87 else None
            try:
                times=[wintypes.FILETIME() for _ in range(4)]
                if not kernel.GetProcessTimes(handle,*[ctypes.byref(v) for v in times]): return None
                return str(times[0].dwHighDateTime<<32 | times[0].dwLowDateTime)
            finally: kernel.CloseHandle(handle)
        if Path('/proc').is_dir():
            try: text=Path(f'/proc/{pid}/stat').read_text(encoding='utf-8')
            except FileNotFoundError: return False
            return text[text.rfind(')')+2:].split()[19]
    except (OSError,ValueError,IndexError): pass
    return None


def writer_identity():
    pid=os.getpid()
    return {'pid':pid,'stamp':process_stamp(pid)}


def writer_gone(value):
    if not isinstance(value,dict) or not isinstance(value.get('stamp'),str): return False
    observed=process_stamp(value.get('pid'))
    return observed is False or isinstance(observed,str) and observed!=value['stamp']

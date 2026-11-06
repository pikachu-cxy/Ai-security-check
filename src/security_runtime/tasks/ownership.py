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
import sys

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
    elif (recorded or {}).get('host') in {'codex', 'cursor', 'workbuddy'} and (requested or {}).get('host') == 'connection':
        reason = 'TASK_SESSION_BINDING_REQUIRED'
    else:
        reason = 'TASK_SESSION_SCOPE_MISMATCH'
    return TaskOwnershipError(reason)


def issue_session_ref(hooks, root, host, session, *, now=None, compact=False):
    """Routing integrity for validated Hook claims, not native host attestation."""
    if compact:
        from .session_handles import issue_session_handle
        return issue_session_handle(hooks, root, host, session,
                                    now=time.time if now is None else lambda: now)
    owner=session_owner(host,session)
    if host not in {'codex','cursor','workbuddy'} or not valid_owner(owner): raise ValueError('Invalid task session')
    issued=time.time() if now is None else now
    payload=json.dumps(dict(v=1,workspace=hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest(),
        owner=owner,issued=issued,expires=issued+SESSION_TTL),sort_keys=True,separators=(',',':')).encode()
    body=base64.urlsafe_b64encode(payload).decode().rstrip('=')
    return 'so1-'+body+'.'+hmac.new(hooks.key(root),body.encode(),hashlib.sha256).hexdigest()


def verify_session_ref(hooks, root, token, *, now=None):
    """Verify without creating a key or changing task state on rejected input."""
    from ..hook_state import no_links
    try:
        if isinstance(token, str) and token.startswith('sh1-'):
            from .session_handles import verify_session_handle
            owner = verify_session_handle(hooks, root, token, now=now)
            try:
                from ..observation import bind_chat
                bind_chat(owner)
            except Exception:
                pass
            return owner
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
                or not valid_owner(data['owner']) or data['owner']['host'] not in {'codex','cursor','workbuddy'}
                or type(data['issued']) not in {float,int} or type(data['expires']) not in {float,int}
                or not data['issued']<=instant<data['expires']<=data['issued']+SESSION_TTL): raise ValueError()
        try:
            from ..observation import bind_chat
            bind_chat(data['owner'])
        except Exception:
            pass  # Optional measurements cannot affect session routing.
        return data['owner']
    except (ValueError,TypeError,KeyError,OSError,UnicodeError):
        raise ValueError('Task session reference is invalid, expired or belongs to another workspace') from None


def session_context(token, *, native_stop=False, workspace=None, grouped_codex=False):
    if native_stop and workspace is not None:
        from ..hooks import codex_commit_only
        if codex_commit_only(workspace):
            return ('安全任务会话路由（内部使用）：' + json.dumps({'session_ref': token})
                    + '。当前仓库由 Git pre-commit 检查暂存内容。普通开发无需主动安全 MCP 或 Stop 收尾，'
                    '未提交内容尚未检查。显式审计和修复沿原任务继续。')
    if native_stop:
        from ..user_config import describe_config
        config = describe_config()
        if config.get('values', {}).get('development', {}).get('stop_fallback', {}).get('enabled'):
            if grouped_codex:
                request = json.dumps({'operation': 'get_development_risks', 'arguments': {
                    'workspace_path': str(workspace), 'session_ref': token,
                    'check_ref': '<检查编号>', 'view': 'review'}}, ensure_ascii=False)
                return ('普通开发由编辑 Hook 记录路径、Stop 自动收尾，无待办无需主动调用安全 MCP。'
                    '收到“安全检查待复核”时，仅将下例的 <检查编号> 替换为提醒中的原编号，'
                    '直接执行取证，无需查工具目录或重复提示进度：\n'
                    f'text((await tools.mcp__ai_security_runtime__development_review({request})).content)\n'
                    '核对 dirty_seq 与提醒版本；按 next_offset 续读同一视图。候选 evidence_refs 为空或证据不足时，按其完整起止行补读。按配置判断后用同一工具提交 operation=submit_development_review。'
                    'arguments 沿用 workspace_path、session_ref、check_ref，必填 expected_seq=本次 dirty_seq、'
                    '在 arguments 顶层只传一次本页 scan_id；observations 每项含 same_issue_as、decision、rationale、evidence_refs，'
                    'decision 用 CONFIRMED（确认）、DISMISSED（误报）或 INCONCLUSIVE（证据不足）。'
                    '确认漏洞时在该项 report_text 一次写好给用户的完整说明（标题、评级来源、路径行号、'
                    '问题、可能影响、建议修复、尚未确认）；误报由产品汇总。按需附 business_reviews，'
                    '仅在证据指向同一问题时把重复项标 DISMISSED 并传 duplicate_of=同批确认项 id。仅监听到的文件不可归因为当前会话写入。传 return_risks=true 和 response_view="final_report"。成功后仅沿本批 next_action 读完。最终回复先用一句话保留原开发结果和实际验证，再原样附上返回的 '
                    'report_text，不重写；未提供时按实际结果及缺口报告。'
                    '已知漏记的实际编辑才补录。显式审计及修复继续沿用原任务。')
            return ('安全任务会话路由（内部使用）：' + json.dumps({'session_ref': token})
                + '。普通开发由编辑 Hook 记录路径、Stop 自动收尾，无待办无需主动调用安全 MCP。'
                '收到“安全检查待复核”即沿原检查编号调用 get_development_risks(include_evidence=true)；'
                'Hook 已向用户显示进度，直接取证，提交复核后统一回复。已知漏记的实际编辑才补录。'
                '显式审计及修复继续沿用原任务。')

    return ('安全任务会话路由（内部使用，不展示给用户，不授予修复权限）：'
        +json.dumps({'session_ref':token})
        +'。默认开发使用无全项目基线的 begin_development_check；已由编辑 Hook 返回 check_ref 时沿用，'
        'Hook 与 record_development_changes 仅记录路径，不扫描。完成编辑后 finish_development_check 调度后台检查，'
        '再 get_development_check 读取实际范围和保存结果；后续编辑须再次收尾，调用均携带此 session_ref。'
        '已有严格审计或原生修复沿原 task_ref 和 task-review 方法继续，不迁移或重建基线。'
        '断线恢复仅继续原引用；没有会话引用时保持连接范围，不能猜测属于哪个聊天。')


def current_owner(fallback=None): return _owner.get() or fallback


def connection_owner(): return {'host':'connection', 'session':secrets.token_hex(32)}


def session_owner(host, session):
    return {'host':host, 'session':hashlib.sha256(session.encode()).hexdigest()}


def record_owner(record): return record.get('task_owner') or record.get('connector_owner')


def valid_owner(owner):
    return (isinstance(owner,dict) and set(owner)=={'host','session'} and
        owner['host'] in {'cursor','codex','workbuddy','connection'} and isinstance(owner['session'],str)
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
        if sys.platform == 'darwin':
            import re
            import subprocess
            try:
                result = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart='],
                    capture_output=True, text=True, timeout=1,
                    env={**os.environ, 'LC_ALL': 'C'})
            except subprocess.SubprocessError:
                return None
            value = result.stdout.strip()
            if result.returncode == 1 and not value and not result.stderr.strip():
                return False
            if (result.returncode == 0 and not result.stderr.strip()
                    and re.fullmatch(r'[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}', value)):
                return 'darwin-' + ' '.join(value.split())
    except (OSError,ValueError,IndexError): pass
    return None


def writer_identity():
    pid=os.getpid()
    return {'pid':pid,'stamp':process_stamp(pid)}


def writer_gone(value):
    if not isinstance(value,dict) or not isinstance(value.get('stamp'),str): return False
    observed=process_stamp(value.get('pid'))
    return observed is False or isinstance(observed,str) and observed!=value['stamp']

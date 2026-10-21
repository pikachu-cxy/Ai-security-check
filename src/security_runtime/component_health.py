"""Fixed component diagnoses, explicit local repair and durable notice delivery.

No raw engine output or settings contents are stored or displayed. Health is
availability information, never project scan evidence or repair authorization.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .diagnostics import ErrorDiagnostic
from .hook_state import HookStateStore, no_links
from .storage import SQLiteStore


LABELS = {'semgrep': '代码检查', 'gitleaks': '密钥检查', 'trivy': '依赖检查'}
ISSUES = {
    'ENGINE_TEMP_DIRECTORY_UNAVAILABLE': ('无法准备引擎专用的短私有临时目录。', '检查目录权限，或将 SECURITY_RUNTIME_ENGINE_TEMP_ROOT 指向项目外已存在的短本地目录；不要修改系统临时目录。'),
    'ENGINE_TEMP_PATH_TOO_LONG': ('引擎临时目录超过本地通信地址的长度预算。', '为 SECURITY_RUNTIME_ENGINE_TEMP_ROOT 选择更短的本地目录；不会自动使用共享目录或放宽权限。'),
    'ENGINE_LOCAL_IPC_DENIED': ('执行环境拒绝引擎创建本地通信通道。', '在获准支持本地通信的环境运行检查；不要关闭沙箱、安全防护或重复下载组件。'),
    'ENGINE_LOCAL_IPC_PATH_LIMIT': ('引擎本地通信地址超过底层路径预算。', '核对引擎私有临时目录和固定版本兼容性；无需重装全部组件。'),
    'ENGINE_LOCAL_IPC_FAILED': ('引擎本地通信初始化失败，具体原因尚未确认。', '核对执行环境的本地通信权限和临时目录；保留组件，不将失败当作检查通过。'),
    'ENGINE_EXECUTION_PROBE_FAILED': ('组件版本可读取，但合成扫描未能确认引擎可执行。', '核对本地引擎环境及诊断；本次没有扫描项目，不自动重装组件。'),
    'RUNTIME_PROBE_FAILED': ('产品的组件探测出现异常，尚未确认组件当前状态。', '保留现有组件，先重试状态查询；持续失败时提供诊断编号，无需直接重装组件。'),
    'COMPONENT_MISSING': ('组件尚未安装。', '联网准备此组件；已有其他组件继续保留。'),
    'COMPONENT_VERSION_MISMATCH': ('已安装版本与当前要求不符。', '准备当前要求的固定版本；不要替换用户指定的外部程序。'),
    'COMPONENT_SETTINGS_CORRUPTED': ('Semgrep 用户设置文件损坏，组件已安装但无法启动。', '先备份损坏设置，再重建默认设置；无需重新下载组件。'),
    'COMPONENT_SETTINGS_UNREADABLE': ('无法读取 Semgrep 用户设置。', '检查设置文件权限或链接路径；不要删除设置或重新下载组件。'),
    'COMPONENT_PERMISSION_DENIED': ('系统拒绝启动检查组件。', '检查文件权限或系统拦截记录；不要关闭安全防护或重复下载。'),
    'COMPONENT_START_TIMEOUT': ('组件启动检查超时。', '检查本机进程和资源占用，再查询状态；不会自动重新下载。'),
    'COMPONENT_DEPENDENCY_BROKEN': ('组件的 Python 依赖缺失或不兼容。', '核对该组件的 Python 环境；需要重装时应明确选择该组件。'),
    'COMPONENT_START_FAILED': ('组件已安装，但启动检查失败，具体原因尚未确认。', '查看本机组件环境；不会把启动失败当作未安装而重新下载。'),
    'COMPONENT_PACKAGE_INCOMPLETE': ('组件安装文件或归属记录不完整。', '核对安装目录；确需重装时显式选择该组件，现有文件不自动删除。'),
    'COMPONENT_INTEGRITY_FAILED': ('组件文件未通过完整性校验。', '保留当前文件并核对来源；不要绕过校验，重装需要明确选择。'),
    'COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE': ('组件版本可读取，但无法核实实际执行程序及其 Python 包。', '将 Semgrep 路径指向完整虚拟环境中的 bin/semgrep 或 Scripts/semgrep.exe，并使用受管或复制到该环境的解释器；外部包装脚本不会自动获准。'),
    'ENGINE_MISSING_OFFLINE': ('本地尚未安装所需检查组件，本轮仅使用本地组件。', '联网时单独准备缺少的组件，再重试检查；本轮不会自动下载。'),
    'NETWORK_TIMEOUT': ('组件下载连接超时。', '检查网络后再重试准备；不要重新安装整个产品。'),
    'DOWNLOAD_STALLED': ('组件下载长时间没有可验证进度。', '检查网络或代理后再重试准备。'),
    'PREPARATION_BUDGET_EXHAUSTED': ('本次组件准备时间已耗尽。', '保留已有缓存，确认网络后再重试准备。'),
    'TLS_ERROR': ('组件下载的安全连接校验失败。', '检查证书、代理和系统时间；不要关闭安全连接校验。'),
    'DNS_RESOLUTION_FAILED': ('无法解析组件下载地址。', '检查网络和域名解析后再重试准备。'),
    'CONNECTION_REFUSED': ('组件下载连接被拒绝。', '检查网络或代理配置后再重试准备。'),
    'PROXY_CONNECTION_FAILED': ('组件下载无法连接代理。', '检查代理是否运行及配置是否正确，再重试准备。'),
    'DOWNLOAD_INTERRUPTED': ('组件下载中断。', '已有可用组件保留，确认网络后再重试准备。'),
    'UNKNOWN_NETWORK_ERROR': ('组件下载遇到尚未确定的网络错误。', '核对网络和代理；不要直接重装全部组件。'),
    'HTTP_401': ('组件下载源要求授权。', '核对下载源访问条件，不在聊天中提供令牌。'),
    'HTTP_403': ('组件下载源拒绝访问。', '核对网络及下载源访问策略后再重试。'),
    'HTTP_404': ('固定版本的下载资源不存在。', '核对发布资源；不要使用未知来源替代。'),
    'HTTP_429': ('组件下载源限制了请求频率。', '等待限流解除后再重试，不连续重复下载。'),
    'HTTP_5XX': ('组件下载服务暂时异常。', '等待服务恢复后再重试，已有组件保留。'),
    'CHECKSUM_MISMATCH': ('下载内容未通过完整性校验。', '不要使用该下载文件或绕过校验，核对固定版本的官方来源。'),
    'PYTHON_PACKAGE_PREPARATION_FAILED': ('组件的 Python 包准备失败，尚未确认具体原因。', '核对组件环境及下载条件；不要反复重装整个产品。'),
    'CONFIG_CORRUPTED': ('组件配置或安装元信息无法正常读取。', '核对对应配置和归属记录；不要通过重复下载覆盖现场。'),
    'OFFLINE_MODE': ('离线模式下缺少可用组件。', '已有缓存保留，联网后再明确启动准备。'),
    'LICENSE_BLOCKED': ('该组件的授权策略不允许自动下载。', '按组件许可要求配置已有程序；不要绕过授权策略。'),
    'PYTHON_BOOTSTRAP_FAILED': ('组件所需的 Python 环境准备失败。', '核对本机 Python 环境；其他已就绪组件继续保留。'),
    'COMPONENT_UNSUPPORTED_PLATFORM': ('当前平台没有受支持的组件安装包。', '核对产品支持范围，不自动改用未知来源。'),
}


def diagnosis(code):
    code = code if code in ISSUES else 'COMPONENT_START_FAILED'
    message, remedy = ISSUES[code]
    return ErrorDiagnostic(code, message, remedy)


def component_issue(component, status, diagnostic=None):
    if status == 'READY':
        return None
    code = getattr(diagnostic, 'error_code', '')
    if code not in ISSUES:
        code = {'MISSING': 'COMPONENT_MISSING', 'VERSION_MISMATCH': 'COMPONENT_VERSION_MISMATCH',
                'OFFLINE': 'OFFLINE_MODE', 'UNSUPPORTED_PLATFORM': 'COMPONENT_UNSUPPORTED_PLATFORM'}.get(status, 'COMPONENT_START_FAILED')
    message, remedy = ISSUES[code]
    repair = (['security-check', 'tools', 'repair', 'semgrep']
        if component == 'semgrep' and code == 'COMPONENT_SETTINGS_CORRUPTED' else [])
    return {'code': code, 'message': message, 'remediation': remedy,
            'affected_capability': LABELS.get(component, '检查组件'),
            'automatic_download': code in {'COMPONENT_MISSING', 'COMPONENT_VERSION_MISMATCH'},
            'repair_command': repair}


def valid_issue(component, value):
    if not isinstance(value, dict) or value.get('code') not in ISSUES:
        return False
    expected = component_issue(component, 'BROKEN', diagnosis(value['code']))
    if expected['automatic_download'] and value.get('automatic_download') is False:
        # Explicit user-selected executables are never replaced automatically.
        expected['automatic_download'] = False
    return value == expected


def semgrep_settings_path():
    explicit = os.getenv('SEMGREP_SETTINGS_FILE')
    if explicit:
        return Path(os.path.abspath(os.path.expanduser(explicit)))
    home = Path(os.getenv('XDG_CONFIG_HOME', ''))
    if not os.getenv('XDG_CONFIG_HOME') or not home.is_dir():
        home = Path.home()
    return Path(os.path.abspath(home / '.semgrep' / 'settings.yml'))


def _settings_bytes():
    path = semgrep_settings_path()
    no_links(path)
    if not path.exists():
        return path, None, None
    before = path.stat()
    if not path.is_file() or before.st_size > 65_536:
        raise ValueError('Settings cannot be inspected safely')
    with path.open('rb') as stream:
        raw = stream.read(65_537)
    after = path.stat()
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if len(raw) > 65_536 or stamp(before) != stamp(after):
        raise ValueError('Settings changed during inspection')
    return path, raw, stamp(after)


def settings_problem():
    try:
        _, raw, _ = _settings_bytes()
        if raw is None:
            return None
        import yaml
        try:
            value = yaml.safe_load(raw)
        except (yaml.YAMLError, UnicodeError, ValueError, RecursionError):
            return diagnosis('COMPONENT_SETTINGS_CORRUPTED')
        if value is not None and not isinstance(value, dict):
            return diagnosis('COMPONENT_SETTINGS_CORRUPTED')
        return None
    except (OSError, ValueError):
        return diagnosis('COMPONENT_SETTINGS_UNREADABLE')


def settings_fingerprint(*, include_metadata=True):
    path, raw, stamp = _settings_bytes()
    # Probe reuse also expires on replacement. Execution binds actual settings
    # bytes: Semgrep atomically rewrites unchanged settings during normal runs.
    metadata = repr(stamp).encode() if include_metadata else (b'MISSING' if raw is None else b'PRESENT')
    return hashlib.sha256(str(path).encode() + metadata + (raw or b'')).digest()


class ComponentHealthStore:
    """SQLite compare-and-swap notices survive process and Host reconnections."""
    def __init__(self, path=None, *, scope='default'):
        self.path = Path(path or SQLiteStore.default_path().parent / 'component-health.db')
        self.scope = hashlib.sha256(str(scope).encode()).hexdigest()

    def observe(self, tools, *, consume=True):
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        notices = []
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS component_health '
                '(scope TEXT, component TEXT, fingerprint TEXT, failed INTEGER, pending TEXT, '
                'PRIMARY KEY(scope, component))')
            db.execute('BEGIN IMMEDIATE')
            for component, current in tools.items():
                if component not in LABELS:
                    continue
                failed = current.get('ready') is not True
                issue = current.get('diagnostic')
                if failed and not valid_issue(component, issue):
                    issue = component_issue(component, current.get('status'))
                from .component_probe import probe_fault_id
                fault_id = probe_fault_id(current.get('probe')) if failed else ''
                identity = [current.get('expected_version'), issue['code'] if failed else 'READY']
                if fault_id:
                    identity.append(fault_id)
                fingerprint = json.dumps(identity, separators=(',', ':'))
                previous = db.execute('SELECT fingerprint,failed,pending FROM component_health '
                    'WHERE scope=? AND component=?', (self.scope, component)).fetchone()
                pending = previous[2] if previous else None
                if previous is None or previous[0] != fingerprint:
                    event = None
                    if failed:
                        event = {'component': component, 'kind': 'FAULT', 'code': issue['code']}
                    elif previous and previous[1]:
                        event = {'component': component, 'kind': 'RECOVERED', 'code': 'READY'}
                    pending = json.dumps(event) if event else None
                if pending and consume:
                    # Persisted state is not trusted as user-facing prose.
                    event = json.loads(pending)
                    if (event.get('component') == component and event.get('kind') in {'FAULT', 'RECOVERED'}
                            and event.get('code') == (issue['code'] if failed else 'READY')):
                        event['message'] = (LABELS[component] + '已恢复可用；这不代表项目已通过安全检查。'
                            if not failed else LABELS[component] + '不可用：' + issue['message'] + issue['remediation'])
                        if fault_id:
                            event['message'] += '诊断编号：' + fault_id + '。'
                        notices.append(event)
                    pending = None
                db.execute('INSERT OR REPLACE INTO component_health VALUES(?,?,?,?,?)',
                    (self.scope, component, fingerprint, int(failed), pending))
        return {'contract': 'component-health-v1', 'notify': bool(notices), 'notifications': notices,
                'message': '\n'.join(item['message'] for item in notices),
                'presentation': '仅通知新增故障或恢复。相同故障不重复提醒；用户主动查询时仍可说明当前状态。'}


def component_feedback(tools, *, root=None, consume=True, store=None):
    try:
        if root is None:
            from .toolchain import default_data_root
            root = default_data_root()
        return (store or ComponentHealthStore(scope=os.path.normcase(str(root)))).observe(tools, consume=consume)
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return {'contract': 'component-health-v1', 'notify': False, 'notifications': [],
                'message': '', 'notice_state': 'UNAVAILABLE'}


def repair_semgrep_settings(*, manager=None):
    """Explicit repair only. Back up invalid settings; never reinstall engines."""
    from .toolchain import ToolManager, ToolStatus
    manager = manager or ToolManager()
    path = semgrep_settings_path()
    problem = settings_problem()
    if problem is None or problem.error_code != 'COMPONENT_SETTINGS_CORRUPTED':
        return {'status': 'NOT_APPLICABLE', 'message': '未确认设置文件损坏，未修改任何设置。',
                'downloaded': False, 'settings_modified': False}
    locks = HookStateStore(SQLiteStore.default_path().parent / 'component-repair-locks')
    with locks.lock(path.parent, wait_seconds=1) as locked:
        if not locked:
            return {'status': 'BUSY', 'message': '另一个组件修复正在进行，本次未修改设置。',
                    'downloaded': False, 'settings_modified': False}
        path, raw, stamp = _settings_bytes()
        problem = settings_problem()
        if raw is None or problem is None or problem.error_code != 'COMPONENT_SETTINGS_CORRUPTED':
            return {'status': 'CHANGED', 'message': '设置已变化，未覆盖其他修改。',
                    'downloaded': False, 'settings_modified': False}
        backup = path.with_name(path.name + '.corrupt-backup-' + uuid.uuid4().hex)
        with backup.open('xb') as stream:
            os.chmod(backup, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        no_links(path)
        _, latest, current_stamp = _settings_bytes()
        if current_stamp != stamp or latest != raw:
            return {'status': 'CHANGED', 'message': '设置已变化，保留备份且未覆盖当前设置。',
                    'backup_path': str(backup), 'downloaded': False, 'settings_modified': False}
        # Recreate only the confirmed corrupt file, without overwriting a new
        # file created concurrently by Semgrep. A missing file uses defaults.
        path.unlink()
        try:
            with path.open('x', encoding='utf-8') as stream:
                os.chmod(path, 0o600)
                stream.write('{}\n')
        except FileExistsError:
            pass
        result = manager.resolve('semgrep')
        from .install_readiness import _component
        health = component_feedback({'semgrep': _component(result, manager.versions['semgrep'], 'semgrep')}, root=manager.root)
        return {'status': 'REPAIRED' if result.status == ToolStatus.READY else 'NOT_READY',
                'message': '损坏设置已备份并重建。' + ('代码检查组件已恢复。' if result.status == ToolStatus.READY else '组件仍不可用，请查看具体诊断。'),
                'backup_path': str(backup), 'downloaded': False, 'settings_modified': True,
                'component': _component(result, manager.versions['semgrep'], 'semgrep'), 'component_health': health}

"""Flushed, stderr-only installation feedback; never an installation receipt."""
from __future__ import annotations

import sys
import threading
import time
import json
import re
import os
import shutil
import unicodedata
import math
from collections import deque
from .download_estimate import DownloadEstimate


STAGES = {
    'START': '开始安装 AI Security Runtime；不会扫描项目或自动修复漏洞。',
    'LAUNCHER_VERIFY': '正在检查固定启动器和已安装程序包。',
    'PREPARE': '正在准备本地安装；不会重复下载扫描器，已有有效缓存会继续使用。',
    'PACKAGE_VERIFY': '正在校验安装包完整性。',
    'CHECK_CONFIG': '正在检查现有配置和 Skill，避免覆盖用户内容。',
    'COPY_RUNTIME': '正在复制 Runtime 到固定安装目录。',
    'VERIFY_INSTALLED': '正在校验安装目录中的程序文件。',
    'CAPABILITY_CHECK': '正在启动 Runtime，检查连接能力。',
    'PREPARE_LAUNCHER': '正在准备固定启动器。',
    'VERIFY_ACTIVATION': '正在校验程序激活状态。',
    'SETUP_CHILD': '正在部署全局连接和专业 Skill，并执行安装自检（子程序最多等待 120 秒）。',
    'APPLY_CONFIG': '正在协同部署全局连接和专业 Skill。',
    'MIGRATE_CONFIG': '正在迁移产品托管的旧配置，保留用户内容。',
    'GLOBAL_CONFIG': '正在配置全局 MCP、Hook，并检查 Runtime 连接。',
    'SKILL': '正在安装或更新专业 Skill。',
    'SELF_CHECK': '正在自检全局配置和 Skill。',
    'VERIFY_RECEIPT': '正在核对安装结果。',
    'CHECK_SCAN_CACHE': '正在核对已有扫描组件和漏洞库；本次安装不等待联网下载。',
    'START_BACKGROUND': '正在启动后台扫描能力准备；安装不会等待下载，无需手动执行前置命令。',
    'INSTALL_TOOLS': '正在自动准备安全检查组件和漏洞数据；已有有效缓存会继续使用，首次准备可能需要下载。',
    'INSTALL_DATA': '正在更新漏洞数据，已有可用数据会在新数据准备完成前保留。',
    'VERIFY_SCAN_READINESS': '正在确认代码、密钥和依赖检查是否已准备完成，并检查漏洞数据有效期。',
    'VERIFY_DOWNLOADED_DATA': '传输接近完成，正在等待解压和数据校验结果；尚未确认就绪。',
    'RECOVERY': '正在检查并安全恢复本次中断的安装。',
    'CLEANUP': '正在清理已停用的旧版本；使用中的文件和用户内容会保留。',
    'DELTA_VERIFY': '正在校验增量升级包及本地基础版本。',
    'DELTA_APPLY': '正在复用未变化的程序文件，准备增量升级。',
}

PREPARATION_STAGES = frozenset({'INSTALL_TOOLS', 'INSTALL_DATA', 'VERIFY_SCAN_READINESS'})
STAGE_PREFIX = 'AI_SECURITY_INSTALL_STAGE:'
EVENT_PREFIX = 'AI_SECURITY_PREPARATION_EVENT:'
_EVENTS = {'DOWNLOAD_STARTED', 'DOWNLOAD_PROGRESS', 'DOWNLOAD_RETRY', 'DOWNLOAD_FAILED', 'DOWNLOAD_COMPLETE', 'DOWNLOAD_FALLBACK', 'DOWNLOAD_VALIDATING',
    'COMPONENT_STARTED', 'COMPONENT_COMPLETE', 'COMPONENT_FAILED'}
_ERRORS = {'', 'NETWORK_TIMEOUT', 'DOWNLOAD_STALLED', 'PREPARATION_BUDGET_EXHAUSTED',
    'TLS_ERROR', 'DNS_RESOLUTION_FAILED', 'CONNECTION_REFUSED', 'PROXY_CONNECTION_FAILED',
    'DOWNLOAD_INTERRUPTED', 'UNKNOWN_NETWORK_ERROR', 'HTTP_401', 'HTTP_403', 'HTTP_404',
    'HTTP_429', 'HTTP_5XX', 'VULNERABILITY_DB_PREPARATION_FAILED', 'CHECKSUM_MISMATCH', 'DOWNLOAD_BUSY',
    'ENGINE_UNAVAILABLE', 'DOWNLOAD_FAILED', 'PYTHON_PACKAGE_PREPARATION_FAILED', 'OFFLINE_MODE',
    'CONFIG_CORRUPTED', 'VERSION_MISMATCH', 'LICENSE_BLOCKED', 'VULNERABILITY_DB_VALIDATION_FAILED'}
_ERROR_TEXT = {'NETWORK_TIMEOUT': '下载超时', 'DOWNLOAD_STALLED': '下载阶段超过无可验证进度等待上限',
    'PREPARATION_BUDGET_EXHAUSTED': '本次准备时间预算已耗尽', 'TLS_ERROR': '安全连接校验失败',
    'DNS_RESOLUTION_FAILED': '下载地址无法解析', 'CONNECTION_REFUSED': '服务器拒绝连接',
    'PROXY_CONNECTION_FAILED': '代理连接失败', 'DOWNLOAD_INTERRUPTED': '传输中断',
    'HTTP_429': '服务器限制请求频率', 'HTTP_401': '下载源要求授权', 'HTTP_403': '下载源拒绝访问',
    'HTTP_404': '下载资源不存在', 'CHECKSUM_MISMATCH': '下载内容校验失败', 'DOWNLOAD_BUSY': '另一个进程正在更新漏洞库',
    'VULNERABILITY_DB_VALIDATION_FAILED': '下载数据未通过版本、有效期或数据库校验'}
from .component_health import ISSUES as _COMPONENT_ISSUES
_ERRORS.update(_COMPONENT_ISSUES)
_ERROR_TEXT.update({code: text[0] for code, text in _COMPONENT_ISSUES.items() if code not in _ERROR_TEXT})


def parse_download_progress(line):
    """Trivy's reported transfer counts; bars and raw logs never reach the UI."""
    if not isinstance(line, str) or len(line) > 256:
        return None
    clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line).strip()
    match = re.match(r'^(\d+(?:\.\d+)?)\s+(B|KiB|MiB|GiB)\s*/\s*(\d+(?:\.\d+)?)\s+(B|KiB|MiB|GiB)\s+\[', clean)
    if not match:
        return None
    units = {'B': 1, 'KiB': 1024, 'MiB': 1048576, 'GiB': 1073741824}
    received = int(float(match[1]) * units[match[2]])
    total = int(float(match[3]) * units[match[4]])
    return (received, total) if 0 <= received <= total <= 8_000_000_000 and total > 0 else None


class DownloadProgressParser:
    """Bounded numeric frames, including Windows pb output without newlines.

    Only counts leave this parser. Fragments, bars and arbitrary raw logs are
    never forwarded. A source-specific instance prevents cross-source replay.
    """
    _frame = re.compile(rb'(?<![\d.+\-eE])(\d{1,16}(?:\.\d{1,8})?)\s+(?:B|KiB|MiB|GiB)\s*/\s*'
        rb'\d{1,16}(?:\.\d{1,8})?\s+(?:B|KiB|MiB|GiB)\s+\[')

    def __init__(self):
        self._pending = b''

    def feed(self, chunk):
        if not isinstance(chunk, (bytes, bytearray)):
            return []
        counts = deque(maxlen=256)
        for offset in range(0, len(chunk), 4096):
            data = self._pending + bytes(chunk[offset:offset + 4096])
            consumed = 0
            for match in self._frame.finditer(data):
                parsed = parse_download_progress(match.group().decode('ascii'))
                if parsed is not None:
                    counts.append(parsed)
                consumed = match.end()
            self._pending = data[consumed:][-256:]
        return list(counts)


def validate_preparation_event(value):
    """Accept fixed identities and bounded numbers, never arbitrary child text."""
    if not isinstance(value, dict) or set(value) - {'event', 'component', 'attempt', 'max_attempts',
            'received_bytes', 'total_bytes', 'timeout_seconds', 'error_code', 'source'}:
        return None
    if (not isinstance(value.get('event'), str) or not isinstance(value.get('component'), str)
            or value['event'] not in _EVENTS or value['component'] not in {'semgrep', 'gitleaks', 'trivy', 'vulnerability_db'}):
        return None
    for name in ('attempt', 'max_attempts', 'received_bytes', 'total_bytes', 'timeout_seconds'):
        if name in value and (type(value[name]) is not int or not 0 <= value[name] <= 8_000_000_000):
            return None
    if (not 1 <= value.get('attempt', 1) <= value.get('max_attempts', 1) <= 2
            or not 0 <= value.get('timeout_seconds', 0) <= 1800
            or value.get('received_bytes', 0) > value.get('total_bytes', 8_000_000_000)
            or not isinstance(value.get('error_code', ''), str) or value.get('error_code', '') not in _ERRORS):
        return None
    source = value.get('source', '')
    if not isinstance(source, str) or len(source) > 200 or source and not re.fullmatch(r'[A-Za-z0-9.-]+', source):
        return None
    if value['event'] == 'DOWNLOAD_PROGRESS' and (value.get('total_bytes', 0) <= 0 or 'received_bytes' not in value):
        return None
    return dict(value)


def child_preparation_progress(stage):
    """Private, fixed-token transport; never forward scanner or config output."""
    if isinstance(stage, dict):
        safe = validate_preparation_event(stage)
        if safe is not None:
            print(EVENT_PREFIX + json.dumps(safe, separators=(',', ':')), file=sys.stderr, flush=True)
    elif stage in PREPARATION_STAGES:
        print(STAGE_PREFIX + stage, file=sys.stderr, flush=True)


def report_progress(progress, stage):
    if progress is not None:
        progress(stage)


class InstallationProgress:
    """No fake percentage: stage changes plus a five-second waiting heartbeat.

    Starts before expensive imports/probes and works with redirected streams.
    Output errors cannot interrupt a configuration transaction. Only fixed text
    is printed: no config, child output, source, path or exception is reflected.
    """
    def __init__(self, *, stream=None, interval=5.0, clock=time.monotonic, preparation=False,
                 adaptive=False, initial_seconds=300, max_wait_seconds=1800):
        self.stream = sys.stderr if stream is None else stream
        self.interval = interval
        self.clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._started = None
        self._stage = 'START'
        self._last_change = None
        self._output_available = True
        self.preparation = preparation
        self._last_download = None
        try:
            self._interactive = bool(self.stream.isatty())
        except (AttributeError, OSError, ValueError):
            self._interactive = False
        self._line_width = 0
        self._download_active = False
        self._download_label = '漏洞库'
        self._download_counts = None
        self._download_estimate = DownloadEstimate()
        self._adaptive_policy = ((initial_seconds, max_wait_seconds) if adaptive is True
            and type(initial_seconds) is int and type(max_wait_seconds) is int
            and 1 <= initial_seconds <= max_wait_seconds <= 1800 else None)

    @staticmethod
    def _cells(text):
        return sum(2 if unicodedata.east_asian_width(char) in 'WF' else 1 for char in text)

    def _columns(self):
        try:
            return max(1, os.get_terminal_size(self.stream.fileno()).columns - 1)
        except (AttributeError, OSError, ValueError):
            return max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)

    def _replace_line(self, message):
        if not self._output_available:
            return
        columns = self._columns()
        text, cells = '', 0
        for char in '[安装] ' + message:
            width = self._cells(char)
            if cells + width > columns:
                break
            text += char
            cells += width
        try:
            padding = max(0, min(self._line_width, columns) - cells)
            self.stream.write('\r' + text + ' ' * padding)
            self.stream.flush()
            self._line_width = cells + padding
        except (OSError, UnicodeError, ValueError):
            self._output_available = False

    def _finish_line(self):
        if self._line_width:
            try:
                if self._output_available:
                    self.stream.write('\n')
                    self.stream.flush()
            except (OSError, UnicodeError, ValueError):
                self._output_available = False
            self._line_width = 0

    def _download_text(self, *, waiting=False):
        if self._download_counts is None:
            elapsed = int(max(0, self.clock() - self._started))
            return f'{self._download_label}下载 [等待实际进度] 已用时 {elapsed} 秒'
        received, total = self._download_counts
        prefix = f'{self._download_label}下载进度 '
        suffix = f' {received / total * 100:.1f}% {received / 1048576:.2f}/{total / 1048576:.2f} MiB'
        estimate = self._download_estimate.estimate(self.clock())
        if estimate is None:
            suffix += ' 估算中'
        else:
            seconds = estimate['remaining_seconds']
            remaining = f'{seconds // 60}分{seconds % 60:02d}秒' if seconds >= 60 else f'{seconds}秒'
            suffix += f" {estimate['bytes_per_second'] / 1048576:.2f} MiB/s 预计剩余{remaining}"
        if waiting:
            suffix += ' 等待新进度'
        columns = self._columns() if self._interactive else 79
        if self._interactive and self._cells('[安装] ' + prefix + suffix) + 5 > columns:
            prefix = self._download_label + ' '
        if self._cells('[安装] ' + prefix + suffix) + 5 > columns:
            # Keep percentage and an approximate ETA visible in small windows.
            prefix = '下载 '
            suffix = f' {received / total * 100:.1f}%'
            if estimate is not None:
                suffix += f' ~{math.ceil(seconds / 60)}m' if seconds >= 60 else f' ~{seconds}s'
            if waiting:
                suffix += ' 等待'
        width = min(20, max(3, columns - self._cells('[安装] ' + prefix + suffix) - 2))
        filled = min(width, received * width // total)
        return prefix + '[' + '#' * filled + '-' * (width - filled) + ']' + suffix

    def _end_download(self):
        if self._download_active:
            if self._download_counts is not None:
                if self._interactive:
                    self._replace_line(self._download_text())
                else:
                    # A pipe/log cannot replace a row: keep only its final real snapshot.
                    self._write(self._download_text())
            self._download_active = False
            self._download_counts = None
            self._download_estimate.reset()
        self._finish_line()

    def _write(self, message):
        self._finish_line()
        if self._output_available:
            try:
                print('[安装] ' + message, file=self.stream, flush=True)
            except (OSError, UnicodeError, ValueError):
                self._output_available = False

    def __enter__(self):
        # The standalone entry and CLI can share the same reporter.
        if self._started is None:
            self._started = self.clock()
            self._last_change = self._started
            self._write('开始准备扫描能力；程序安装和已有配置将保留。' if self.preparation else STAGES['START'])
            if self.preparation and self._adaptive_policy:
                initial, maximum = self._adaptive_policy
                self._write(f'初始等待 {initial} 秒；按真实进度自动续等，最长 {maximum} 秒。剩余下载时间随实际网速估算。')
            self._thread = threading.Thread(target=self._wait, name='install-progress', daemon=True)
            self._thread.start()
        return self

    def __call__(self, stage):
        with self._lock:
            if not self._stop.is_set():
                if isinstance(stage, dict):
                    event = validate_preparation_event(stage)
                    if event is None:
                        return
                    now = self.clock()
                    kind = event['event']
                    label = {'semgrep': '代码检查', 'gitleaks': '密钥检查', 'trivy': '依赖检查', 'vulnerability_db': '漏洞库'}[event['component']]
                    if kind == 'DOWNLOAD_PROGRESS':
                        self._download_active = True
                        self._download_label = label
                        self._download_counts = event['received_bytes'], event['total_bytes']
                        self._download_estimate.update(*self._download_counts, now)
                        self._last_change = now
                        if self._last_download is not None and now - self._last_download < 1:
                            return
                        self._last_download = now
                        if self._interactive:
                            self._replace_line(self._download_text())
                        return
                    self._end_download()
                    if kind == 'DOWNLOAD_STARTED':
                        self._last_download = None
                        self._stage = 'INSTALL_DATA'
                        self._download_active = True
                        self._download_label = label
                        source = {'ghcr.io': '官方发布源', 'mirror.gcr.io': '官方镜像源'}.get(event.get('source'), '当前来源')
                        self._write(f"正在从{source}下载漏洞库，第 {event.get('attempt', 1)} / {event.get('max_attempts', 1)} 轮；最长剩余等待 {event.get('timeout_seconds', 0)} 秒。")
                    elif kind == 'DOWNLOAD_FALLBACK':
                        self._last_download = None
                        self._stage = 'INSTALL_DATA'
                        source = {'ghcr.io': '官方发布源', 'mirror.gcr.io': '官方镜像源'}.get(event.get('source'), '备用来源')
                        self._write('本来源未完成，正在切换到' + source + '；共用剩余总预算。')
                    elif kind == 'DOWNLOAD_VALIDATING':
                        self._stage = 'VERIFY_DOWNLOADED_DATA'
                        self._write(STAGES[self._stage])
                    elif kind == 'DOWNLOAD_RETRY':
                        self._last_download = None
                        self._write('正在按指定重试次数重新下载；上次未完成的数据不能作为有效缓存。')
                    elif kind == 'DOWNLOAD_FAILED':
                        why = _ERROR_TEXT.get(event.get('error_code'), '下载或数据校验未完成')
                        self._write(why + '。原有可用缓存已保留；扫描能力仍以最后核对结果为准。')
                        if event.get('error_code') == 'PREPARATION_BUDGET_EXHAUSTED':
                            if self._adaptive_policy:
                                self._write('本次等待已结束，可检查下载网络后重试 prepare-scanners；会重新下载，不必重新安装程序。')
                            else:
                                self._write('慢速网络可运行 prepare-scanners --timeout 900 延长准备时间；会重新下载，不必重新安装程序。')
                    elif kind == 'DOWNLOAD_COMPLETE':
                        self._write('漏洞库已下载并通过校验，已更新本地缓存。')
                    elif kind == 'COMPONENT_STARTED':
                        self._write(label + '组件正在准备；仅下载进度已被实际取得时才显示传输量。')
                    elif kind == 'COMPONENT_COMPLETE':
                        self._write(label + '组件已准备完成。')
                    elif kind == 'COMPONENT_FAILED':
                        self._write(label + '组件尚未准备完成；' + _ERROR_TEXT.get(event.get('error_code'), '组件下载或验证未完成') + '。')
                    self._last_change = now
                    return
                if stage not in STAGES:
                    return
                if stage == self._stage:
                    return
                self._stage = stage
                self._last_change = self.clock()
                self._end_download()
                self._write(STAGES[stage])

    def _heartbeat(self):
        with self._lock:
            now = self.clock()
            if (not self._stop.is_set() and self._started is not None
                    and now - self._last_change >= self.interval):
                elapsed = int(max(0, now - self._started))
                if self._download_active:
                    if self._interactive:
                        self._replace_line(self._download_text(waiting=True))
                elif self._interactive:
                    self._replace_line(f'已用时 {elapsed} 秒；仍在等待当前步骤完成：{STAGES[self._stage]}')
                else:
                    self._write(f'已用时 {elapsed} 秒；仍在等待当前步骤完成：{STAGES[self._stage]}')

    def _wait(self):
        while not self._stop.wait(self.interval):
            self._heartbeat()

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        with self._lock:
            self._end_download()

    def finish(self, succeeded, *, scan_ready=True):
        self.close()
        with self._lock:
            if self.preparation:
                self._write('扫描能力准备完成，漏洞数据在有效期内。' if succeeded else
                    '扫描能力尚未全部准备完成；程序、配置和原有可用缓存已保留。')
                return
            if succeeded and not scan_ready:
                self._write('本地安装完成；扫描能力准备状态见下方回执，后台进度可用 preparation watch 查看。')
                return
            self._write('本地安装完成。请完全退出并重启 Codex，按提示审核 Hook 信任；扫描能力以实际扫描结果为准。'
                        if succeeded else '安装未完成。请查看下方诊断；不要删除配置或 Skill，也不要将本次安装视为成功。')

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        if exc_type is not None:
            with self._lock:
                if self.preparation:
                    self._write('扫描能力准备已取消，未确认就绪；程序、配置和原有可用缓存保留。')
                    return
                self._write('安装已取消，未确认完成。若已写入部分配置，请先使用产品恢复入口。'
                            if issubclass(exc_type, KeyboardInterrupt) else
                            '安装未完成。请查看诊断；现有状态可能需要通过产品恢复入口核对。')

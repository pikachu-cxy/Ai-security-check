"""Small stderr renderer: delayed events, one heartbeat thread, no percentages."""
from collections import deque
from datetime import datetime
import sys
import threading
import time
import shutil
import unicodedata

from .progress import ProgressReporter


LABELS = {
    'RULE_PLAN_READY': '代码安全规则计划已准备', 'SAST_NOT_COVERED': '代码安全未覆盖',
    'SCAN_STARTED': '正在检查代码', 'WORKSPACE_DISCOVERY_STARTED': '正在识别项目',
    'WORKSPACE_DISCOVERY_COMPLETED': '项目识别完成', 'TARGET_DISCOVERY_STARTED': '正在发现扫描文件',
    'TARGET_DISCOVERY_COMPLETED': '扫描文件发现完成', 'PLANNING_STARTED': '正在规划安全检查',
    'PLAN_READY': '安全检查计划已准备', 'ENGINE_PREPARING': '正在准备引擎',
    'ENGINE_READY': '引擎已就绪', 'ENGINE_PREPARATION_FAILED': '引擎准备失败',
    'ENGINE_DOWNLOAD_STARTED': '正在下载引擎', 'ENGINE_DOWNLOAD_COMPLETED': '引擎下载完成',
    'ENGINE_DOWNLOAD_FAILED': '引擎下载失败', 'ENGINE_PACKAGE_PREPARING': '正在准备引擎 Python 环境',
    'DATA_PREPARING': '正在准备漏洞数据库', 'DATA_READY': '漏洞数据库已准备',
    'DATA_PREPARATION_FAILED': '漏洞数据库准备失败', 'SCANNER_STARTED': '正在运行',
    'SCANNER_COMPLETED': '完成', 'SCANNER_FAILED': '失败', 'SCANNER_UNAVAILABLE': '不可用',
    'SCANNER_TIMEOUT': '超时', 'SCAN_COMPLETED': '检查结束', 'SCAN_CANCELLED': '扫描已取消',
}
ACTIVE = {'SCAN_STARTED', 'WORKSPACE_DISCOVERY_STARTED', 'TARGET_DISCOVERY_STARTED',
          'PLANNING_STARTED', 'ENGINE_PREPARING', 'ENGINE_DOWNLOAD_STARTED',
          'ENGINE_PACKAGE_PREPARING', 'DATA_PREPARING', 'SCANNER_STARTED'}


class CLIProgressRenderer:
    def __init__(self, stream=None, *, delay=.5, tty=None, heartbeat_interval=None, clock=time.monotonic):
        self.stream = stream if stream is not None else sys.stderr
        self.tty = self.stream.isatty() if tty is None else tty
        self.delay = delay
        self.interval = heartbeat_interval if heartbeat_interval is not None else (1 if self.tty else 10)
        self.clock = clock
        self.started = clock()
        self.visible = False
        self.buffer = deque(maxlen=128)
        self.active = {}
        self.parents = {}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = None
        self.last_heartbeat = self.started
        self.line_width = 0
        self.reporter = ProgressReporter(self)

    def __enter__(self):
        self.thread = threading.Thread(target=self._loop, name='security-progress', daemon=True)
        self.thread.start()
        return self.reporter

    def __exit__(self, *args):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        with self.lock:
            if self.line_width:
                self.stream.write('\r' + ' ' * self.line_width + '\r')
                self.stream.flush()

    def _write(self, text, *, dynamic=False):
        text = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
        if self.line_width:
            self.stream.write('\r' + ' ' * self.line_width + '\r')
            self.line_width = 0
        if dynamic:
            available = max(10, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
            width = 0
            bounded = []
            for char in text:
                size = 2 if unicodedata.east_asian_width(char) in {'W', 'F'} else 1
                if width + size > available - 1:
                    bounded.append('…')
                    width += 1
                    break
                bounded.append(char)
                width += size
            text = ''.join(bounded)
            self.stream.write('\r' + text)
            self.line_width = width
        else:
            self.stream.write(text + '\n')
        self.stream.flush()

    def __call__(self, event):
        with self.lock:
            key = event.scanner or event.component
            if event.event_type == 'ENGINE_DOWNLOAD_STARTED' and key in self.active:
                self.parents[key] = self.active[key]
            if event.event_type in ACTIVE:
                self.active[key] = (event, self.clock())
            elif event.event_type == 'ENGINE_DOWNLOAD_COMPLETED' and key in self.parents:
                self.active[key] = self.parents.pop(key)
            else:
                self.active.pop(key, None)
                self.parents.pop(key, None)
            if event.event_type in {'SCAN_COMPLETED', 'SCAN_CANCELLED'}:
                self.active.clear()
                self.parents.clear()
            if not self.visible:
                self.buffer.append(event)
            else:
                self._event(event)
            self.tick()

    def _event(self, event):
        stamp = datetime.fromisoformat(event.timestamp).astimezone().strftime('%H:%M:%S')
        name = ' '.join(value for value in (event.scanner, event.scanner_version) if value)
        text = f'[{stamp}] {name} {LABELS.get(event.event_type, event.event_type)}'.strip()
        if event.message:
            text += ' · ' + event.message
        if event.finding_count is not None:
            text += f' · {event.finding_count} 个问题'
        if event.duration_ms is not None:
            text += f' · {event.duration_ms / 1000:.1f}s'
        if event.error_code:
            text += ' · ' + event.error_code
        if event.source:
            text += ' · 来源：' + event.source
        self._write(text)

    def tick(self):
        with self.lock:
            now = self.clock()
            if not self.visible and now-self.started >= self.delay:
                self.visible = True
                for event in self.buffer:
                    self._event(event)
                self.buffer.clear()
                self.last_heartbeat = now
            if self.visible and self.active and now-self.last_heartbeat >= self.interval:
                pieces = [f'{event.scanner or event.component} {event.scanner_version} · {LABELS.get(event.event_type, "正在处理")} · {now-start:.0f}s'
                          for event, start in self.active.values()]
                spinner = '|/-\\'[int(now) % 4] if self.tty else '仍在处理'
                self._write(spinner + ' ' + '；'.join(pieces), dynamic=self.tty)
                self.last_heartbeat = now

    def _loop(self):
        while not self.stop.wait(.1):
            try:
                self.tick()
            except (OSError, ValueError):
                return

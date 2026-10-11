"""Flushed, stderr-only installation feedback; never an installation receipt."""
from __future__ import annotations

import sys
import threading
import time


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
    'RECOVERY': '正在检查并安全恢复本次中断的安装。',
    'CLEANUP': '正在清理已停用的旧版本；使用中的文件和用户内容会保留。',
    'DELTA_VERIFY': '正在校验增量升级包及本地基础版本。',
    'DELTA_APPLY': '正在复用未变化的程序文件，准备增量升级。',
}


def report_progress(progress, stage):
    if progress is not None:
        progress(stage)


class InstallationProgress:
    """No fake percentage: stage changes plus a five-second waiting heartbeat.

    Starts before expensive imports/probes and works with redirected streams.
    Output errors cannot interrupt a configuration transaction. Only fixed text
    is printed: no config, child output, source, path or exception is reflected.
    """
    def __init__(self, *, stream=None, interval=5.0, clock=time.monotonic):
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

    def _write(self, message):
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
            self._write(STAGES['START'])
            self._thread = threading.Thread(target=self._wait, name='install-progress', daemon=True)
            self._thread.start()
        return self

    def __call__(self, stage):
        with self._lock:
            if not self._stop.is_set():
                self._stage = stage
                self._last_change = self.clock()
                self._write(STAGES[stage])

    def _heartbeat(self):
        with self._lock:
            now = self.clock()
            if (not self._stop.is_set() and self._started is not None
                    and now - self._last_change >= self.interval):
                elapsed = int(max(0, now - self._started))
                self._write(f'已用时 {elapsed} 秒；仍在等待当前步骤完成：{STAGES[self._stage]}')

    def _wait(self):
        while not self._stop.wait(self.interval):
            self._heartbeat()

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def finish(self, succeeded):
        self.close()
        with self._lock:
            self._write('本地安装完成。请完全退出并重启 Codex，按提示审核 Hook 信任；扫描能力以实际扫描结果为准。'
                        if succeeded else '安装未完成。请查看下方诊断；不要删除配置或 Skill，也不要将本次安装视为成功。')

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        if exc_type is not None:
            with self._lock:
                self._write('安装已取消，未确认完成。若已写入部分配置，请先使用产品恢复入口。'
                            if issubclass(exc_type, KeyboardInterrupt) else
                            '安装未完成。请查看诊断；现有状态可能需要通过产品恢复入口核对。')

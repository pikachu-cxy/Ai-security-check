"""Cancellation must survive the actual BaseScanner execution boundary."""
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import run_process
from security_runtime.progress import ProgressReporter, ScanCancelled, progress_context
from security_runtime.scanners import BaseScanner
from security_runtime.toolchain import ToolStatus


class PreparedScanner(BaseScanner):
    scanner_id = name = 'cancellation-fixture'

    def __init__(self):
        self.tool_manager = SimpleNamespace(ensure=lambda *_args, **_kwargs:
            SimpleNamespace(status=ToolStatus.READY, path=sys.executable, version='1.0'))

    def _prepare(self, _binary):
        return ToolStatus.READY


def context(root):
    return ScanContext(str(root), ScanMode.QUICK, ('app.py',))


def test_data_preparation_checkpoint_propagates_cancellation(tmp_path):
    reporter = ProgressReporter()

    class CancelDuringPrepare(PreparedScanner):
        def _prepare(self, _binary):
            reporter.cancel()
            return ToolStatus.READY

        def _scan(self, *_args):
            pytest.fail('cancelled preparation cannot start execution')

    with progress_context(reporter), pytest.raises(ScanCancelled):
        CancelDuringPrepare().scan(context(tmp_path), FindingNormalizer(tmp_path))


def test_subprocess_execution_cancellation_is_not_a_failed_scanner_run(tmp_path):
    reporter = ProgressReporter()
    timers = []

    class CancelDuringProcess(PreparedScanner):
        def _scan(self, *_args):
            timer = threading.Timer(.2, reporter.cancel)
            timers.append(timer)
            timer.start()
            run_process([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=40)
            pytest.fail('cancelled execution cannot produce successful findings')

    started = time.monotonic()
    try:
        with progress_context(reporter), pytest.raises(ScanCancelled):
            CancelDuringProcess().scan(context(tmp_path), FindingNormalizer(tmp_path))
    finally:
        for timer in timers:
            timer.cancel()
            timer.join(timeout=1)
    assert time.monotonic() - started < 4

"""Windows component workers keep output pipes without creating consoles."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_runtime import processes


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows console behavior')


def test_hidden_child_keeps_progress_and_failure_output():
    lines, chunks = [], []
    script = (
        "import ctypes,sys;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())));"
        "sys.stderr.write('1.00 KiB / 2.00 KiB [=>]\\rdownload failed\\n');"
        "sys.stderr.flush();sys.exit(7)"
    )
    result = processes.run_process([sys.executable, '-c', script],
        on_stderr_line=lines.append, on_stderr_chunk=chunks.append)
    assert result.stdout.strip() == '0', 'Captured child must have no console window'
    assert result.returncode == 7
    assert lines == ['1.00 KiB / 2.00 KiB [=>]', 'download failed']
    assert b''.join(chunks).decode() == result.stderr


def test_background_preparation_worker_and_child_have_no_console():
    # Reproduce the actual background-worker launch flags, then launch a
    # captured console executable inside it (as the worker does for Trivy).
    script = (
        "import ctypes;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))"
    )
    worker = (
        "import ctypes,json,sys;from security_runtime.processes import run_process;"
        "worker_console=int(bool(ctypes.windll.kernel32.GetConsoleWindow()));"
        f"result=run_process([sys.executable,'-c',{script!r}]);"
        "print(json.dumps({'worker_console':worker_console,'code':result.returncode,'output':result.stdout.strip()}))"
    )
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    result = subprocess.run([sys.executable, '-c', worker], env=environment,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {'worker_console': 0, 'code': 0, 'output': '0'}


def test_timeout_cleanup_also_runs_without_console(monkeypatch):
    calls = []
    execute = subprocess.run

    def record(arguments, **options):
        calls.append((arguments, options))
        return execute(arguments, **options)

    monkeypatch.setattr(processes.subprocess, 'run', record)
    with pytest.raises(TimeoutError, match='process timed out'):
        processes.run_process([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=.3)
    assert len(calls) == 1
    command, options = calls[0]
    assert Path(command[0]).name == 'taskkill.exe'
    assert '/T' in command and '/F' in command
    assert options['creationflags'] == subprocess.CREATE_NO_WINDOW

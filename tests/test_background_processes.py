"""Windows component workers keep output pipes without creating consoles."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_runtime import processes
from test_development_check import check  # noqa: F401
from test_scan_jobs import jobs  # noqa: F401


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


@pytest.mark.parametrize('kind', ['development', 'explicit-scan'])
def test_actual_dispatcher_flags_hide_venv_worker_and_child(kind, request, tmp_path, monkeypatch):
    # Replace only the worker body with a harmless console probe; keep the
    # dispatcher's real executable, redirection and creation flags.
    fixture = request.getfixturevalue('check' if kind == 'development' else 'jobs')
    output = tmp_path / 'console-probe.json'
    child = "import ctypes;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))"
    script = (
        "import ctypes,json,subprocess,sys;from pathlib import Path;"
        "own=int(bool(ctypes.windll.kernel32.GetConsoleWindow()));"
        f"child=subprocess.run([sys._base_executable,'-c',{child!r}],"
        "capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW);"
        "Path(sys.argv[1]).write_text(json.dumps({'worker':own,'child':child.stdout.strip(),'exit':child.returncode}))"
    )
    original = subprocess.Popen
    workers = []

    def probe(arguments, **options):
        # Old code fails before spawning, so this regression cannot flash a
        # console even when run against the original conflicting flags.
        assert options['creationflags'] == subprocess.CREATE_NO_WINDOW
        process = original([arguments[0], '-c', script, str(output)], **options)
        workers.append(process)
        return process

    monkeypatch.setattr(subprocess, 'Popen', probe)
    if kind == 'development':
        from security_runtime.development_check_worker import launch_worker
        root, service, _, _ = fixture
        ref = service.begin(root, 'console-probe')['check_ref']
        service.record(root, ref, ['app.ts'])
        service.finish(root, ref)
        assert launch_worker(service.hooks, root)
    else:
        fixture.submit('console-probe-001')
    assert len(workers) == 1
    assert workers[0].wait(timeout=15) == 0
    assert json.loads(output.read_text()) == {'worker': 0, 'child': '0', 'exit': 0}

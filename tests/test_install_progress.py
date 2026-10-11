"""Installation feedback is immediate, truthful and separate from JSON receipts."""
import io
import json
import threading

import pytest

from security_runtime.cli import main
from security_runtime.install_progress import InstallationProgress, STAGES
from security_runtime.personal_install import CONTRACT


def receipt(ready=True):
    return {'overall': 'CONFIGURED' if ready else 'BROKEN',
            'installation': {'contract': CONTRACT, 'local_files_ready': ready}}


def test_start_is_flushed_before_installation_work(monkeypatch, capsys):
    import security_runtime.personal_install as module
    def install(**kwargs):
        output = capsys.readouterr()
        assert output.out == ''
        assert '开始安装' in output.err
        kwargs['progress']('CHECK_CONFIG')
        return receipt()
    monkeypatch.setattr(module, 'install_personal_codex', install)
    assert main(['install', 'codex', '--json']) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == receipt()
    assert '现有配置和 Skill' in output.err and '本地安装完成' in output.err


@pytest.mark.parametrize('ready', [True, False])
def test_json_stdout_stays_a_single_receipt(monkeypatch, capsys, ready):
    monkeypatch.setattr('security_runtime.personal_install.install_personal_codex', lambda **kw: receipt(ready))
    assert main(['install', 'codex', '--json']) == (0 if ready else 2)
    output = capsys.readouterr()
    assert json.loads(output.out) == receipt(ready)
    assert len(output.out.splitlines()) == 1 and '[安装]' not in output.out
    assert ('本地安装完成' if ready else '安装未完成') in output.err
    if not ready:
        assert '本地安装完成' not in output.err


def test_heartbeat_uses_elapsed_time_and_current_stage_without_percentages():
    stream = io.StringIO()
    now = [100.0]
    with InstallationProgress(stream=stream, interval=5, clock=lambda: now[0]) as progress:
        progress('SETUP_CHILD')
        now[0] += 5
        progress._heartbeat()
        assert '已用时 5 秒' in stream.getvalue()
        assert STAGES['SETUP_CHILD'] in stream.getvalue()
        assert '%' not in stream.getvalue()
        assert '本地安装完成' not in stream.getvalue()
        progress.finish(False)
        final = stream.getvalue()
        now[0] += 50
        progress._heartbeat()
        assert stream.getvalue() == final
    assert not progress._thread.is_alive()


def test_real_waiting_work_does_not_require_the_worker_to_emit_feedback():
    class Stream(io.StringIO):
        def __init__(self):
            super().__init__()
            self.waiting = threading.Event()
            self.flush_count = 0
        def write(self, value):
            if '仍在等待' in value:
                self.waiting.set()
            return super().write(value)
        def flush(self):
            self.flush_count += 1
    stream = Stream()
    with InstallationProgress(stream=stream, interval=0.02) as progress:
        progress('CAPABILITY_CHECK')
        assert stream.waiting.wait(2)
    assert stream.flush_count >= 3
    assert not progress._thread.is_alive()


def test_stage_change_resets_wait_message():
    stream = io.StringIO()
    now = [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        now[0] = 4
        progress('SKILL')
        now[0] = 5
        progress._heartbeat()
        assert '仍在等待' not in stream.getvalue()
        now[0] = 9
        progress._heartbeat()
        assert '专业 Skill' in stream.getvalue().splitlines()[-1]


@pytest.mark.parametrize('operation', ['write', 'flush'])
def test_console_failure_does_not_fail_installation(operation):
    class BrokenStream(io.StringIO):
        def write(self, value):
            if operation == 'write':
                raise OSError('private console error')
            return super().write(value)
        def flush(self):
            if operation == 'flush':
                raise OSError('private console error')
    with InstallationProgress(stream=BrokenStream()) as progress:
        progress('SELF_CHECK')
        progress.finish(True)
    assert not progress._thread.is_alive()


def test_shared_bootstrap_and_cli_reporter_starts_only_once(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr('security_runtime.personal_install.install_personal_codex', lambda **kw: receipt())
    with InstallationProgress(stream=stream) as progress:
        assert main(['install', 'codex', '--json'], installation_progress=progress) == 0
    assert stream.getvalue().count('开始安装') == 1
    assert stream.getvalue().count('本地安装完成') == 1
    assert not progress._thread.is_alive()


def test_cancelled_install_is_not_reported_as_a_cancelled_scan(monkeypatch, capsys):
    def interrupt(**kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr('security_runtime.personal_install.install_personal_codex', interrupt)
    assert main(['install', 'codex', '--json']) == 130
    output = capsys.readouterr()
    assert '安装已取消' in output.err
    assert '扫描已取消' not in output.err and '本地安装完成' not in output.err
    assert not output.out


def test_failure_never_echoes_private_exception(monkeypatch, capsys):
    def failed(**kwargs):
        raise OSError('PRIVATE-CONFIG-CONTENTS')
    monkeypatch.setattr('security_runtime.personal_install.install_personal_codex', failed)
    assert main(['install', 'codex', '--json']) == 2
    output = capsys.readouterr()
    assert 'PRIVATE-CONFIG-CONTENTS' not in output.out + output.err
    assert '安装未完成' in output.err and '本地安装完成' not in output.err

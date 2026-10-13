"""Terminal progress replaces one row; redirected receipts and logs remain readable."""
import io
import json
import os
import shutil
import unicodedata

import pytest

from security_runtime.install_progress import InstallationProgress, child_preparation_progress, EVENT_PREFIX


class Terminal(io.StringIO):
    def isatty(self):
        return True


def event(kind='DOWNLOAD_PROGRESS', received=20, total=100, **fields):
    data = dict(event=kind, component='vulnerability_db', **fields)
    if kind == 'DOWNLOAD_PROGRESS':
        data.update(received_bytes=received * 1048576, total_bytes=total * 1048576)
    return data


def test_terminal_download_and_idle_updates_replace_one_row():
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0], preparation=True) as progress:
        progress(event('DOWNLOAD_STARTED'))
        initial_newlines = stream.getvalue().count('\n')
        for count in (20, 35, 50):
            now[0] += 2
            progress(event(received=count))
        now[0] += 6
        progress._heartbeat()
        text = stream.getvalue()
        assert text.count('\n') == initial_newlines
        assert '\r' in text and '[' in text and '50.0%' in text
        assert '等待' in text
        progress(event('DOWNLOAD_VALIDATING'))
        assert '校验' in stream.getvalue() and '准备完成' not in stream.getvalue()
        progress(event('DOWNLOAD_COMPLETE'))
        progress.finish(True)
        assert stream.getvalue().endswith('漏洞数据在有效期内。\n')


def test_unknown_download_heartbeat_has_no_fake_percentage():
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        progress(event('DOWNLOAD_STARTED'))
        baseline = stream.getvalue().count('\n')
        now[0] = 6
        progress._heartbeat()
        now[0] = 12
        progress._heartbeat()
        assert stream.getvalue().count('\n') == baseline
        assert '等待实际进度' in stream.getvalue() and '%' not in stream.getvalue()


def test_redirected_progress_is_one_snapshot_and_has_no_console_controls():
    stream, now = io.StringIO(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0], preparation=True) as progress:
        progress(event('DOWNLOAD_STARTED'))
        baseline = stream.getvalue().count('\n')
        for count in range(1, 100):
            now[0] += 2
            progress(event(received=count))
        now[0] += 6
        progress._heartbeat()
        assert stream.getvalue().count('\n') == baseline
        progress(event('DOWNLOAD_VALIDATING'))
        text = stream.getvalue()
        assert text.count('下载进度') == 1 and '99.0%' in text
        assert '\r' not in text and '\x1b' not in text
        progress.finish(False)
        assert '原有可用缓存已保留' in stream.getvalue()


@pytest.mark.parametrize('columns', [30, 32, 80])
def test_chinese_progress_fits_columns_and_clears_shorter_row(monkeypatch, columns):
    monkeypatch.setattr(shutil, 'get_terminal_size', lambda **kw: os.terminal_size((columns, 24)))
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        progress(event('DOWNLOAD_STARTED'))
        now[0] += 2
        progress(event(received=99))
        now[0] += 6
        progress._heartbeat()
        previous = stream.getvalue().split('\r')[-1]
        now[0] += 2
        progress(event(received=100))
        current = stream.getvalue().split('\r')[-1]
        cells = lambda line: sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in line)
        assert cells(current) <= columns - 1 and cells(previous) <= columns - 1
        assert cells(current) >= cells(previous)
        assert '100.0%' in current


def test_fallback_failure_and_cancel_end_row_without_false_success():
    stream, now = Terminal(), [0.0]
    with pytest.raises(KeyboardInterrupt):
        with InstallationProgress(stream=stream, clock=lambda: now[0], preparation=True) as progress:
            progress(event('DOWNLOAD_STARTED', source='ghcr.io'))
            now[0] = 2
            progress(event(received=30))
            progress(event('DOWNLOAD_FAILED', error_code='NETWORK_TIMEOUT'))
            progress(event('DOWNLOAD_FALLBACK', source='mirror.gcr.io'))
            progress(event('DOWNLOAD_STARTED', source='mirror.gcr.io'))
            now[0] = 4
            progress(event(received=2))
            raise KeyboardInterrupt()
    text = stream.getvalue()
    assert '\n[安装] 下载超时' in text
    assert '\n[安装] 扫描能力准备已取消' in text
    assert '2.0%' in text and '扫描能力准备完成' not in text


@pytest.mark.parametrize('broken', ['isatty', 'write', 'flush'])
def test_terminal_probe_or_io_failure_does_not_interrupt_preparation(broken):
    class Broken(Terminal):
        def isatty(self):
            if broken == 'isatty':
                raise OSError('PRIVATE')
            return True

        def write(self, text):
            if broken == 'write':
                raise OSError('PRIVATE')
            return super().write(text)

        def flush(self):
            if broken == 'flush':
                raise OSError('PRIVATE')
            return super().flush()
    with InstallationProgress(stream=Broken()) as progress:
        progress(event('DOWNLOAD_STARTED'))
        progress(event())
        progress.finish(False)
    assert not progress._thread.is_alive()


def test_private_child_event_protocol_stays_newline_delimited_json(capsys):
    data = event()
    child_preparation_progress(data)
    output = capsys.readouterr()
    assert not output.out and output.err.endswith('\n') and '\r' not in output.err
    assert json.loads(output.err.removeprefix(EVENT_PREFIX)) == data


def test_component_completion_ends_row_and_next_download_starts_fresh():
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        progress(dict(event='COMPONENT_STARTED', component='gitleaks'))
        first = dict(event(), component='gitleaks')
        progress(first)
        progress(dict(event='COMPONENT_COMPLETE', component='gitleaks'))
        progress(dict(event='COMPONENT_STARTED', component='trivy'))
        now[0] += 2
        progress(dict(event(received=3), component='trivy'))
        assert '\n[安装] 密钥检查组件已准备完成' in stream.getvalue()
        assert '依赖检查' in stream.getvalue().split('\r')[-1]
        assert '3.0%' in stream.getvalue().split('\r')[-1]


def test_budget_exhaustion_explains_bounded_retry_without_false_readiness():
    stream = io.StringIO()
    with InstallationProgress(stream=stream, preparation=True) as progress:
        progress(event(received=61))
        progress(event('DOWNLOAD_FAILED', error_code='PREPARATION_BUDGET_EXHAUSTED'))
        progress.finish(False)
    text = stream.getvalue()
    assert 'prepare-scanners --timeout 900' in text and '会重新下载' in text
    assert '不必重新安装' in text and '扫描能力准备完成' not in text


def test_eta_follows_real_deltas_and_stale_rate_is_removed_without_countdown(monkeypatch):
    monkeypatch.setattr(shutil, 'get_terminal_size', lambda **kw: os.terminal_size((120, 24)))
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        progress(event('DOWNLOAD_STARTED'))
        progress(event(received=0))
        assert '估算中' in stream.getvalue().split('\r')[-1]
        now[0] = 4
        progress(event(received=40))
        long_line = stream.getvalue().split('\r')[-1]
        assert '10.00 MiB/s' in long_line and '预计剩余6秒' in long_line
        now[0] = 16
        progress._heartbeat()
        short_line = stream.getvalue().split('\r')[-1]
        assert '估算中' in short_line and '等待新进度' in short_line
        assert 'MiB/s' not in short_line and '预计剩余' not in short_line
        cells = lambda line: sum(2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in line)
        assert short_line.endswith(' ') and cells(short_line) >= cells(long_line)


def test_standard_terminal_keeps_rate_and_eta_visible(monkeypatch):
    monkeypatch.setattr(shutil, 'get_terminal_size', lambda **kw: os.terminal_size((80, 24)))
    stream, now = Terminal(), [0.0]
    with InstallationProgress(stream=stream, clock=lambda: now[0]) as progress:
        progress(event(received=0, total=127))
        now[0] = 10
        progress(event(received=3, total=127))
        line = stream.getvalue().split('\r')[-1]
        assert '0.30 MiB/s' in line and '预计剩余6分54秒' in line
        assert '3.00/127.00 MiB' in line and '[' in line


def test_adaptive_policy_explains_estimate_and_absolute_limit_once():
    stream = io.StringIO()
    with InstallationProgress(stream=stream, preparation=True, adaptive=True,
            initial_seconds=300, max_wait_seconds=1800):
        pass
    assert stream.getvalue().count('按真实进度自动续等') == 1
    assert '初始等待 300 秒' in stream.getvalue() and '最长 1800 秒' in stream.getvalue()


def test_adaptive_limit_failure_does_not_offer_a_shorter_initial_budget_as_a_fix():
    stream = io.StringIO()
    with InstallationProgress(stream=stream, preparation=True, adaptive=True) as progress:
        progress(event('DOWNLOAD_FAILED', error_code='PREPARATION_BUDGET_EXHAUSTED'))
        progress.finish(False)
    assert '检查下载网络后重试' in stream.getvalue()
    assert '--timeout 900' not in stream.getvalue() and '扫描能力准备完成' not in stream.getvalue()


@pytest.mark.parametrize('terminal', [True, False])
def test_prepare_json_receipt_is_separate_from_download_display(monkeypatch, capsys, terminal):
    import sys
    from security_runtime.cli import main
    from test_personal_install_readiness import readiness
    stream = Terminal() if terminal else io.StringIO()
    monkeypatch.setattr(sys, 'stderr', stream)
    receipt = readiness(ready=True)
    def prepare(**kwargs):
        callback = kwargs['progress']
        callback(event('DOWNLOAD_STARTED'))
        callback(event())
        callback(event('DOWNLOAD_VALIDATING'))
        callback(event('DOWNLOAD_COMPLETE'))
        return receipt
    monkeypatch.setattr('security_runtime.install_readiness.prepare_installation_readiness', prepare)
    assert main(['prepare-scanners', '--json']) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == receipt and len(out.splitlines()) == 1
    assert '[安装]' not in out and '下载进度' in stream.getvalue()

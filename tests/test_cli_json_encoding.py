"""Machine-readable CLI output survives legacy Windows pipeline decoders."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from security_runtime import cli


@pytest.mark.parametrize('encoding', ['cp936', 'cp1252', 'utf-8'])
@pytest.mark.parametrize('entry', ['runtime-info', 'review-skill', 'summary', 'scan'])
def test_cli_json_preserves_unicode_after_pipeline_decoding(tmp_path, monkeypatch, entry, encoding):
    payload = {'version': '0.3.5', 'status': 'INSTALLED',
               'message': '安全检查。“中文引号”与结束标点。',
               'path': 'C:\\测试目录\\工具.exe', 'nested': ['恢复连接', '🔒']}
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL', raising=False)
    monkeypatch.setattr(cli, 'configure_logging', lambda **kwargs: None)
    if entry == 'runtime-info':
        monkeypatch.setattr('security_runtime.host_guidance.runtime_info', lambda: payload)
        args = ['runtime-info', '--json']
    elif entry == 'review-skill':
        monkeypatch.setattr('security_runtime.review_skill.ReviewSkillManager',
                            lambda path: SimpleNamespace(execute=lambda action: payload))
        args = ['review-skill', 'status', '--json']
    elif entry == 'summary':
        monkeypatch.setattr('security_runtime.security_summary.SecuritySummaryService',
                            lambda: SimpleNamespace(get=lambda *args, **kwargs: payload))
        args = ['summary', '--path', str(tmp_path), '--json']
    else:
        result = SimpleNamespace(to_dict=lambda: payload, release_status='READY',
                                 duration_ms=0, findings=[], coverage='FULL',
                                 target_profile=SimpleNamespace(path=str(tmp_path)))
        monkeypatch.setattr(cli, 'ScannerRegistry', lambda: object())
        monkeypatch.setattr(cli, 'SecurityRuntime',
                            lambda **kwargs: SimpleNamespace(scan=lambda *args, **kw: result))
        monkeypatch.setattr(cli, 'IntegrationStateStore',
                            lambda: SimpleNamespace(event=lambda event: None))
        args = ['scan', '--path', str(tmp_path), '--json', '--no-progress']
    captured = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', captured)
    assert cli.main(args) == 0
    raw_stdout = captured.getvalue().encode('utf-8')
    # Test the consumer boundary, including exact Chinese/path/emoji values.
    assert json.loads(raw_stdout.decode(encoding)) == payload


def test_runtime_info_human_output_retains_readable_chinese(monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL', raising=False)
    monkeypatch.setattr(cli, 'configure_logging', lambda **kwargs: None)
    monkeypatch.setattr('security_runtime.host_guidance.runtime_info', lambda: {
        'version': '0.3.5', 'capability_contract': 'developer-guidance-v0.3',
        'connection_recovery': ['连接已准备好。']})
    captured = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', captured)
    assert cli.main(['runtime-info']) == 0
    assert '连接已准备好。' in captured.getvalue()


@pytest.mark.skipif(os.name != 'nt' or not shutil.which('powershell.exe'),
                    reason='Requires Windows PowerShell')
def test_windows_powershell_parses_runtime_info_under_cp936(tmp_path):
    script = tmp_path / 'pipeline.ps1'
    script.write_text(r'''$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)
$OutputEncoding = [Console]::OutputEncoding
$info = (& $env:CLI_ENCODING_TEST_PYTHON -m security_runtime.cli runtime-info --json) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Runtime command failed' }
if ($info.features.task_security_review_protocol -notlike 'task-review-plan-v3*') {
    throw 'Unexpected review protocol'
}
$info.version
$info.features.task_security_review_protocol
''', encoding='ascii')
    env = dict(os.environ, CLI_ENCODING_TEST_PYTHON=sys.executable,
               PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
               SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'))
    env.pop('SECURITY_RUNTIME_GLOBAL', None)
    completed = subprocess.run([shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive',
                                '-File', str(script)], env=env, capture_output=True, timeout=60,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    assert completed.returncode == 0, completed.stderr.decode('cp936', errors='replace')
    assert b'task-review-plan-v3' in completed.stdout
    assert b'task-review-plan-v2' in completed.stdout  # legacy capability remains advertised

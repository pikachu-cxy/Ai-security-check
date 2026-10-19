"""Launch failures retain actionable numeric facts, never private arguments."""
import json
import sys
from types import SimpleNamespace

import pytest

from security_runtime.diagnostics import classify_network_error
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessStartError, run_process
from security_runtime.scanners import BaseScanner
from security_runtime.toolchain import ResolvedTool, ToolStatus


def test_real_missing_cwd_has_bounded_process_start_diagnostics(tmp_path):
    cwd = tmp_path/'PRIVATE_CWD_DO_NOT_REPORT'
    with pytest.raises(ProcessStartError) as caught:
        run_process([sys.executable, '-c', 'PRIVATE_SOURCE_DO_NOT_REPORT'], cwd=cwd,
            env={'PRIVATE_ENV_DO_NOT_REPORT': 'PRIVATE_VALUE'}, capture_start_failure=True)
    error = caught.value
    assert error.failure['stage'] == 'PROCESS_START'
    assert error.failure['cwd_length'] == len(str(cwd))
    assert type(error.failure['errno']) is int or type(error.failure['winerror']) is int
    diagnostic = classify_network_error(error)
    assert diagnostic.error_code == 'PROCESS_START_FAILED'
    assert 'PRIVATE_' not in json.dumps(diagnostic.to_dict()) + str(error)


def test_windows_error_number_survives_without_os_exception_text():
    original = OSError(22, 'PRIVATE_COMMAND http://private.invalid/?token=PRIVATE')
    original.winerror = 267
    error = ProcessStartError(original, cwd='PRIVATE_CWD', executable='PRIVATE_EXE')
    assert error.failure == dict(stage='PROCESS_START', exception_type='OSError', errno=22,
        winerror=267, cwd_length=11, executable_length=11)
    assert 'PRIVATE' not in json.dumps(classify_network_error(error).to_dict())


def test_scanner_result_preserves_safe_launch_stage_and_os_numbers(tmp_path):
    class InertScanner(BaseScanner):
        name = scanner_id = 'inert-launch-test'
        def _environment(self, binary, context):
            return {}
        def _scan(self, binary, context, normalizer):
            run_process([sys.executable, '-c', 'pass'], cwd=tmp_path/'PRIVATE_MISSING', capture_start_failure=True)
    manager = SimpleNamespace(ensure=lambda *args, **kwargs:
        ResolvedTool('inert', 'fixture', sys.executable, None, ToolStatus.READY))
    scanner = InertScanner(manager)
    found, run = scanner.scan(ScanContext(str(tmp_path), ScanMode.QUICK, ()), FindingNormalizer(tmp_path))
    assert found == [] and run.error_code == 'PROCESS_START_FAILED'
    assert run.scanner_diagnostics['failure']['stage'] == 'PROCESS_START'
    assert run.scanner_diagnostics['failure']['cwd_length'] > 0
    assert 'PRIVATE_' not in json.dumps(run.scanner_diagnostics)


@pytest.mark.parametrize('error', [FileNotFoundError(2, 'missing'), PermissionError(13, 'denied')])
def test_general_callers_keep_the_original_os_exception_type(monkeypatch, error):
    def failed(*args, **kwargs):
        raise error
    monkeypatch.setattr('security_runtime.processes.subprocess.Popen', failed)
    with pytest.raises(type(error)) as caught:
        run_process([sys.executable, '-c', 'pass'])
    assert caught.value is error


@pytest.mark.parametrize('error,code', [(FileNotFoundError(2, 'missing'), 'RUNTIME_MISSING'),
    (PermissionError(13, 'denied'), 'RUNTIME_LAUNCH_PERMISSION_DENIED')])
def test_codex_probe_keeps_its_existing_launch_diagnostic(monkeypatch, tmp_path, error, code):
    from security_runtime.codex_integration import probe_runtime
    from security_runtime.integration_lifecycle import IntegrationDiagnostic
    def failed(*args, **kwargs):
        raise error
    monkeypatch.setattr('security_runtime.processes.subprocess.Popen', failed)
    with pytest.raises(IntegrationDiagnostic, match=code):
        probe_runtime(dict(command=sys.executable, prefix=[]), tmp_path, {})

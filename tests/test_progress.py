"""Progress is local, bounded, parallel, stderr-only and cancellable."""
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch
from urllib.error import URLError

import pytest

from security_runtime.cli import main, render
from security_runtime.cli_progress import CLIProgressRenderer
from security_runtime.diagnostics import classify_network_error
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScannerRun, ScanContext, ScanMode
from security_runtime.progress import (ProgressEvent, ProgressReporter, NullProgressReporter,
    progress_context, emit, ScanCancelled)
from security_runtime.processes import run_process
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry, BaseScanner
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus, OfficialReleaseProvider
from security_runtime.capabilities import Capability


class FakeScanner:
    filter_changed_lines = False
    capabilities = frozenset({Capability.SECRET_SCAN})
    def __init__(self, name='test-engine', status='SUCCESS', delay=0):
        self.name = self.scanner_id = name
        self.status, self.delay = status, delay
    def supports(self, profile, context):
        return bool(context.files)
    def scan(self, context, normalizer):
        time.sleep(self.delay)
        return [], ScannerRun(self.name, '1.0', self.status, round(self.delay*1000), 0,
            error_code='PROCESS_TIMEOUT' if self.status == 'TIMEOUT' else '')


def engine(tmp_path, adapters):
    (tmp_path / 'app.py').write_text('pass\n')
    return SecurityRuntime(ScannerRegistry(adapters), SQLiteStore(tmp_path / '.security-runtime/state.db'))


def test_event_structure_and_sanitization():
    events=[]
    reporter=ProgressReporter(events.append)
    event=reporter.emit('SCANNER_COMPLETED', scanner='engine', scanner_version='1.0',
        capability=('SECRET_SCAN',), duration_ms=1100, finding_count=9, message='password=PRIVATE_VALUE')
    data=asdict(event)
    assert data['duration_ms'] == 1100 and data['finding_count'] == 9
    assert data['elapsed_ms'] >= 0 and data['timestamp']
    assert data['capability'] == ('SECRET_SCAN',)
    assert 'PRIVATE_VALUE' not in json.dumps(data)
    assert events == [event]


def test_null_reporter_no_output(tmp_path, capsys):
    engine(tmp_path,[FakeScanner()]).scan(tmp_path,'release',progress=NullProgressReporter())
    assert capsys.readouterr() == ('','')


def test_library_default_no_output(tmp_path,capsys):
    engine(tmp_path,[FakeScanner()]).scan(tmp_path,'release')
    assert capsys.readouterr() == ('','')


@pytest.mark.parametrize('status,event_type',[('SUCCESS','SCANNER_COMPLETED'),('FAILED','SCANNER_FAILED'),
    ('UNAVAILABLE','SCANNER_UNAVAILABLE'),('TIMEOUT','SCANNER_TIMEOUT')])
def test_scanner_lifecycle(tmp_path,status,event_type):
    events=[]
    runtime=engine(tmp_path,[FakeScanner(status=status)])
    runtime.scan(tmp_path,'release',progress=ProgressReporter(events.append))
    types=[e.event_type for e in events]
    assert 'SCANNER_STARTED' in types and event_type in types
    for event in ('SCAN_STARTED','WORKSPACE_DISCOVERY_STARTED','WORKSPACE_DISCOVERY_COMPLETED',
        'TARGET_DISCOVERY_STARTED','TARGET_DISCOVERY_COMPLETED','PLANNING_STARTED','PLAN_READY','SCAN_COMPLETED'):
        assert event in types
    completed=next(e for e in events if e.event_type == event_type)
    assert completed.scanner_version == '1.0' and completed.finding_count == 0


def test_parallel_completion_feedback_not_registry_order(tmp_path):
    events=[]
    barrier=threading.Barrier(2)
    class Scanner(FakeScanner):
        def scan(self,*args):
            barrier.wait(timeout=2)
            return super().scan(*args)
    runtime=engine(tmp_path,[Scanner('slow',delay=.2),Scanner('fast')])
    runtime.scan(tmp_path,'release',progress=ProgressReporter(events.append))
    finished=[event.scanner for event in events if event.event_type=='SCANNER_COMPLETED']
    assert finished == ['fast','slow']


def test_failing_progress_sink_does_not_fail_scan(tmp_path):
    def sink(event): raise OSError('closed terminal')
    assert engine(tmp_path,[FakeScanner()]).scan(tmp_path,'release',progress=ProgressReporter(sink)).scanner_runs[0].status=='SUCCESS'


@pytest.mark.parametrize('ready',[True,False])
def test_engine_prepare_events(tmp_path,ready):
    events=[]
    manager=ToolManager(root=tmp_path)
    diagnostic=classify_network_error(TimeoutError(),url='https://github.com/private')
    result=ResolvedTool('gitleaks','8.30.0','',None,ToolStatus.READY if ready else ToolStatus.BROKEN,
                        diagnostic= None if ready else diagnostic)
    with patch.object(manager,'_ensure',return_value=result),progress_context(ProgressReporter(events.append)):
        manager.ensure('gitleaks')
    assert [event.event_type for event in events] == ['ENGINE_PREPARING','ENGINE_READY' if ready else 'ENGINE_PREPARATION_FAILED']
    if not ready:
        assert events[-1].error_code == 'NETWORK_TIMEOUT' and events[-1].source == 'github.com'


def test_first_download_feedback_uses_network_diagnostic(tmp_path):
    manager=ToolManager(root=tmp_path)
    events=[]
    with patch.object(manager,'resolve',return_value=ResolvedTool('gitleaks','','',None,ToolStatus.MISSING)), \
         patch('urllib.request.urlopen',side_effect=URLError(TimeoutError('password=PRIVATE_VALUE'))), \
         progress_context(ProgressReporter(events.append)):
        result=manager.ensure('gitleaks',offline=False)
    assert result.diagnostic.error_code=='NETWORK_TIMEOUT'
    assert 'ENGINE_DOWNLOAD_STARTED' in [e.event_type for e in events]
    assert 'ENGINE_DOWNLOAD_FAILED' in [e.event_type for e in events]
    assert 'PRIVATE_VALUE' not in json.dumps([asdict(e) for e in events])


def test_download_success_events(tmp_path):
    manager=ToolManager(root=tmp_path)
    events=[]
    with patch.object(manager.provider,'_download'),progress_context(ProgressReporter(events.append)):
        manager.provider.download(manager.manifest('gitleaks'),tmp_path/'asset')
    assert [e.event_type for e in events]==['ENGINE_DOWNLOAD_STARTED','ENGINE_DOWNLOAD_COMPLETED']


def test_cancellation_during_tool_resolution_is_not_preparation_failure(tmp_path):
    manager=ToolManager(root=tmp_path)
    events=[]
    with patch.object(manager,'resolve',side_effect=ScanCancelled()),progress_context(ProgressReporter(events.append)):
        with pytest.raises(ScanCancelled):
            manager.ensure('gitleaks')
    assert [e.event_type for e in events]==['ENGINE_PREPARING']


@pytest.mark.parametrize('state',['READY','BROKEN'])
def test_data_preparation_events(tmp_path,state):
    manager=ToolManager(root=tmp_path)
    events=[]
    with patch.object(manager,'_prepare_trivy_database',return_value=state),progress_context(ProgressReporter(events.append)):
        manager.prepare_trivy_database('trivy')
    assert [e.event_type for e in events]==['DATA_PREPARING','DATA_READY' if state=='READY' else 'DATA_PREPARATION_FAILED']


def test_ready_database_quiet(tmp_path):
    manager=ToolManager(root=tmp_path)
    events=[]
    with patch.object(manager,'database_status',return_value='READY'),progress_context(ProgressReporter(events.append)):
        assert manager.prepare_trivy_database('trivy')=='READY'
    assert events==[]


@pytest.mark.parametrize('tty',[False,True])
def test_renderer_heartbeat_and_elapsed(tty):
    clock=[0.]
    stream=io.StringIO()
    renderer=CLIProgressRenderer(stream,tty=tty,delay=.5,heartbeat_interval=1,clock=lambda:clock[0])
    reporter=renderer.reporter
    reporter.emit('SCANNER_STARTED',scanner='trivy',scanner_version='0.74.0')
    assert stream.getvalue()==''
    clock[0]=.5;renderer.tick()
    assert 'trivy 0.74.0' in stream.getvalue()
    clock[0]=2.;renderer.tick()
    text=stream.getvalue()
    assert '2s' in text and '正在运行' in text
    assert ('\r' in text) == tty
    assert '\x1b' not in text and '%' not in text
    reporter.emit('SCANNER_COMPLETED',scanner='trivy',duration_ms=2300,finding_count=9)
    assert '9 个问题' in stream.getvalue() and '2.3s' in stream.getvalue()
    before=stream.getvalue();clock[0]=20.;renderer.tick()
    assert stream.getvalue()==before


def test_non_tty_heartbeat_throttled():
    clock=[0.];stream=io.StringIO()
    renderer=CLIProgressRenderer(stream,tty=False,delay=0,clock=lambda:clock[0])
    renderer.reporter.emit('SCANNER_STARTED',scanner='engine')
    for value in range(1,10): clock[0]=value;renderer.tick()
    assert '仍在处理' not in stream.getvalue()
    clock[0]=10.;renderer.tick()
    assert stream.getvalue().count('仍在处理')==1


def test_short_scan_no_progress_noise(tmp_path):
    stream=io.StringIO()
    renderer=CLIProgressRenderer(stream,tty=False,delay=10)
    with renderer as reporter:
        engine(tmp_path,[FakeScanner()]).scan(tmp_path,'release',progress=reporter)
    assert stream.getvalue()==''


@pytest.mark.parametrize('json_output',[False,True])
@pytest.mark.parametrize('no_progress',[False,True])
def test_cli_stdout_stderr_separation(tmp_path,capsys,json_output,no_progress):
    runtime=engine(tmp_path,[FakeScanner(delay=.6)])
    args=['scan','--mode','release','--path',str(tmp_path)]
    if json_output: args.append('--json')
    if no_progress: args.append('--no-progress')
    with patch('security_runtime.cli.SecurityRuntime',return_value=runtime),patch('security_runtime.cli.configure_logging'):
        assert main(args)==0
    output=capsys.readouterr()
    if json_output:
        assert json.loads(output.out)['scanner_runs'][0]['status']=='SUCCESS'
    else:
        assert '安全检查' in output.out
    assert ('正在运行' in output.err) != no_progress
    assert '[SCANNER' not in output.out and '\x1b' not in output.err and '\r' not in output.err


def test_no_change_scan_no_engine_progress(tmp_path):
    import subprocess
    (tmp_path/'app.py').write_text('pass\n')
    subprocess.run(['git','init','-q',str(tmp_path)],check=True)
    subprocess.run(['git','-C',str(tmp_path),'add','app.py'],check=True)
    subprocess.run(['git','-C',str(tmp_path),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','base'],check=True)
    events=[]
    runtime=SecurityRuntime(ScannerRegistry([FakeScanner()]),SQLiteStore(tmp_path/'.security-runtime/state.db'))
    result=runtime.scan(tmp_path,progress=ProgressReporter(events.append))
    assert result.status=='NO_CHANGES'
    assert not any(event.event_type.startswith(('ENGINE_','SCANNER_','DATA_')) for event in events)


def test_chinese_relation_and_retry(tmp_path):
    from test_diagnostics import mock_registry,java_fixture
    java_fixture(tmp_path)
    registry,execute=mock_registry(tmp_path)
    runtime=SecurityRuntime(registry,SQLiteStore(tmp_path/'.security-runtime/state.db'))
    with patch('security_runtime.scanners._execute',side_effect=execute): result=runtime.scan(tmp_path,'release')
    text=render(result)
    for phrase in ('安全检查','为什么覆盖不完整','trivy-vuln 未完成，因此','依赖安全未完成','敏感信息检测：已完成','Maven 仓库返回 HTTP 429','重试：security-check scan --mode release'):
        assert phrase in text
    assert '<project>' not in text and 'Why partial?' not in text and 'Security checks' not in text
    assert next(run for run in result.scanner_runs if run.scanner=='trivy-vuln').error_summary.startswith('Maven repository')


def test_not_applicable_hidden_unless_verbose(tmp_path):
    result=engine(tmp_path,[FakeScanner()]).scan(tmp_path,'release')
    assert '本次不适用' not in render(result)
    assert '本次不适用' in render(result,verbose=True)


def test_cancellation_kills_external_worker_and_emits_event(tmp_path):
    events=[];reporter=ProgressReporter(events.append)
    sentinel=tmp_path/'.security-runtime/late-file'
    class Scanner(FakeScanner):
        def scan(self,context,normalizer):
            run_process([sys.executable,'-c',f'import time;from pathlib import Path;time.sleep(3);Path({str(sentinel)!r}).touch()'],timeout=10)
            return super().scan(context,normalizer)
    timer=threading.Timer(.3,reporter.cancel)
    timer.start();start=time.monotonic()
    try:
        with pytest.raises(ScanCancelled): engine(tmp_path,[Scanner()]).scan(tmp_path,'release',progress=reporter)
    finally: timer.cancel()
    assert time.monotonic()-start<2
    assert not sentinel.exists()
    assert events[-1].event_type=='SCAN_CANCELLED'


def test_blocking_download_can_be_cancelled_without_late_writes(tmp_path):
    reporter=ProgressReporter();gate=threading.Event();entered=threading.Event()
    class Response(io.BytesIO): url='https://github.com/fixture'
    def connect(*args,**kwargs):
        entered.set();gate.wait(timeout=2);return Response(b'download')
    timer=threading.Timer(.2,reporter.cancel)
    timer.start()
    destination=tmp_path/'asset'
    try:
        with patch('urllib.request.urlopen',side_effect=connect),progress_context(reporter):
            with pytest.raises(ScanCancelled):
                OfficialReleaseProvider().download(ToolManager(root=tmp_path).manifest('gitleaks'),destination)
    finally:
        gate.set();timer.cancel()
    assert entered.is_set() and not destination.exists()


def test_cancellation_kills_scanner_helper_process(tmp_path):
    reporter=ProgressReporter()
    sentinel=tmp_path/'helper-late-file'
    helper=f'import time;from pathlib import Path;time.sleep(1.5);Path({str(sentinel)!r}).touch()'
    parent=f'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",{helper!r}]);time.sleep(30)'
    timer=threading.Timer(.4,reporter.cancel)
    timer.start()
    try:
        with progress_context(reporter),pytest.raises(ScanCancelled):
            run_process([sys.executable,'-c',parent],timeout=40)
    finally:
        timer.cancel();timer.join(timeout=1)
    time.sleep(1.6)
    assert not sentinel.exists()


def test_cli_keyboard_interrupt_no_traceback(capsys):
    with patch('security_runtime.cli.SecurityRuntime.scan',side_effect=KeyboardInterrupt()),patch('security_runtime.cli.configure_logging'):
        assert main(['scan','--no-progress'])==130
    output=capsys.readouterr()
    assert output.out=='' and '扫描已取消' in output.err and 'Traceback' not in output.err


def test_ctrl_c_interrupts_waiting_cli_worker(tmp_path,capsys):
    import _thread
    class Scanner(FakeScanner):
        def scan(self,context,normalizer):
            run_process([sys.executable,'-c','import time; time.sleep(30)'],timeout=40)
            return super().scan(context,normalizer)
    runtime=engine(tmp_path,[Scanner()])
    timer=threading.Timer(.4,_thread.interrupt_main)
    start=time.monotonic()
    with patch('security_runtime.cli.SecurityRuntime',return_value=runtime),patch('security_runtime.cli.configure_logging'):
        timer.start()
        try:
            assert main(['scan','--mode','release','--path',str(tmp_path)])==130
        finally:
            timer.cancel();timer.join(timeout=1)
    assert time.monotonic()-start<2
    output=capsys.readouterr()
    assert '扫描已取消' in output.err and 'Traceback' not in output.err and output.out==''


def test_download_completion_restores_preparation_heartbeat():
    clock=[0.];stream=io.StringIO()
    renderer=CLIProgressRenderer(stream,tty=False,delay=0,heartbeat_interval=1,clock=lambda:clock[0])
    renderer.reporter.emit('ENGINE_PREPARING',scanner='gitleaks')
    renderer.reporter.emit('ENGINE_DOWNLOAD_STARTED',scanner='gitleaks')
    renderer.reporter.emit('ENGINE_DOWNLOAD_COMPLETED',scanner='gitleaks')
    clock[0]=2.;renderer.tick()
    assert '仍在处理 gitleaks' in stream.getvalue() and '正在准备引擎' in stream.getvalue()


def test_mcp_tools_default_no_cli_progress(tmp_path,monkeypatch,capsys):
    from security_runtime.mcp_server import create_server
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    runtime=engine(tmp_path,[FakeScanner()])
    # MCP's stdio client binds stderr as a default argument on first import.
    # Do not bind pytest's temporary StringIO to later real-process checks.
    with capsys.disabled():
        server=create_server(runtime)
    assert {tool.name for tool in server._tool_manager.list_tools()}=={'scan_diff','scan_project','get_findings','generate_fix','verify','prepare_triage','submit_triage','get_triage','get_security_summary'}
    result=server._tool_manager.get_tool('scan_project').fn(str(tmp_path))
    assert result['status']=='COMPLETED' or result['status']=='PARTIAL'
    assert capsys.readouterr() == ('','')

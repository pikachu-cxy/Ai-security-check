import asyncio
import importlib.util
import json
import os
from pathlib import Path
import pytest
from security_runtime import performance_trace as perf


def configure(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_DIR', str(tmp_path))
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_RUN', 'a'*32)


def rows(tmp_path):
    return [json.loads(line) for p in tmp_path.glob('events-*.jsonl') for line in p.read_text().splitlines()]


def test_nested_exception_no_payload(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    @perf.timed('test.child')
    def child(secret):
        raise ValueError(secret)
    with perf.span('test.parent'):
        with pytest.raises(ValueError,match='PRIVATE_SECRET'):
            child('PRIVATE_SECRET')
    data=rows(tmp_path)
    assert len(data)==4
    assert data[1]['parent']==data[0]['span']
    assert data[2]['status']=='raised'
    assert data[3]['status']=='returned'
    assert 'PRIVATE_SECRET' not in json.dumps(data)


def test_disabled_and_unwritable_preserve_result(monkeypatch,tmp_path):
    monkeypatch.delenv('SECURITY_RUNTIME_PERF_DIR',raising=False)
    @perf.timed('test.result')
    def result(): return 42
    assert result()==42 and not rows(tmp_path)
    configure(monkeypatch,tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_DIR',str(tmp_path/'missing'))
    assert result()==42 and not rows(tmp_path)


def test_async_cancellation_keeps_parent_separate(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    @perf.timed('test.async')
    async def work(): raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError): asyncio.run(work())
    assert rows(tmp_path)[-1]['status']=='raised'
    assert perf._PARENT.get() is None


@pytest.mark.skipif(os.name == 'nt', reason='POSIX permissions and symlinks')
def test_symlink_and_public_directory_rejected(monkeypatch,tmp_path):
    root=tmp_path/'private';root.mkdir(mode=0o700)
    link=tmp_path/'alias';link.symlink_to(root,target_is_directory=True)
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_RUN','a'*32)
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_DIR',str(link))
    with perf.span('test.link'): pass
    assert not rows(root)
    monkeypatch.setenv('SECURITY_RUNTIME_PERF_DIR',str(root));root.chmod(0o755)
    with perf.span('test.public'): pass
    assert not rows(root)


def test_report_incomplete_does_not_claim_success(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    with perf.span('test.complete'): pass
    perf._write(dict(event='start',span='unfinished',parent=None,phase='test.pending',monotonic_ns=1,wall_ns=1))
    (tmp_path/'run.json').write_text(json.dumps({'run':'a'*32}))
    path=Path(__file__).parents[1]/'scripts/performance/report.py'
    spec=importlib.util.spec_from_file_location('perf_report',path); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    report=module.report(tmp_path)
    assert report['unmatched_starts']==1 and not report['measurement_valid']
    assert report['phases'][0]['p95_ms'] is None


def test_concurrent_calls_do_not_share_parents(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    async def work():
        with perf.span('test.concurrent'):
            await asyncio.sleep(0)
    async def run(): await asyncio.gather(work(),work())
    asyncio.run(run())
    starts=[r for r in rows(tmp_path) if r['event']=='start']
    assert len(starts)==2 and all(r['parent'] is None for r in starts)


def test_queue_digest_matches_without_reference_disclosure(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    value={'check_ref':'PRIVATE_CHECK_REFERENCE','dirty_seq':7}
    perf.queue_event('submitted',value);perf.queue_event('attempt',value)
    data=rows(tmp_path)
    assert data[0]['batch']==data[1]['batch']
    assert 'PRIVATE_CHECK_REFERENCE' not in json.dumps(data)


def test_file_cap_preserves_operation(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    monkeypatch.setattr(perf,'_MAX_BYTES',1)
    @perf.timed('test.capped')
    def work(): return 'kept'
    assert work()=='kept' and not rows(tmp_path)


def test_report_review_completion_and_overlapping_calls(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    times = iter([0, 1_000_000, 3_000_000, 5_000_000])
    monkeypatch.setattr(perf.time, 'perf_counter_ns', lambda: next(times))
    check = dict(check_ref='private', dirty_seq=1)
    perf.review_event('evidence_read', check)
    perf.review_event('saved', check, dict(scanner_review='COMPLETE', business_review='PENDING'))
    perf.review_event('saved', check, dict(scanner_review='COMPLETE', business_review='COMPLETE'))
    perf.review_event('evidence_read', dict(check, dirty_seq=2))
    for identity, start, end in [('a', 0, 4_000_000), ('b', 2_000_000, 6_000_000), ('c', 8_000_000, 9_000_000)]:
        perf._write(dict(event='start', span=identity, phase='mcp.fixture', monotonic_ns=start))
        perf._write(dict(event='end', span=identity, phase='mcp.fixture', monotonic_ns=end, status='returned'))
    (tmp_path/'run.json').write_text(json.dumps({'run':'a'*32}))
    path = Path(__file__).parents[1]/'scripts/performance/report.py'
    spec = importlib.util.spec_from_file_location('perf_report', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    result = module.report(tmp_path)
    assert result['measurement_valid']
    assert result['mcp_timing'] == dict(observed_window_ms=9, active_call_ms=7,
        model_thinking_ms=None, first_call_to_final_reply_ms=None)
    assert result['review_windows'][0]['first_evidence_to_complete_ms'] == 3
    assert result['review_windows'][1]['first_evidence_to_complete_ms'] is None
    assert result['review_windows'][1]['review_completed'] is False


def test_grouped_mcp_timing_uses_operation_name(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from mcp.types import CallToolRequest
    configure(monkeypatch, tmp_path)
    async def original(request): return 'unchanged'
    handlers = {CallToolRequest: original}
    registry = SimpleNamespace(low_level=SimpleNamespace(request_handlers=handlers),
        names=lambda: {'submit_development_review'})
    perf.observe_mcp(registry)
    request = SimpleNamespace(params=SimpleNamespace(name='development_review',
        arguments=dict(operation='submit_development_review', arguments={})))
    assert asyncio.run(handlers[CallToolRequest](request)) == 'unchanged'
    assert {r['phase'] for r in rows(tmp_path)} == {'mcp.submit_development_review'}


def test_measure_runner_preserves_exit_and_excludes_output():
    import subprocess
    import sys
    script=Path(__file__).parents[1]/'scripts/performance/measure.py'
    result=subprocess.run([sys.executable,str(script),'--scenario','smoke','--cache','unknown',
        '--build','fixture','--',sys.executable,'-c',
        'import sys; print("PRIVATE_OUTPUT",file=sys.stderr); sys.exit(7)'],capture_output=True,text=True)
    assert result.returncode==7
    root=Path(result.stderr.rsplit('Timing directory: ',1)[1].strip())
    manifest=json.loads((root/'run.json').read_text())
    assert manifest['exit_code']==7 and not manifest['launch_failed']
    assert 'PRIVATE_OUTPUT' not in (root/'run.json').read_text()


def test_measure_runner_timeout_saved():
    import subprocess
    import sys
    script=Path(__file__).parents[1]/'scripts/performance/measure.py'
    result=subprocess.run([sys.executable,str(script),'--scenario','smoke','--cache','unknown',
        '--build','fixture','--timeout','.05','--',sys.executable,'-c',
        'import time; time.sleep(10)'],capture_output=True,text=True)
    root=Path(result.stderr.rsplit('Timing directory: ',1)[1].strip())
    assert result.returncode==124 and json.loads((root/'run.json').read_text())['timed_out']

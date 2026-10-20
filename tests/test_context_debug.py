import asyncio
import json
import sqlite3
from types import SimpleNamespace

import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_mcp import observe_response
from security_runtime.context_report import report_data, write_report


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE', raising=False)
    return ContextCostStore(tmp_path / 'cost.sqlite3')


def test_mode_switch_is_live_across_instances_and_off_retains_history(store):
    assert store.monitoring()['mode'] == 'basic'
    assert not store.path.exists()
    assert store.set_monitoring('debug')['effective']['mode'] == 'debug'
    other = ContextCostStore(store.path)
    assert other.record_call('scan_project', {}, started_at=100, finished_at=101, elapsed_ms=1000)['status'] == 'RECORDED'
    assert store.set_monitoring('off')['effective']['mode'] == 'off'
    assert other.record_call('get_runtime_info', {})['status'] == 'DISABLED'
    assert other.summary()['calls'] == 1
    assert store.set_monitoring('basic')['effective']['mode'] == 'basic'
    other.record_call('get_runtime_info', {}, started_at=102, finished_at=103)
    events = report_data(store)['events']
    assert events[0]['started_at'] is None
    assert events[1]['started_at'] == 100


def test_debug_run_label_changes_without_process_restart(store):
    store.set_monitoring('debug', 'pilot-one')
    store.record_call('get_runtime_info', {})
    store.set_monitoring('debug', 'pilot-two')
    store.record_call('get_runtime_info', {})
    assert report_data(store, 'pilot-one')['summary']['calls'] == 1
    assert report_data(store, 'pilot-two')['summary']['calls'] == 1
    assert store.set_monitoring('off')['effective']['run'] == 'pilot-two'


def test_env_override_and_invalid_settings_fail_closed(store, monkeypatch):
    store.set_monitoring('debug')
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '0')
    assert store.set_monitoring('basic')['effective']['mode'] == 'off'
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR')
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', 'not-a-mode')
    assert store.monitoring()['status'] == 'UNAVAILABLE'
    assert store.record_call('scan_project', {})['status'] == 'UNAVAILABLE'
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE')
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE monitor_settings SET record=?', (b'{"mode":"debug"}',))
    assert store.monitoring()['mode'] == 'off'
    assert store.monitoring()['status'] == 'UNAVAILABLE'


def test_old_database_without_setting_table_remains_readable(store):
    store.record_call('get_runtime_info', {})
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TABLE monitor_settings')
    assert store.monitoring()['mode'] == 'basic'
    assert store.summary()['calls'] == 1


def test_overlapping_calls_union_is_distinct_from_cumulative_and_unknown_task_time(store):
    store.set_monitoring('debug')
    for tool, start, end in [('scan_project', 100, 110), ('get_runtime_info', 101, 102),
                             ('read_task_review_context', 108, 112)]:
        store.record_call(tool, {}, started_at=start, finished_at=end, elapsed_ms=(end-start)*1000)
    data = report_data(store, limit=2)
    assert data['summary']['elapsed_ms'] == 15000
    assert data['timing']['tool_active_wall_ms'] == 12000
    assert data['timing']['observed_window_ms'] == 12000
    assert data['timing']['task_wall_ms'] is None
    assert data['summary']['actual_model_tokens'] is None
    assert data['exported_events'] == 2 and data['omitted_events'] == 1
    assert len(data['tools']) == 3
    assert data['events'][0]['phase'] == 'evidence'


def test_unknown_timings_invalid_clock_and_percentiles(store):
    store.record_call('get_runtime_info', {}, elapsed_ms=2)
    store.set_monitoring('debug')
    store.record_call('get_runtime_info', {}, started_at=200, finished_at=100, elapsed_ms=10)
    store.record_call('get_runtime_info', {}, started_at=float('nan'), finished_at=300, elapsed_ms=99)
    report = report_data(store)
    assert report['timing']['timed_calls'] == 0
    assert report['timing']['tool_active_wall_ms'] is None
    assert report['tools'][0]['p50_ms'] == 10
    assert report['tools'][0]['p95_ms'] == report['tools'][0]['max_ms'] == 99


def test_snapshot_run_filter_and_tampered_records(store):
    for label in ('before', 'after'):
        store.record_call('get_runtime_info', {}, run_label=label)
    assert report_data(store, 'before')['summary']['calls'] == 1
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE events SET run='before' WHERE run='after'")
    report = report_data(store, 'before')
    assert report['summary']['calls'] == 1
    assert report['summary']['invalid_records'] == 1
    assert report['status'] == 'PARTIAL'


def test_report_uses_real_imported_usage_without_assigning_it_to_tools(store, tmp_path):
    from security_runtime.codex_usage import parse_codex_usage
    log = tmp_path / 'usage.jsonl'
    log.write_text(json.dumps({'type': 'thread.started', 'thread_id': 'explicit-fixture'})+'\n'+
                   json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 120,
                               'cached_input_tokens': 80, 'output_tokens': 30,
                               'reasoning_output_tokens': 10}})+'\n', encoding='utf-8')
    parsed = parse_codex_usage(log)
    store.record_host_usage('pilot', parsed)
    store.record_host_usage('pilot', parsed)
    store.record_call('get_runtime_info', {}, run_label='pilot')
    report = report_data(store, 'pilot')
    assert report['summary']['actual_model_tokens']['total_tokens'] == 150
    assert report['summary']['actual_model_tokens_status'] == 'HOST_REPORTED'
    assert report['summary']['host_usage_imports'] == 1
    assert 'NOT_ATTRIBUTABLE' in report['token_scope']
    assert 'actual_model_tokens' not in report['tools'][0]


def test_export_is_readonly_private_bounded_and_never_overwrites(store, tmp_path):
    store.set_monitoring('debug')
    store.record_call('get_runtime_info', {'private': 'NEVER_EXPORT_BODY'}, connection_id='PRIVATE_SESSION',
                      workspace='/PRIVATE/PROJECT', elapsed_ms=35, started_at=100, finished_at=100.035)
    before = store.path.read_bytes()
    report = report_data(store)
    raw = json.dumps(report)
    assert 'NEVER_EXPORT_BODY' not in raw and 'PRIVATE_SESSION' not in raw and 'PRIVATE/PROJECT' not in raw
    assert 'connection_hash' not in raw and 'workspace_hash' not in raw
    path = tmp_path / 'report.html'
    write_report(path, report)
    assert store.path.read_bytes() == before
    assert 'get_runtime_info' in path.read_text(encoding='utf-8')
    with pytest.raises(FileExistsError):
        write_report(path, report)
    with pytest.raises(ValueError):
        report_data(store, limit=0)


def test_report_embedded_data_cannot_break_out_of_script(store, tmp_path):
    data = report_data(store)
    data['summary']['builds'] = [{'version': '</script><img src=x onerror=alert(1)>',
                                 'build_id': None, 'build_status': 'UNKNOWN'}]
    path = tmp_path / 'safe.html'
    write_report(path, data)
    html = path.read_text(encoding='utf-8')
    assert '</script><img' not in html
    assert '\\u003c/script\\u003e' in html
    assert 'connect-src \'none\'' in html
    assert '.innerHTML' not in html


def test_report_rejects_link_output(store, tmp_path):
    target = tmp_path / 'target'
    target.write_text('keep', encoding='utf-8')
    link = tmp_path / 'report.html'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('Symlinks unavailable')
    with pytest.raises((ValueError, OSError)):
        write_report(link, report_data(store))
    assert target.read_text(encoding='utf-8') == 'keep'


def test_wrapper_preserves_errors_and_live_off_switch_during_call(store, monkeypatch):
    from security_runtime import context_cost
    monkeypatch.setattr(context_cost, 'ContextCostStore', lambda: store)
    store.set_monitoring('debug')
    request = SimpleNamespace(params=SimpleNamespace(name='get_runtime_info'))
    response = {'isError': True, 'content': [{'type': 'text', 'text': 'private error'}]}

    async def error(_):
        return response

    assert asyncio.run(observe_response(error, request, connection_id='session')) is response
    assert store.summary()['failed_calls'] == 1
    assert report_data(store)['timing']['timed_calls'] == 1

    async def switched_off(_):
        store.set_monitoring('off')
        return response

    asyncio.run(observe_response(switched_off, request, connection_id='session'))
    assert store.summary()['calls'] == 1


def test_inflight_call_keeps_starting_run_when_user_switches_label(store, monkeypatch):
    from security_runtime import context_cost
    monkeypatch.setattr(context_cost, 'ContextCostStore', lambda: store)
    store.set_monitoring('debug', 'first')
    request = SimpleNamespace(params=SimpleNamespace(name='get_runtime_info'))

    async def switch_run(_):
        store.set_monitoring('debug', 'second')
        return {'status': 'AVAILABLE'}

    asyncio.run(observe_response(switch_run, request, connection_id='session'))
    assert store.summary('first')['calls'] == 1
    assert store.summary('second')['calls'] == 0


def test_cli_monitor_and_html_report(store, monkeypatch, capsys, tmp_path):
    from security_runtime import cli
    monkeypatch.setattr(cli, 'configure_logging', lambda **kwargs: None)
    common = ['--db', str(store.path), '--json']
    assert cli.main(['context-usage', 'monitor', '--mode', 'debug', *common]) == 0
    assert json.loads(capsys.readouterr().out)['effective']['mode'] == 'debug'
    store.record_call('get_runtime_info', {}, run_label='real')
    path = tmp_path / 'calls.html'
    assert cli.main(['context-usage', 'report', '--run', 'real', '--output', str(path), *common]) == 0
    assert json.loads(capsys.readouterr().out)['calls'] == 1
    assert cli.main(['context-usage', 'report', '--output', str(path), *common]) == 2

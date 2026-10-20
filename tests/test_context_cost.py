import json
import ast
from pathlib import Path
import sqlite3
import time

from security_runtime.codex_usage import parse_codex_usage
from security_runtime.context_cost import ContextCostStore


def _store(tmp_path):
    return ContextCostStore(tmp_path / 'private' / 'context-cost.sqlite3')


def _exec(path, counts, *, thread='thread-one'):
    records = ([{'type': 'thread.started', 'thread_id': thread}] if thread else [])
    records += [{'type': 'turn.completed', 'usage': dict(input_tokens=count, cached_input_tokens=0,
                                                       output_tokens=10, reasoning_output_tokens=0)} for count in counts]
    path.write_text(''.join(json.dumps(record) + '\n' for record in records), encoding='utf-8')
    return parse_codex_usage(path)


def test_exact_channels_privacy_and_evidence_repeat(tmp_path):
    store = _store(tmp_path)
    result = {'content': [{'type': 'text', 'text': '秘密'}],
              'structuredContent': {'evidence_id': 'te3-private', 'lines': ['SOURCE SECRET'],
                                    'start_line': 1, 'scanner_run': False}}
    for _ in range(2):
        assert store.record_call('read_task_review_context', result, transport='mcp',
                                 workspace='C:/secret/workspace', connection_id='secret-session',
                                 run_label='before')['status'] == 'RECORDED'
    summary = store.summary('before')
    assert summary['text_bytes'] == 12
    assert summary['source_lines_delivered'] == 2
    assert summary['repeated_evidence_deliveries'] == 1
    assert summary['actual_model_tokens'] is None
    assert summary['measurement'] == 'UTF8_RESPONSE_BYTES_NOT_MODEL_TOKENS'
    raw = store.path.read_bytes()
    for forbidden in (b'SOURCE SECRET', b'secret/workspace', b'secret-session', b'te3-private'):
        assert forbidden not in raw


def test_bytes_comparison_is_distinct_from_actual_tokens(tmp_path):
    store = _store(tmp_path)
    store.record_call('scan_project', {'value': 'x' * 1000}, run_label='before')
    store.record_call('scan_project', {'value': 'x' * 100}, run_label='after')
    report = store.compare('before', 'after')
    assert report['response_byte_reduction_percent'] > 80
    assert report['actual_token_reduction_percent'] is None
    assert report['actual_tokens_comparable'] is False


def test_observer_failure_does_not_raise_and_never_returns_database_content(tmp_path):
    path = tmp_path / 'poison.sqlite3'
    path.write_bytes(b'PRIVATE DATABASE PAYLOAD')
    store = ContextCostStore(path)
    assert store.record_call('scan_project', {})['status'] == 'UNAVAILABLE'
    summary = store.summary()
    assert summary['status'] == 'UNAVAILABLE'
    assert 'PRIVATE DATABASE PAYLOAD' not in json.dumps(summary)


def test_metadata_integrity_tamper_ignored(tmp_path):
    store = _store(tmp_path)
    store.record_call('scan_project', {'scanner_run': True})
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE events SET record=?', (b'{"tool":"PRIVATE SECRET"}',))
    report = store.summary()
    assert report['status'] == 'PARTIAL'
    assert report['invalid_records'] == 1
    assert report['calls'] == 0
    assert 'PRIVATE SECRET' not in json.dumps(report)


def test_retention_and_event_limit(tmp_path, monkeypatch):
    import security_runtime.context_cost as module
    monkeypatch.setattr(module, 'MAX_EVENTS', 2)
    store = _store(tmp_path)
    for _ in range(3):
        store.record_call('scan_project', {})
    assert store.summary()['calls'] == 2
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE events SET at=?', (time.time() - 15 * 86400,))
    store.record_call('scan_project', {})
    assert store.summary()['calls'] == 1


def test_fixed_tool_names_and_run_labels(tmp_path, monkeypatch):
    store = _store(tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_RUN', 'candidate')
    store.record_call('SECRET_TOOL_NAME', {})
    assert store.summary('candidate')['top_tools'][0]['tool'] == 'unknown'
    assert store.record_call('scan_project', {}, run_label='../private')['status'] == 'UNAVAILABLE'
    assert b'SECRET_TOOL_NAME' not in store.path.read_bytes()


def test_exec_import_is_idempotent_and_growing_file_updates_not_adds(tmp_path):
    store = _store(tmp_path)
    path = tmp_path / 'exec.jsonl'
    report = _exec(path, [100])
    assert store.record_host_usage('before', report)['status'] == 'RECORDED'
    assert store.record_host_usage('before', report)['status'] == 'ALREADY_IMPORTED'
    report = _exec(path, [100, 50])
    assert store.record_host_usage('before', report)['status'] == 'RECORDED'
    total = store.summary('before')['actual_model_tokens']
    assert total['input_tokens'] == 150
    assert total['total_tokens'] == 170
    assert store.summary('before')['host_usage_imports'] == 1
    assert store.record_host_usage('after', report)['status'] == 'RUN_LABEL_CONFLICT'


def test_rollout_latest_snapshot_updates_without_double_counting(tmp_path):
    store = _store(tmp_path)
    path = tmp_path / 'rollout.jsonl'
    def report(count):
        records = [{'type': 'session_meta', 'payload': {'id': 'same-private-thread'}},
                   {'type': 'event_msg', 'payload': {'type': 'token_count', 'info': {
                       'total_token_usage': {'input_tokens': count, 'output_tokens': 10}}}}]
        path.write_text(''.join(json.dumps(item) + '\n' for item in records), encoding='utf-8')
        return parse_codex_usage(path)
    store.record_host_usage('after', report(100))
    store.record_host_usage('after', report(200))
    assert store.summary('after')['actual_model_tokens']['total_tokens'] == 210
    # A copied older snapshot has the same host thread id and cannot add usage.
    assert store.record_host_usage('after', report(100))['status'] == 'ALREADY_IMPORTED'


def test_unknown_identity_sources_are_not_silently_aggregated(tmp_path):
    store = _store(tmp_path)
    store.record_host_usage('before', _exec(tmp_path / 'one.jsonl', [100], thread=None))
    store.record_host_usage('before', _exec(tmp_path / 'two.jsonl', [100], thread=None))
    report = store.summary('before')
    assert report['actual_model_tokens'] is None
    assert report['host_usage_warning'] == 'UNVERIFIED_SOURCES_NOT_AGGREGATED'


def test_host_usage_comparison_reports_whole_run_scope(tmp_path):
    store = _store(tmp_path)
    store.record_host_usage('before', _exec(tmp_path / 'one.jsonl', [100], thread='one'))
    store.record_host_usage('after', _exec(tmp_path / 'two.jsonl', [50], thread='two'))
    report = store.compare('before', 'after')
    assert report['actual_token_reduction_percent'] == 45.45
    assert report['comparison_note'] == 'HOST_USAGE_COVERS_WHOLE_RUN_NOT_RUNTIME_ATTRIBUTION'


def test_resume_exec_different_source_same_thread_is_unknown_overlap(tmp_path):
    store = _store(tmp_path)
    store.record_host_usage('after', _exec(tmp_path / 'initial.jsonl', [100]))
    status = store.record_host_usage('after', _exec(tmp_path / 'resumed.jsonl', [200]))
    assert status['status'] == 'SOURCE_OVERLAP_UNVERIFIABLE'
    summary = store.summary('after')
    assert summary['actual_model_tokens']['input_tokens'] == 100
    assert summary['actual_model_tokens_status'] == 'HOST_REPORTED_PARTIAL'
    assert summary['host_usage_complete'] is False


def test_invalid_usage_warnings_prevent_false_comparison(tmp_path):
    store = _store(tmp_path)
    first = _exec(tmp_path / 'one.jsonl', [100], thread='one')
    second = _exec(tmp_path / 'two.jsonl', [50], thread='two')
    second['warnings'] = ['INVALID_USAGE_IGNORED']
    store.record_host_usage('before', first)
    store.record_host_usage('after', second)
    summary = store.summary('after')
    assert summary['actual_model_tokens_status'] == 'HOST_REPORTED_PARTIAL'
    assert summary['host_usage_warnings'] == ['INVALID_USAGE_IGNORED']
    assert store.compare('before', 'after')['actual_tokens_comparable'] is False
    assert store.compare('before', 'after')['actual_token_reduction_percent'] is None


def test_common_observer_does_not_import_codex_parser():
    import security_runtime.context_cost as module
    tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert 'token_usage' in imported
    assert 'codex_usage' not in imported

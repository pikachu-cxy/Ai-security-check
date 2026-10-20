import json

from security_runtime import cli
from security_runtime.context_cost import ContextCostStore


def test_cli_status_and_comparison_keep_tokens_unknown_without_host_data(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'configure_logging', lambda **kwargs: None)
    path = tmp_path / 'metrics.sqlite3'
    store = ContextCostStore(path)
    store.record_call('scan_project', {'result': 'x'*1000}, run_label='before')
    store.record_call('scan_project', {'result': 'x'*100}, run_label='after')
    assert cli.main(['context-usage', 'status', '--run', 'after', '--db', str(path), '--json']) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary['calls'] == 1
    assert summary['actual_model_tokens'] is None
    assert cli.main(['context-usage', 'compare', '--baseline', 'before', '--candidate', 'after',
                     '--db', str(path), '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['response_byte_reduction_percent'] > 80
    assert report['actual_token_reduction_percent'] is None


def test_cli_explicit_import_is_idempotent_and_unknown_usage_is_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'configure_logging', lambda **kwargs: None)
    path, log = tmp_path / 'metrics.sqlite3', tmp_path / 'codex.jsonl'
    log.write_text(json.dumps({'type': 'thread.started', 'thread_id': 'synthetic-thread'})+'\n'+
                   json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 100,
                       'cached_input_tokens': 80, 'output_tokens': 10}})+'\n', encoding='utf-8')
    args = ['context-usage', 'import-codex', '--path', str(log), '--run', 'after', '--db', str(path), '--json']
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'RECORDED'
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'ALREADY_IMPORTED'
    assert ContextCostStore(path).summary('after')['actual_model_tokens']['total_tokens'] == 110
    log.write_text('{"type":"thread.started","thread_id":"no-usage"}\n', encoding='utf-8')
    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'UNKNOWN'

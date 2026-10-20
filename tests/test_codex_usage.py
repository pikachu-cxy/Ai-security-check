import json

import pytest

from security_runtime.codex_usage import parse_codex_usage


def _write(path, records):
    path.write_text(''.join(json.dumps(record) + '\n' for record in records), encoding='utf-8')
    return path


def _usage(input=100, cached=60, output=20, reasoning=5):
    return dict(input_tokens=input, cached_input_tokens=cached,
                output_tokens=output, reasoning_output_tokens=reasoning)


def test_exec_usage_subsets_are_not_added_twice(tmp_path):
    path = _write(tmp_path / 'exec.jsonl', [
        {'type': 'thread.started', 'thread_id': 'private-thread'},
        {'type': 'item.completed', 'item': {'text': 'SECRET SOURCE BODY'}},
        {'type': 'turn.completed', 'usage': _usage()},
        {'type': 'turn.completed', 'usage': _usage(30, 10, 5, 0)},
    ])
    report = parse_codex_usage(path)
    assert report['usage'] == dict(input_tokens=130, cached_input_tokens=70,
                                   output_tokens=25, reasoning_output_tokens=5, total_tokens=155)
    assert report['observed_turns'] == 2
    assert 'SECRET' not in json.dumps(report)
    assert str(path) not in json.dumps(report)
    assert 'private-thread' not in json.dumps(report)


def test_rollout_uses_last_cumulative_snapshot_per_thread(tmp_path):
    def snapshot(count):
        return {'type': 'event_msg', 'payload': {'type': 'token_count', 'info': {
            'total_token_usage': _usage(count, 0, 10, 0),
            'last_token_usage': _usage(900, 0, 100, 0)}}}
    path = _write(tmp_path / 'rollout.jsonl', [
        {'type': 'session_meta', 'payload': {'id': 'thread-a', 'cwd': 'secret-workspace'}},
        snapshot(100), snapshot(200), snapshot(150),
        {'type': 'session_meta', 'payload': {'id': 'thread-b'}}, snapshot(20),
    ])
    report = parse_codex_usage(path)
    assert report['usage']['input_tokens'] == 170
    assert report['usage']['total_tokens'] == 190
    assert report['cumulative_snapshots'] == 4
    assert len(report['streams']) == 2


def test_mixed_format_does_not_count_same_thread_twice(tmp_path):
    path = _write(tmp_path / 'mixed.jsonl', [
        {'type': 'thread.started', 'thread_id': 'a'},
        {'type': 'turn.completed', 'usage': _usage()},
        {'type': 'event_msg', 'payload': {'type': 'token_count', 'info': {'total_token_usage': _usage()}}},
    ])
    report = parse_codex_usage(path)
    assert report['usage']['total_tokens'] == 120
    assert report['format'] == 'mixed'


def test_unknown_or_invalid_usage_never_estimates_tokens(tmp_path):
    path = _write(tmp_path / 'none.jsonl', [
        {'type': 'turn.completed', 'usage': _usage(-1)},
        {'type': 'item.completed', 'text': 'x' * 1000},
    ])
    report = parse_codex_usage(path)
    assert report['status'] == 'UNKNOWN'
    assert report['usage'] is None
    assert report['warnings'] == ['INVALID_USAGE_IGNORED']


def test_import_budget_and_missing_file_error_have_no_path(tmp_path, monkeypatch):
    import security_runtime.codex_usage as module
    monkeypatch.setattr(module, 'MAX_LINE_BYTES', 30)
    path = tmp_path / 'sensitive-name.jsonl'
    path.write_text('x' * 31, encoding='utf-8')
    with pytest.raises(ValueError, match='^CODEX_USAGE_INPUT_UNAVAILABLE_OR_OVER_BUDGET$'):
        parse_codex_usage(path)
    with pytest.raises(ValueError) as error:
        parse_codex_usage(tmp_path / 'missing-private-name')
    assert str(tmp_path) not in str(error.value)


def test_unchanged_file_digest_stable_but_append_changes_report(tmp_path):
    path = _write(tmp_path / 'exec.jsonl', [{'type': 'turn.completed', 'usage': _usage()}])
    original = parse_codex_usage(path)
    assert parse_codex_usage(path) == original
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'type': 'turn.completed', 'usage': _usage()}) + '\n')
    appended = parse_codex_usage(path)
    assert appended['import_key'] != original['import_key']
    assert appended['streams'][0]['identity'] == original['streams'][0]['identity']
    assert appended['usage']['total_tokens'] == 240

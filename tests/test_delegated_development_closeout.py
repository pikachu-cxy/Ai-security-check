"""Parent Stop adopts only host-proven child edits, without another scan path."""
import hashlib
import json
import sqlite3
import uuid

import pytest

from test_development_check import check, OWNER, execute
from test_user_config_stop import config
from security_runtime.codex_turn_scope import resolve_child_turns
from security_runtime.development_check import record_hook
from security_runtime.development_stop import fallback


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def host_records(tmp_path, monkeypatch, root):
    home = tmp_path/'codex'
    (home/'sessions').mkdir(parents=True)
    monkeypatch.setenv('SECURITY_RUNTIME_CODEX_HOME', str(home))
    session, parent, child, turn = (str(uuid.uuid4()) for _ in range(4))
    transcript = home/'sessions'/('rollout-'+child+'.jsonl')
    payload = dict(type='task_started', turn_id=turn, root_turn_id=parent,
                   turn_attribution=dict(turn_id=turn, root_turn_id=parent, parent_turn_id=parent))
    transcript.write_text(json.dumps(dict(type='event_msg', payload=payload))+'\n')
    with sqlite3.connect(home/'state_5.sqlite') as db:
        db.execute('CREATE TABLE threads(id TEXT PRIMARY KEY, cwd TEXT, rollout_path TEXT, created_at INTEGER)')
        db.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT, child_thread_id TEXT PRIMARY KEY)')
        db.execute('INSERT INTO threads VALUES (?,?,?,1)', (child,str(root),str(transcript)))
        db.execute('INSERT INTO thread_spawn_edges VALUES (?,?)', (session,child))
    return home, session, parent, child, turn, transcript


def test_native_child_ancestry_is_exact_to_parent_turn_workspace_and_chat(tmp_path, monkeypatch):
    root = tmp_path/'project'; root.mkdir()
    home, session, parent, child, turn, transcript = host_records(tmp_path, monkeypatch, root)
    expected = frozenset({digest(turn)})
    assert resolve_child_turns(root, session, parent, expected) == expected
    assert not resolve_child_turns(root, str(uuid.uuid4()), parent, expected)
    assert not resolve_child_turns(root, session, str(uuid.uuid4()), expected)
    assert not resolve_child_turns(tmp_path/'other-worktree', session, parent, expected)
    transcript.write_text(json.dumps(dict(type='event_msg', payload=dict(
        type='task_started', turn_id=turn, root_turn_id=parent)))+'\n')
    assert not resolve_child_turns(root, session, parent, expected)


def test_missing_or_untrusted_host_records_grant_no_link(tmp_path, monkeypatch):
    root = tmp_path/'project'; root.mkdir()
    home, session, parent, child, turn, transcript = host_records(tmp_path, monkeypatch, root)
    expected = {digest(turn)}
    transcript.unlink()
    outside = tmp_path/'outside.jsonl'; outside.write_text('{}\n')
    transcript.symlink_to(outside)
    assert not resolve_child_turns(root, session, parent, expected)
    (home/'state_5.sqlite').unlink()
    assert not resolve_child_turns(root, session, parent, expected)
    assert not resolve_child_turns(root, 'unresolved-session', parent, expected)


def test_long_child_keeps_attribution_without_full_transcript_read(tmp_path, monkeypatch):
    root = tmp_path/'project'; root.mkdir()
    _, session, parent, _, turn, transcript = host_records(tmp_path, monkeypatch, root)
    with transcript.open('a') as stream:
        stream.write(json.dumps(['task_started'])+'\n')
        stream.write(json.dumps({'type': 'irrelevant', 'data': 'x' * 1_100_000})+'\n')
    assert resolve_child_turns(root, session, parent, {digest(turn)}) == {digest(turn)}


def test_parent_stop_scans_delegated_files_once_and_reuses_saved_batch(check, config, monkeypatch):
    root, service, _, counters = check
    config.write_text('[agent]\nreview_scanner_findings=false\n')
    home, session, parent, child, turn, transcript = host_records(root.parent, monkeypatch, root)
    first = record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id=turn)
    other = str(uuid.uuid4())
    with transcript.open('a') as stream:
        stream.write(json.dumps(dict(type='event_msg', payload=dict(type='task_started', turn_id=other,
            root_turn_id=parent, turn_attribution=dict(turn_id=other, root_turn_id=parent))))+'\n')
    record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id=other, event_id='second')
    dispatched = []
    def closeout(_service, _root, row, *_args):
        dispatched.append(row['check_ref'])
        execute(check, monkeypatch)
        return {'status':'RESULTS_READY'}
    monkeypatch.setattr('security_runtime.development_stop.native_closeout', closeout)
    result = fallback(service.hooks, root, OWNER, service=service, turn_id=parent, session_id=session,
                      automatic=True, child_turn_resolver=resolve_child_turns)
    assert result['status'] == 'RESULTS_READY'
    row = service.store(root).load(first['check_ref'])
    assert row['dirty_seq'] == row['scanned_seq'] and row['scan_id']
    assert row['stop_activity']['turn'] == digest(parent)
    assert set(row['stop_activity']['executor_turns']) == {digest(turn),digest(other)}
    assert row['stop_activity_previous'] == []
    assert fallback(service.hooks, root, OWNER, service=service, turn_id=parent, session_id=session,
                    automatic=True, child_turn_resolver=resolve_child_turns) is None
    assert counters['calls'] == 1 and dispatched == [first['check_ref']]


def test_matching_normal_stop_does_not_consult_host_database(check, config, monkeypatch):
    root, service, _, _ = check
    record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='main')
    def forbidden(*args):
        pytest.fail('Normal Stop must not read host history')
    monkeypatch.setattr('security_runtime.development_stop.native_closeout', lambda *a: {'status':'CALLED'})
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='main', automatic=True,
                    child_turn_resolver=forbidden)['status'] == 'CALLED'


def test_partial_ancestry_cannot_adopt_an_unrelated_pending_turn(check, config, monkeypatch):
    root, service, _, counters = check
    first = record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='old-unrelated')
    record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='child', event_id='child-edit')
    before = service.store(root).load(first['check_ref'])
    assert fallback(service.hooks, root, OWNER, service=service, turn_id='parent', automatic=True,
                    child_turn_resolver=lambda *a: {digest('child')}) is None
    assert service.store(root).load(first['check_ref']) == before
    assert counters['calls'] == 0

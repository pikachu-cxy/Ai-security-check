import asyncio
import json
import pytest

from security_runtime.connection_lifecycle import Lifecycle
from test_development_check import check
from test_user_config_stop import config


def test_calls_are_memory_only_and_exceptions_are_redacted(tmp_path, monkeypatch):
    tracker = Lifecycle(tmp_path)
    tracker.save()
    initial = tracker.path.read_bytes()
    async def call(name, args):
        assert args['secret'] == 'not-for-logs'
        return object()
    asyncio.run(tracker.call(call, 'handle_stop_event', {'secret': 'not-for-logs'}))
    assert tracker.path.read_bytes() == initial
    tracker.finish('UNHANDLED_EXCEPTION', 1, ExceptionGroup('secret', [ValueError('password')]))
    value = json.loads(tracker.path.read_text())
    assert value['last_completed']['tool'] == 'handle_stop_event'
    assert value['active_requests'] == 0
    assert value['exception_types'] == ['ExceptionGroup', 'ValueError']
    assert not any(s in tracker.path.read_text() for s in ('secret', 'password', 'not-for-logs'))


def test_stdio_normal_exit_is_not_reported_as_crash(tmp_path, monkeypatch):
    import security_runtime.connection_lifecycle as module
    tracker = Lifecycle(tmp_path)
    monkeypatch.setattr(module, 'Lifecycle', lambda: tracker)
    module.run(lambda: None)
    assert json.loads(tracker.path.read_text())['reason'] == 'STDIO_ENDED'
    assert module.CURRENT is None


def test_guard_same_owner_once_without_scanning(check, config, tmp_path, monkeypatch):
    from security_runtime.connection_guard import check as guard_check
    from security_runtime.hook_state import identity
    from security_runtime.tasks.ownership import session_owner
    from security_runtime.development_check import record_hook, owner_key
    root, service, _, counters = check
    owner = session_owner('codex', 'guard-owner')
    service.owner = owner
    directory = tmp_path / 'state/global-workspaces' / identity(str(root)) / 'hooks'
    directory.mkdir(parents=True)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    guard = lambda event: guard_check(event, hooks=service.hooks)
    event = dict(hook_event_name='UserPromptSubmit', cwd=str(root), session_id='guard-owner')
    assert guard(event) == {}
    record_hook(service.hooks, root, owner, ['app.ts'], turn_id='old-edit')
    store = service.store(root)
    ref = store.read('focus:' + owner_key(owner))['check_ref']
    before = store.load(ref)
    assert guard(dict(event, session_id='other-owner')) == {}
    result = guard(event)
    assert ref in result['hookSpecificOutput']['additionalContext']
    assert '此前开发' in result['systemMessage']
    assert guard(event) == {}
    after = store.load(ref)
    assert (before['dirty_seq'], before['scanned_seq'], before['finish_requested']) == (
        after['dirty_seq'], after['scanned_seq'], after['finish_requested'])
    assert counters['calls'] == 0


@pytest.mark.parametrize('event', [{}, {'hook_event_name': 'Stop'},
    dict(hook_event_name='UserPromptSubmit', cwd='relative', session_id='s')])
def test_guard_ignores_unusable_claims(event):
    from security_runtime.connection_guard import check
    assert check(event) == {}

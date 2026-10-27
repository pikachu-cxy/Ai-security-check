"""Short references preserve original owners; validation is always read-only."""
import sqlite3

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import issue_session_ref, verify_session_ref, session_owner, SESSION_TTL
from security_runtime.tasks.session_handles import issue_session_handle, verify_session_handle, SessionHandleError


@pytest.fixture
def route(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    return root, HookStateStore(tmp_path/'private')


def files(root):
    return {p:(p.read_bytes(), p.stat().st_mtime_ns) for p in root.parent.rglob('*') if p.is_file()}


def test_handle_reuses_exact_owner_and_legacy_reference_remains_valid(route):
    root, hooks = route
    old = issue_session_ref(hooks, root, 'codex', 'chat', now=1000)
    token = issue_session_ref(hooks, root, 'codex', 'chat', now=1000, compact=True)
    assert len(token) == 36 and token.startswith('sh1-')
    assert issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:1001) == token
    before = files(root)
    assert verify_session_ref(hooks, root, token, now=1002) == session_owner('codex', 'chat')
    assert verify_session_ref(hooks, root, old, now=1002) == session_owner('codex', 'chat')
    assert files(root) == before


def test_unknown_changed_foreign_and_expired_handles_never_create_or_rebind(route):
    root, hooks = route
    token = issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:1000)
    other = root.parent/'other'
    other.mkdir()
    changed = token[:-1]+('0' if token[-1] != '0' else '1')
    before = files(root)
    for workspace, value, instant, host in [
        (root, changed, 1001, None), (other, token, 1001, None),
        (root, token, 1000+SESSION_TTL, None), (root, token, 999, None),
        (root, token, 1001, 'cursor'),
    ]:
        with pytest.raises(SessionHandleError):
            verify_session_handle(hooks, workspace, value, now=instant, host=host)
    assert files(root) == before and not hooks.workspace_directory(other).exists()


def test_refresh_keeps_previous_handle_and_other_chat_owner(route):
    root, hooks = route
    old = issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:1000)
    foreign = issue_session_handle(hooks, root, 'codex', 'other-chat', now=lambda:1000)
    now = 1001+SESSION_TTL/2
    new = issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:now)
    assert old != new != foreign
    for token in (old, new):
        assert verify_session_ref(hooks, root, token, now=now) == session_owner('codex', 'chat')
    assert verify_session_ref(hooks, root, foreign, now=now) == session_owner('codex', 'other-chat')


def test_tampered_signed_handle_state_is_rejected(route):
    root, hooks = route
    token = issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:1000)
    database = hooks.workspace_directory(root)/'session-routing.db'
    with sqlite3.connect(database) as db:
        db.execute("UPDATE records SET mac=? WHERE key LIKE 'handle:%'", ('0'*64,))
    before = files(root)
    with pytest.raises(ValueError):
        verify_session_ref(hooks, root, token, now=1001)
    assert files(root) == before


def test_handle_cannot_bypass_key_hardlink_guard(route):
    import os
    root, hooks = route
    token = issue_session_handle(hooks, root, 'codex', 'chat', now=lambda:1000)
    key = hooks.workspace_directory(root)/'snapshot.key'
    alias = root.parent/'key-alias'
    os.link(key, alias)
    before = files(root)
    with pytest.raises(SessionHandleError):
        verify_session_handle(hooks, root, token, now=1001)
    assert files(root) == before

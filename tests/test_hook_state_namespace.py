"""Shared Hook directories never classify ledger facts as host sessions."""
import copy
import json
import os
from pathlib import Path

import pytest

from security_runtime.closeout_state import digest
from security_runtime.hook_state import atomic_bytes, hook_session_paths, identity
from security_runtime.risk_closure import RiskClosureService
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from test_remediation import setup  # noqa: F401
from test_hook_runtime import repo  # noqa: F401
from test_confirmation_recovery import record, refresh, assert_no_grant

pytestmark = pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)


def legacy_stores(root, hooks):
    directory = hooks.workspace_directory(root)
    key = hooks.key(root)
    ledger = directory / 'task-risk-ledger.json'
    closure = directory / 'closures.state'
    atomic_bytes(ledger, json.dumps(dict(contract='task-risk-ledger-v1',
        workspace=str(root), rows={}, mac=digest(key, {}))).encode())
    atomic_bytes(closure, json.dumps(dict(records={}, mac=digest(key, {}))).encode())
    return ledger, closure


@pytest.mark.parametrize('format', ['legacy', 'fenced'])
def test_confirmation_recovery_ignores_ledger_namespace_without_migrating_it(setup, format):
    root, _, _, service, _, _ = setup
    ledger, closure = legacy_stores(root, service.hooks)
    if format == 'fenced':
        with service.hooks.lock(root) as acquired:
            assert acquired
            authority = TaskRiskLedger(service.hooks, root)
            authority.save(authority.read())
            # Exercise the real product closure fence, with no new proof.
            closure_authority = RiskClosureService(service.hooks)._authority(root)
            from security_runtime.private_authority import revision
            value = closure_authority.read()
            closure_authority.save(value, revision(value))
        assert ledger.is_dir() and closure.is_dir()
        assert list(ledger.iterdir()) and list(closure.iterdir())
    protected = {str(p): p.read_bytes() for p in ledger.parent.rglob('*')
                 if p.is_file() and p.suffix != '.json'}
    if format == 'legacy':
        protected[str(ledger)] = ledger.read_bytes()
    before = record(setup)
    output = refresh(setup)
    assert output['status'] == 'PENDING_CONFIRMATION'
    assert output['issues_edit_grant'] is False
    assert record(setup)['episode_id'] == before['episode_id']
    assert_no_grant(setup, output)
    assert all(Path(name).read_bytes() == data for name, data in protected.items())
    assert ledger.is_file() == (format == 'legacy')


def test_session_retention_preserves_old_ledger_closure_and_unknown_names(setup, monkeypatch):
    root, _, _, service, _, _ = setup
    hooks = service.hooks
    path = hooks.path(root, 'codex', 'session')
    current, corrupt = hooks.load(path)
    assert current and not corrupt
    ledger, closure = legacy_stores(root, hooks)
    unknown = path.parent / 'user-notes.json'
    unknown.write_text('private unrelated metadata')
    protected = {p: p.read_bytes() for p in (ledger, closure, unknown)}
    for p in protected:
        os.utime(p, (1, 1))
    import security_runtime.hook_state as module
    monkeypatch.setattr(module, 'MAX_SESSIONS', 2)
    with hooks.lock(root) as acquired:
        assert acquired
        for index in range(3):
            session = 'retention-' + str(index)
            value = copy.deepcopy(current)
            value['session_id'] = identity(session)
            hooks.save(hooks.path(root, 'codex', session), value)
    assert len(hook_session_paths(path.parent)) == 2
    assert all(p.read_bytes() == data for p, data in protected.items())
    assert TaskRiskLedger(hooks, root).read() == {}
    assert RiskClosureService(hooks)._read(root) == {}


def test_corrupt_real_hook_namespace_still_rejects_recovery(setup):
    root, _, _, service, _, _ = setup
    before = record(setup)
    path = service.hooks.path(root, 'codex', 'other-session')
    path.write_text('{bad-json')
    output = refresh(setup)
    assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_HOOK_STATE_INVALID'
    assert record(setup) == before
    assert_no_grant(setup, output)


def test_valid_hook_copied_to_another_namespace_is_not_current_proof(setup):
    root, _, _, service, _, _ = setup
    before = record(setup)
    path = service.hooks.path(root, 'codex', 'session')
    other = service.hooks.path(root, 'codex', 'other-session')
    other.write_bytes(path.read_bytes())
    output = refresh(setup)
    assert output['diagnostic_reason'] == 'CONFIRMATION_RECOVERY_HOOK_SCAN_NOT_CURRENT'
    assert record(setup) == before
    assert_no_grant(setup, output)

"""Public diagnostic preflight has no admission or routing side effects."""
import asyncio
from types import SimpleNamespace

import pytest

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import workspace_state
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.ownership import issue_session_ref


@pytest.fixture
def context(tmp_path, monkeypatch):
    root, home = tmp_path/'project', tmp_path/'codex-home'
    root.mkdir()
    (root/'pyproject.toml').write_text('[project]\nname="fixture"\n')
    home.mkdir()
    monkeypatch.setenv('SECURITY_RUNTIME_CODEX_HOME', str(home))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'runtime'))
    pool = GlobalWorkspaces(base=tmp_path/'routing', integration=SimpleNamespace(
        home=home, configuration_status=lambda: {'overall': 'CONFIGURED'},
        inspect_project=lambda path: []))
    for name in ('admit', 'bootstrap'):
        monkeypatch.setattr(pool, name, lambda *a, **kw: pytest.fail('diagnostic cannot admit or bootstrap'))
    server = create_global_server(workspaces=pool)
    try:
        yield root, home, pool, server
    finally:
        pool.close()


def query(server, root, **args):
    return asyncio.run(server.call_tool('get_workspace_binding_status',
        dict(workspace_path=str(root), **args))).structuredContent


def test_unregistered_path_and_denied_home_diagnostics_create_no_state(context):
    root, home, pool, server = context
    before = list(root.parent.rglob('*'))
    for _ in range(2):
        good = query(server, root)
        assert good['path_status'] == 'ALLOWED' and good['resolved_workspace'] == str(root)
        assert good['session_binding_status'] == 'UNKNOWN'
        assert good['configuration_status'] == 'VALIDATED'
        assert good['admission_status'] == 'ELIGIBLE'
        assert not good['routing_binding_confirmed']
        bad = query(server, home)
        assert bad['path_status'] == 'REJECTED' and bad['resolved_workspace'] is None
        assert bad['reason_code'] == 'WORKSPACE_OUTSIDE_ALLOWED_ROOT'
    assert list(root.parent.rglob('*')) == before
    assert not pool.sessions and not pool.children and not pool.jobs


def test_signed_routing_match_completes_without_extra_host_checks(context):
    root, _, pool, server = context
    hooks = HookStateStore(workspace_state(root, pool.base)/'hooks')
    token = issue_session_ref(hooks, root, 'codex', 'session-a')
    pool.bind_session('session-a', root)
    before = {p:(p.read_bytes(), p.stat().st_mtime_ns) for p in root.parent.rglob('*') if p.is_file()}
    out = query(server, root, session_ref=token)
    assert out['session_binding_status'] == 'MATCH'
    assert out['identity_evidence'] == 'SIGNED_ROUTING_CONTEXT'
    assert out['routing_binding_confirmed']
    assert out['session_context_status'] == 'VERIFIED'
    assert out['reason_code'] is None and out['next_action'] is None
    assert not {'current_host_verified', 'execution_root_match', 'binding_confirmed',
                'task_target_match', 'binding_generation'} & out.keys()
    assert before == {p:(p.read_bytes(), p.stat().st_mtime_ns) for p in root.parent.rglob('*') if p.is_file()}


def test_invalid_credential_neither_discloses_nor_changes_routing(context):
    root, _, pool, server = context
    pool.bind_session('session-other', root)
    before = dict(pool.sessions)
    out = query(server, root, session_ref='so1-invalid.invalid')
    assert out['session_binding_status'] == 'UNKNOWN' and out['registered_workspace'] is None
    assert out['reason_code'] == 'SESSION_CONTEXT_UNVERIFIED'
    assert pool.sessions == before and not pool.children


@pytest.mark.parametrize('token', [None, 'so1-invalid.invalid'])
def test_unverified_query_never_reads_existing_foreign_registration(context, token):
    root, _, pool, server = context

    class UnreadableSessions(dict):
        def get(self, *args, **kwargs):
            pytest.fail('unverified query cannot look up existing sessions')

        def __iter__(self):
            pytest.fail('unverified query cannot select a recent session')

    pool.sessions = UnreadableSessions({'foreign-session': root.parent/'private-project'})
    result = query(server, root, session_ref=token)
    assert result['session_binding_status'] == 'UNKNOWN'
    assert result['registered_workspace'] is None and not result['routing_binding_confirmed']


@pytest.mark.parametrize('failure,reason', [
    ('global', 'GLOBAL_CONFIGURATION_NOT_READY'),
    ('project', 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR'),
    ('directory', 'WORKSPACE_OUTSIDE_ALLOWED_ROOT'),
])
def test_preflight_reports_second_stage_rejection_before_missing_context(context, failure, reason):
    root, _, pool, server = context
    before = list(root.parent.rglob('*'))
    if failure == 'global':
        pool.integration.configuration_status = lambda: {'overall': 'DEGRADED'}
    elif failure == 'project':
        pool.integration.inspect_project = lambda path: [{'related': True}]
    else:
        def reject(path):
            raise ValueError('RUNTIME_STATE_IS_NOT_A_WORKSPACE')
        pool.integration.inspect_project = reject
    out = query(server, root)
    assert out['path_status'] == 'ALLOWED'
    assert out['configuration_status'] == out['admission_status'] == 'REJECTED'
    assert out['resolution_stage'] == 'VALIDATING_CONFIGURATION'
    assert out['reason_code'] == reason
    assert out['next_action'] == 'CHECK_INTEGRATION_CONFIGURATION'
    assert not out['routing_binding_confirmed'] and not out['scanner_run']
    assert not pool.sessions and not pool.children and not pool.jobs
    assert list(root.parent.rglob('*')) == before


def test_other_root_token_cannot_confirm_or_disclose_routing(context):
    root, _, pool, server = context
    other = root.parent/'other-project'
    other.mkdir()
    hooks = HookStateStore(workspace_state(other, pool.base)/'hooks')
    token = issue_session_ref(hooks, other, 'codex', 'other-session')
    pool.bind_session('other-session', other)
    out = query(server, root, session_ref=token)
    assert out['session_context_status'] == 'UNVERIFIED'
    assert out['registered_workspace'] is None and not out['routing_binding_confirmed']

"""Real linked worktrees traverse both admission gates and native routing."""
import asyncio
import subprocess

import pytest

from security_runtime.global_mcp import create_global_server
from security_runtime.global_workspace import resolve_workspace
from test_global_integration import installed, projects, pool_fixture, structured


def worktree(origin, home, name):
    target = home/'worktrees'/name/'project'
    target.parent.mkdir(parents=True)
    subprocess.run(['git', '-C', str(origin), 'worktree', 'add', '--detach',
                    str(target), 'HEAD'], check=True, capture_output=True)
    return target


def test_three_worktrees_pass_config_gate_and_have_independent_session_routes(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    roots = [worktree(projects[0], installed.home, name) for name in ('a', 'b', 'c')]
    server = create_global_server(workspaces=pool)

    def call(name, **args):
        return structured(asyncio.run(server.call_tool(name, args)))

    try:
        tokens = []
        for index, root in enumerate(roots):
            pool.validate_layers(root/'src')
            assert installed.project_layers(root/'src') == [root, root/'src']
            out = call('get_workspace_binding_status', workspace_path=str(root))
            assert out['configuration_status'] == 'VALIDATED'
            assert out['admission_status'] == 'ELIGIBLE'
            assert out['reason_code'] == 'SESSION_CONTEXT_REQUIRED'
            start = call('handle_readiness_event', event='SessionStart',
                         workspace_path=str(root), session_id=f'acceptance-{index}',
                         permission_mode='default')
            assert start['host_claim_status'] == 'VALID'
            assert start['session_claim_match'] and start['session_binding_present']
            tokens.append(start['task_session_ref'])
            out = call('get_workspace_binding_status', workspace_path=str(root),
                       session_ref=tokens[-1])
            assert out['session_binding_status'] == 'MATCH'
            assert out['registered_workspace'] == str(root)
            assert out['routing_binding_confirmed']
            assert out['reason_code'] is None and out['next_action'] is None
            # Global installation status must use the same narrow worktree policy.
            assert installed.execute('doctor', root)['overall'] == 'CONFIGURED'
        assert len(set(tokens)) == 3
        assert len(pool.sessions) == len(pool.children) == 3
        for index, root in enumerate(roots):
            out = call('get_workspace_binding_status', workspace_path=str(root),
                       session_ref=tokens[(index+1) % 3])
            assert out['session_context_status'] == 'UNVERIFIED'
            assert out['registered_workspace'] is None
            assert not out['routing_binding_confirmed']
    finally:
        pool.close()


@pytest.mark.parametrize('relative', ['', 'worktrees', 'logs', 'worktrees/fake/project'])
def test_config_gate_keeps_codex_internal_and_fake_directories_protected(installed, projects, relative):
    installed.execute('setup')
    target = installed.home/relative
    target.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError):
        installed.project_layers(target)


def test_worktree_does_not_override_integration_state_exclusion(installed, projects):
    installed.execute('setup')
    root = worktree(projects[0], installed.home, 'protected')
    installed.store.directory = root
    with pytest.raises(ValueError, match='RUNTIME_STATE_IS_NOT_A_WORKSPACE'):
        installed.project_layers(root)

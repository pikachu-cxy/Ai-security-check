"""Synthetic official-shaped Pre/Post pairs; not a native desktop acceptance."""
import asyncio
import copy
import json

import pytest

from security_runtime import development_file_watch as watching
from security_runtime.codex_host_claims import CodexClaimGuard, diagnostics
from security_runtime.codex_integration import product_hooks
from security_runtime.development_check import DevelopmentCheckService
from security_runtime.global_mcp import create_global_server
from security_runtime.mcp_server import create_server
from security_runtime.tasks.ownership import session_owner
from test_codex_host_claims import claims
from test_codex_mcp_hook import binding
from test_global_integration import installed, projects, pool_fixture, structured, complete_runtime
from test_hook_runtime import coordinator


def call(server, tool, args):
    return structured(asyncio.run(server.call_tool(tool, args)))


def test_pre_post_pair_shares_binding_and_budget_but_replay_is_rejected():
    guard = CodexClaimGuard(limit=1)
    before = dict(claims('/project'), event='PreToolUse')
    after = dict(before, event='PostToolUse')
    for args in (before, after):
        assert guard.accept(args,'/project',diagnostics(args,args['event'])) is None
    for args in (before, after, dict(after,session_id='other'),dict(after,turn_id='other')):
        assert guard.accept(args,'/project',diagnostics(args,args['event'])) == 'TOOL_USE_CLAIM_REPLAYED'
    fresh = dict(before,tool_use_id='other')
    assert guard.accept(fresh,'/project',diagnostics(fresh,'PreToolUse')) == 'HOST_CLAIM_BUDGET_EXCEEDED'


@pytest.mark.parametrize('global_mode',[False, True])
def test_pre_ready_before_script_post_and_finish_collect_exact_paths(installed, projects, tmp_path, monkeypatch, global_mode):
    root = projects[0]
    runtime = complete_runtime()
    core = coordinator(tmp_path/'core',runtime,cooldown_ms=0)
    pool = None
    if global_mode:
        def child(root,directory,bound):
            return create_server(runtime,hook_coordinator=core,workspace_binding=bound,global_mode=False), core
        pool = pool_fixture(installed,tmp_path,child)
        server = create_global_server(workspaces=pool)
        monkeypatch.setattr(pool,'bootstrap',lambda *_a,**_k: pytest.fail('Pre/Post cannot create a baseline'))
    else:
        server = create_server(runtime,hook_coordinator=core,workspace_binding=binding(root),global_mode=False)
    try:
        args = dict(claims(root),event='PreToolUse')
        no_edit = call(server,'handle_before_hook_event',args)
        assert no_edit['status'] == 'NOT_STARTED' and 'check_ref' not in no_edit
        assert not runtime.calls
        # An opaque script with no path hint still registers before it writes.
        args = dict(args,tool_use_id='script',tool_input={'command':'python opaque_script.py'})
        started = call(server,'handle_before_hook_event',args)
        assert started['host_claim_status'] == 'VALID' and started['file_watch']['status'] == 'ACTIVE', started
        ref = started['check_ref']
        (root/'shell-created.py').write_text('value = 1')
        after = call(server,'handle_hook_event',dict(args,event='PostToolUse'))
        assert after['host_claim_status'] == 'VALID' and not after['scanner_run'], after
        assert not runtime.calls
        service = DevelopmentCheckService(None,core.store,owner=session_owner('codex','s'),
            scan_path_provider=tmp_path/'scan.db',launcher=lambda *_: None)
        finished = service.finish(root,ref)
        assert finished['scope']['paths'] == ['shell-created.py']
        assert finished['scope']['scope_unknown'] is False
        assert finished['file_watch']['status'] == 'STOPPED'
        replay = call(server,'handle_before_hook_event',args)
        assert replay.get('reason_code',replay.get('reason')) == 'TOOL_USE_CLAIM_REPLAYED'
    finally:
        if pool:
            pool.close()
        watching._shutdown()


def test_signed_three_hook_upgrade_adds_pre_preserves_foreign_and_repeats_idempotently(installed, monkeypatch):
    import security_runtime.global_integration as module
    old = copy.deepcopy(product_hooks())
    old['hooks'].pop('PreToolUse')
    with monkeypatch.context() as patch:
        patch.setattr(module,'product_hooks',lambda: copy.deepcopy(old))
        installed.execute('setup')
    target = installed.home/'hooks.json'
    value = json.loads(target.read_bytes())
    foreign = {'matcher':'Read','hooks':[{'type':'command','command':'keep user hook'}]}
    value['hooks']['PreToolUse'] = [foreign]
    target.write_text(json.dumps(value))
    assert installed.execute('status')['pre_tool_hook']['status'] == 'HOOK_MISSING'
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    upgraded = target.read_bytes()
    groups = json.loads(upgraded)['hooks']['PreToolUse']
    assert groups == [foreign,*product_hooks()['hooks']['PreToolUse']]
    assert installed.execute('setup')['operation'] == 'ALREADY_CONFIGURED'
    assert target.read_bytes() == upgraded
    assert installed.execute('uninstall')['overall'] == 'NOT_INSTALLED'
    assert json.loads(target.read_bytes())['hooks']['PreToolUse'] == [foreign]

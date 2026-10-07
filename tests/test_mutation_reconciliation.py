"""Real filesystem byte reconciliation; process/scanner ledgers are fixtures."""
import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

from security_runtime.baseline_seed import WorkspaceBaselineSeeds
from security_runtime.codex_mcp_hook import handle_codex_hook
from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import validate_state
from security_runtime.recent_hooks import RecentHookStore
from security_runtime.integration_state import WorkspaceBinding
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_global_integration import projects, installed, pool_fixture, ready
from test_codex_host_claims import connected, claims, invoke


def binding(root):
    return WorkspaceBinding('fixture', str(root), str(root), 'codex', 'PROJECT', '')


def start(root, tmp_path, *, dirty=True):
    if dirty:
        (root/'A.java').write_bytes(b'class A { int timeout = 2300; }\n')
    runtime=FakeRuntime()
    core=coordinator(tmp_path, runtime, cooldown_ms=0)
    core.handle('SESSION_START', root, 'codex', 's')
    runtime.calls.clear()
    return core, runtime


def edit(core, root, tool='Bash'):
    return handle_codex_hook('PostToolUse', str(root), 's', tool,
        {'command':'Set-Content A.java fixture'}, binding=binding(root), coordinator=core)


@pytest.mark.parametrize('tool',['Bash','apply_patch','Edit','Write'])
def test_real_edit_after_trusted_snapshot(repo,tmp_path,tool):
    core,runtime=start(repo,tmp_path)
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    out=edit(core,repo,tool)
    assert out['workspace_mutation_observed'] is True
    assert out['changed_file_count']==1 and out['snapshot_file_count']==1
    assert out['content_delta_detected'] is True and out['pre_snapshot_match'] is False
    assert out['reconciliation_reason']=='CONTENT_DIGEST_DELTA'
    assert out['scanner_run'] and runtime.calls==[('A.java',)]


def test_same_dirty_bytes_are_zero_delta_not_one(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    out=edit(core,repo)
    assert out['status']=='NO_CHANGE' and not out['scanner_run'] and not runtime.calls
    assert out['snapshot_file_count']==1 and out['changed_file_count']==0
    assert out['workspace_mutation_observed'] is False
    assert out['scanner_trigger_reason'] is None and out['pre_snapshot_match'] is True


def test_readonly_does_not_capture_or_scan(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    core.snapshot_capture=lambda *a:pytest.fail('readonly must not reconcile')
    out=handle_codex_hook('PostToolUse',str(repo),'s','Bash',{'command':'git status'},
        binding=binding(repo),coordinator=core)
    assert out['tool_classification']=='READ_ONLY' and not out['scanner_run'] and not runtime.calls


def test_restored_content_no_change(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    original=(repo/'A.java').read_bytes()
    (repo/'A.java').write_bytes(b'temporary change')
    (repo/'A.java').write_bytes(original)
    assert edit(core,repo)['status']=='NO_CHANGE' and not runtime.calls


def test_multifile_count_excludes_unchanged_dirty_file(repo,tmp_path):
    (repo/'B.java').write_bytes(b'class B {}')
    core,runtime=start(repo,tmp_path)
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    out=edit(core,repo)
    assert out['snapshot_file_count']==2 and out['changed_file_count']==1
    (repo/'B.java').write_bytes(b'class B { int n; }')
    (repo/'C.java').write_bytes(b'class C {}')
    out=edit(core,repo)
    assert out['snapshot_file_count']==3 and out['changed_file_count']==2


@pytest.mark.parametrize('prefix,newline',[(b'',b'\n'),(b'',b'\r\n'),(b'\xef\xbb\xbf',b'\r\n')])
def test_crlf_bom_and_aliases_preserve_real_byte_delta(repo,tmp_path,prefix,newline):
    core,runtime=start(repo,tmp_path)
    (repo/'A.java').write_bytes(prefix+b'class A { int timeout = 2400; }'+newline)
    alias=str(repo).upper().replace('\\','/')+'/' if os.name=='nt' else str(repo)+'/'
    out=handle_codex_hook('PostToolUse',alias,'s','Write',binding=binding(repo),coordinator=core)
    assert out['scanner_run'] and out['changed_file_count']==1
    assert not edit(core,repo)['scanner_run']


def test_session_capture_preserves_pre_edit_on_reconnect(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    before=core.store.path(repo,'codex','s').read_bytes()
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    WorkspaceBaselineSeeds(coordinator=core).capture_session(repo,'s')
    assert core.store.path(repo,'codex','s').read_bytes()==before
    assert edit(core,repo)['scanner_run']


def test_git_autocrlf_does_not_hide_byte_delta(repo,tmp_path):
    subprocess.run(['git','-C',str(repo),'config','core.autocrlf','true'],check=True)
    (repo/'A.java').write_bytes(b'safe\n')
    subprocess.run(['git','-C',str(repo),'add','--renormalize','.'],check=True)
    subprocess.run(['git','-C',str(repo),'commit','--allow-empty','-qm','normalized fixture'],check=True)
    core,runtime=start(repo,tmp_path,dirty=False)
    original=(repo/'A.java').read_bytes()
    (repo/'A.java').write_bytes(original.replace(b'\n',b'\r\n'))
    assert subprocess.run(['git','-C',str(repo),'diff','--name-only'],capture_output=True,check=True).stdout==b''
    out=edit(core,repo)
    assert out['scanner_run'] and out['changed_file_count']==1
    assert not edit(core,repo)['scanner_run']


def test_restart_preserves_current_session_snapshot(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }')
    reloaded=coordinator(tmp_path,FakeRuntime(),cooldown_ms=0)
    WorkspaceBaselineSeeds(coordinator=reloaded).capture_session(repo,'s')
    out=edit(reloaded,repo)
    assert out['scanner_run'] and out['snapshot_available'] is True


def test_first_edit_without_snapshot_is_unattributed(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime(),cooldown_ms=0)
    (repo/'A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    out=edit(core,repo)
    assert out['status']=='BASELINE_ESTABLISHED' and out['snapshot_available'] is False
    assert out['workspace_mutation_observed'] is None and out['changed_file_count'] is None
    assert out['reconciliation_reason']=='NO_TRUSTED_PRE_EDIT_SNAPSHOT'
    assert out['new_families']==0


def test_legacy_snapshot_read_and_future_upgrade(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    path=core.store.path(repo,'codex','s')
    state=json.loads(path.read_bytes());state.pop('file_digests')
    path.write_text(json.dumps(state));validate_state(state)
    assert edit(core,repo)['changed_file_count']==0
    (repo/'A.java').write_bytes(b'changed')
    out=edit(core,repo)
    assert out['scanner_run'] and out['changed_file_count'] is None
    assert json.loads(path.read_bytes())['file_digests']


def test_source_changes_during_scan_do_not_advance_snapshot(repo,tmp_path):
    core,runtime=start(repo,tmp_path)
    path=core.store.path(repo,'codex','s');before=path.read_bytes()
    (repo/'A.java').write_bytes(b'changed')
    original=runtime.scan
    def moving(*a,**k):
        result=original(*a,**k);(repo/'A.java').write_bytes(b'raced');return result
    runtime.scan=moving
    out=edit(core,repo)
    assert out['status']=='PARTIAL' and path.read_bytes()==before


def test_global_lazy_bootstrap_cannot_claim_no_change(installed,projects,tmp_path):
    root=projects[0]
    (root/'src/A.java').write_bytes(b'class A { int timeout = 2400; }')
    pool=pool_fixture(installed,tmp_path)
    server=create_global_server(workspaces=pool)
    args=dict(event='PostToolUse',workspace_path=str(root),session_id='s',turn_id='t',
              tool_use_id='call',tool_name='Bash',tool_input={'command':'Set-Content src/A.java fixture'})
    try:
        out=asyncio.run(server.call_tool('handle_hook_event',args)).structuredContent
        assert out['status']=='INCONCLUSIVE' and out['reason_code'] in {
            'WORKSPACE_INITIALIZING','WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE'}
        row=RecentHookStore().recent(root,limit=1)['records'][0]
        assert row['snapshot_available'] is False and row['snapshot_source']=='LAZY_BOOTSTRAP'
        assert row['reconciliation_reason']=='NO_TRUSTED_PRE_EDIT_SNAPSHOT'
        assert row['workspace_mutation_observed'] is None
        ready(pool,root,'s')
    finally:pool.close()


def test_generation_and_no_source_in_persistent_diagnostics(repo,tmp_path,monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'namespace'))
    core,runtime=start(repo,tmp_path)
    from security_runtime.recent_hooks import Observation,CURRENT
    observation=Observation('handle_hook_event',{'session_id':'raw-session-secret','tool_name':'Write'})
    observation.bind(repo);token=CURRENT.set(observation)
    try:
        (repo/'A.java').write_bytes(b'class A { int timeout = 2400; } // fixture-source-secret')
        out=edit(core,repo);observation.finish(out)
    finally:CURRENT.reset(token)
    row=RecentHookStore().recent(repo,limit=1)['records'][0]
    assert row['content_delta_detected'] is True and len(row['snapshot_generation'])==64
    text=json.dumps(row)
    assert 'fixture-source-secret' not in text and 'raw-session-secret' not in text and str(repo) not in text


@pytest.mark.parametrize('tool',['Bash','apply_patch','Edit','Write'])
def test_global_mcp_uses_trusted_snapshot_and_persists_actual_delta(connected,projects,tool):
    server,pool,runtimes=connected
    root=projects[0];runtime=runtimes[root]
    runtime.calls.clear()
    (root/'src/A.java').write_bytes(b'class A { int timeout = 2400; }\n')
    args=claims(root);args.update(tool_name=tool,tool_input={'command':'Set-Content src/A.java fixture'})
    out=invoke(server,args)
    assert out['host_claim_status']=='VALID' and out['scanner_run']
    assert out['changed_file_count']==1 and runtime.calls==[('src/A.java',)]
    row=RecentHookStore().recent(root,limit=1)['records'][0]
    assert row['content_delta_detected'] is True and row['snapshot_source']=='SESSION_BASELINE'
    args['tool_use_id']='second-call'
    repeated=invoke(server,args)
    assert repeated['status']=='NO_CHANGE' and repeated['changed_file_count']==0
    assert len(runtime.calls)==1


@pytest.mark.parametrize('value',[{'A.java':'source-secret'},{'wrong.java':'a'*64}])
def test_malformed_file_digest_inventory_rejected(repo,tmp_path,value):
    core,runtime=start(repo,tmp_path)
    state=json.loads(core.store.path(repo,'codex','s').read_bytes());state['file_digests']=value
    with pytest.raises(ValueError):validate_state(state)

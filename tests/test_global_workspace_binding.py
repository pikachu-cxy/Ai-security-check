"""Canonical workspace admission and safe rejection diagnostics."""
import asyncio
import hashlib
import json
import os
import subprocess

import pytest

from security_runtime.global_integration import GlobalCodexIntegration
from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import resolve_workspace
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.mcp_server import create_server
from security_runtime.recent_hooks import RecentHookStore, safe_fields, workspace_hash
from test_codex_host_claims import connected, claims, invoke
from test_global_integration import installed, projects, complete_runtime, ready, structured
from test_hook_runtime import coordinator


def test_default_child_admission_without_prior_session(installed, projects, tmp_path):
    installed.execute('setup')
    pool = GlobalWorkspaces(base=tmp_path/'state/default-workspaces', integration=installed)
    try:
        root = pool.root(projects[0]/'src')
        child, core = pool.admit(root)
        assert child is not None and core is not None
        assert not pool.sessions and not pool.jobs
    finally:
        pool.close()


@pytest.fixture
def dev_enrollment(installed):
    previous=installed.discover()
    discover=lambda: {**previous, 'kind':'DEV'}
    installed.discover=discover
    with pytest.raises(IntegrationDiagnostic, match='INSTALLED_RUNTIME_REQUIRED'):
        installed.execute('setup')
    installed.allow_dev=True
    assert installed.execute('setup')['overall']=='CONFIGURED'
    observer=GlobalCodexIntegration(home=installed.home, directory=installed.store.directory,
        discover=discover, probe=installed.probe, legacy_adapter=installed.legacy_adapter)
    assert not observer.allow_dev
    return observer


def test_signed_dev_enrollment_verified_without_new_dev_install(dev_enrollment):
    adapter=dev_enrollment
    files=(adapter.home/'config.toml',adapter.home/'hooks.json')
    before={p:p.read_bytes() for p in files}
    assert adapter.configuration_status()['overall']=='CONFIGURED'
    assert before=={p:p.read_bytes() for p in files}
    for action in ('setup','repair'):
        with pytest.raises(IntegrationDiagnostic,match='INSTALLED_RUNTIME_REQUIRED'):
            adapter.execute(action)
    assert before=={p:p.read_bytes() for p in files}


def test_unowned_dev_configuration_cannot_self_enroll(installed):
    installed.discover=lambda:{'command':'python','prefix':[],'kind':'DEV'}
    installed.home.mkdir()
    (installed.home/'config.toml').write_text('[mcp_servers.ai_security_runtime]\ncommand="python"\n')
    with pytest.raises(IntegrationDiagnostic,match='INSTALLED_RUNTIME_REQUIRED'):
        installed.configuration_status()


def test_tampered_dev_enrollment_fails_closed(dev_enrollment):
    adapter=dev_enrollment
    manifest=adapter._state_path(adapter.home,'ownership.json')
    data=json.loads(manifest.read_bytes()); data['signature']='0'*64
    manifest.write_text(json.dumps(data))
    with pytest.raises(IntegrationDiagnostic,match='OWNERSHIP_INVALID'):
        adapter.configuration_status()


def test_stale_dev_launcher_not_configured(dev_enrollment):
    adapter=dev_enrollment
    path=adapter.home/'config.toml'
    path.write_bytes(path.read_bytes().replace(b'enabled = true',b'enabled = false'))
    with pytest.raises(IntegrationDiagnostic,match='MCP_CONFIGURATION_CONFLICT'):
        adapter.configuration_status()


def test_incomplete_dev_enrollment_not_accepted(dev_enrollment):
    adapter=dev_enrollment
    value=adapter._manifest(adapter.home); value['phase']='UPDATING'
    adapter._save(adapter.home,value)
    with pytest.raises(IntegrationDiagnostic,match='INSTALLED_RUNTIME_REQUIRED'):
        adapter.configuration_status()


def test_existing_enrollment_not_authority_for_different_launcher(dev_enrollment):
    adapter=dev_enrollment
    previous=adapter.discover()
    adapter.discover=lambda:{**previous,'command':previous['command']+'-different'}
    assert adapter.configuration_status()['overall']=='DEGRADED'


@pytest.mark.parametrize('style',['root','slash','backslash','case','trailing','subdirectory','subdirectory_slash','subdirectory_case'])
def test_cwd_variants_bind_same_canonical_git_root(connected,projects,style):
    server,pool,_=connected
    root=projects[0]
    candidate=root/'src' if style.startswith('subdirectory') else root
    value=str(candidate)
    if 'slash' in style: value=value.replace('\\','/')
    if style=='backslash' and os.name=='nt': value=value.replace('/','\\')
    if 'case' in style and os.name=='nt': value=value.upper()
    if style=='trailing': value+=os.sep
    args=claims(root); args['workspace_path']=value
    out=invoke(server,args)
    assert out['host_claim_status']=='VALID'
    assert out['workspace_claim_match'] and out['session_claim_match']
    assert out['workspace_relation']==('SUBDIRECTORY' if candidate!=root else 'SAME_ROOT')
    assert out['resolved_workspace_hash']==out['registered_workspace_hash']==out['session_workspace_hash']==workspace_hash(root)
    assert not out['scanner_run']
    row=RecentHookStore().recent(root)['records'][0]
    assert row['workspace_claim_hash']==workspace_hash(candidate.resolve())
    assert row['workspace_binding_stage']=='COMPLETE' and row['workspace_rejection_reason'] is None


def test_nested_repository_has_independent_root_and_session(connected,projects):
    server,pool,_=connected
    outer=projects[0]; inner=outer/'nested'; inner.mkdir()
    subprocess.run(['git','init','-q',str(inner)],check=True)
    (inner/'src').mkdir()
    assert resolve_workspace(inner/'src')==inner
    args=claims(inner); args.update(workspace_path=str(inner/'src'),session_id='nested-session')
    out=invoke(server,args)
    assert out['workspace_claim_match'] and out['resolved_workspace_hash']==workspace_hash(inner)
    assert inner in pool.children and out['workspace_relation']=='SUBDIRECTORY'
    args.update(session_id='s',tool_use_id='nested-cross-call')
    out=invoke(server,args)
    assert out['reason_code']=='SESSION_WORKSPACE_MISMATCH' and not out['scanner_run']
    assert out['workspace_rejection_reason']=='WORKSPACE_SESSION_MISMATCH'


def test_sessionstart_uses_same_binding(connected,projects):
    server,_,_=connected
    out=structured(asyncio.run(server.call_tool('handle_readiness_event',
        dict(event='SessionStart',workspace_path=str(projects[0]/'src'),session_id='s'))))
    assert out['host_claim_status']=='VALID' and out['workspace_claim_match'] and out['session_claim_match']


def test_lazy_posttooluse_after_explicit_dev_enrollment(dev_enrollment,projects,tmp_path):
    runtimes={}
    def factory(root,directory,binding):
        runtime=complete_runtime(); runtimes[root]=runtime
        core=coordinator(directory,runtime,cooldown_ms=0)
        return create_server(runtime,hook_coordinator=core,workspace_binding=binding,
                             global_mode=False,hook_advisory_only=True),core
    pool=GlobalWorkspaces(base=tmp_path/'state/lazy-dev',integration=dev_enrollment,child_factory=factory)
    server=create_global_server(workspaces=pool)
    root=projects[0]
    try:
        assert not pool.sessions and not pool.children and not pool.jobs
        args=claims(root); args.update(tool_name='apply_patch',workspace_path=str(root/'src'))
        first=invoke(server,args)
        assert first['host_claim_status']=='VALID' and first['workspace_claim_match']
        assert first['session_binding_present'] and pool.jobs
        for future in tuple(pool.jobs.values()): future.result(timeout=20)
        (root/'src/A.java').write_text('class A { int changed; }\n')
        args.update(tool_use_id='lazy-second')
        out=invoke(server,args)
        assert out['scanner_run'] and out['workspace_mutation_observed']
        assert runtimes[root].calls[-1]==('src/A.java',)
        assert out['workspace_rejection_reason'] is None
    finally:
        pool.close()


@pytest.mark.parametrize('code',['INSTALLED_RUNTIME_REQUIRED','CONFIG_INVALID','OWNERSHIP_INVALID','POTENTIAL_DUPLICATE_HOOK','MCP_CONFIGURATION_CONFLICT'])
def test_configuration_rejection_not_reported_as_path_mismatch(connected,projects,monkeypatch,code):
    server,pool,runtimes=connected
    before=len(runtimes[projects[0]].calls)
    def failed(*args): raise IntegrationDiagnostic(code)
    monkeypatch.setattr(pool,'validate_layers',failed)
    out=invoke(server,claims(projects[0]))
    assert out['reason_code']==code and out['workspace_rejection_reason']==code
    assert out['workspace_claim_match'] is True and out['session_claim_match'] is None
    assert out['workspace_binding_stage']=='VALIDATING_CONFIGURATION'
    assert not out['scanner_run'] and len(runtimes[projects[0]].calls)==before
    row=RecentHookStore().recent(projects[0])['records'][0]
    assert row['workspace_rejection_reason']==code and row['handler_reason']==code


def test_wrong_resolved_workspace_is_rejected(connected,projects,monkeypatch):
    server,pool,_=connected
    monkeypatch.setattr(pool,'root',lambda *args:projects[1])
    out=invoke(server,claims(projects[0]))
    assert out['workspace_claim_match'] is False and not out['scanner_run']
    assert out['reason_code']=='WORKSPACE_CANONICALIZATION_MISMATCH'


def test_cross_workspace_session_and_tool_reuse_rejected(connected,projects):
    server,_,_=connected
    assert invoke(server,claims(projects[0]))['host_claim_status']=='VALID'
    out=invoke(server,claims(projects[1],call='another-call'))
    assert out['session_claim_match'] is False and not out['scanner_run']
    args=claims(projects[1]); args['session_id']='new-session'
    out=invoke(server,args)
    assert out['reason_code']=='TOOL_USE_CLAIM_REPLAYED' and not out['scanner_run']
    assert out['workspace_rejection_reason']=='TOOL_USE_CLAIM_REPLAYED'


def test_link_workspace_remains_rejected(connected,projects,tmp_path):
    server,_,_=connected
    link=tmp_path/'junction'
    if os.name=='nt':
        subprocess.run(['cmd.exe','/c','mklink','/J',str(link),str(projects[0])],check=True,capture_output=True)
    else:
        link.symlink_to(projects[0],target_is_directory=True)
    out=invoke(server,claims(link))
    assert out['workspace_claim_match'] is False and not out['scanner_run']
    assert out['workspace_rejection_reason']=='WORKSPACE_LINK_REJECTED'


def test_unsafe_workspace_remains_rejected(connected):
    from pathlib import Path
    server,_,_=connected
    out=invoke(server,claims(Path.home()))
    assert out['host_claim_status']=='REJECTED' and not out['scanner_run']
    assert out['workspace_rejection_reason']=='WORKSPACE_OUTSIDE_ALLOWED_ROOT'


def test_workspace_diagnostics_drop_arbitrary_text():
    marker='private-command-source-secret'
    result=safe_fields(dict(workspace_rejection_reason=marker,workspace_binding_stage=marker,
        workspace_relation=marker,resolved_workspace_hash=marker,session_workspace_hash=marker))
    assert marker not in json.dumps(result)
